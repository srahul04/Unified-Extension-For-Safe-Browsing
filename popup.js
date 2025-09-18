document.addEventListener('DOMContentLoaded', async () => {
    const loadingSpinner = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const llmOutputDiv = document.getElementById('ai-analysis');
    const llmOutputLoading = document.getElementById('ai-loading');
    const pdfLoadingText = document.getElementById('pdf-loading');
    const scanningUi = document.getElementById('scanning-ui');
    const scanningProgress = document.getElementById('scanning-progress');
    
    // Theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    const body = document.body;
    
    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'light';
    body.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
    
    // Theme toggle event listener
    themeToggle.addEventListener('click', () => {
        const currentTheme = body.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        body.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });
    
    function updateThemeIcon(theme) {
        if (theme === 'dark') {
            themeIcon.setAttribute('name', 'moon-outline');
        } else {
            themeIcon.setAttribute('name', 'sunny-outline');
        }
    }

    // Initialize button states
    const startBtn = document.getElementById('start-scan-btn');
    const stopBtn = document.getElementById('stop-scan-btn');
    
    if (startBtn) {
        startBtn.disabled = false;
    }
    if (stopBtn) {
        stopBtn.disabled = true; // Start disabled since no scan is running
    }

    let currentAnalysisData = {}; // Store the latest analysis data
    let currentLlmSummary = ""; // Store the latest LLM summary
    let currentLlmExplanations = ""; // Store the latest LLM explanations
    let currentLlmOverallSecurityAssessment = ""; // Store the LLM's overall security assessment
    
    // Performance optimization variables
    let performanceMetrics = {
        scanStartTime: 0,
        scanEndTime: 0,
        memoryUsage: 0,
        apiCallCount: 0,
        domAnalysisTime: 0,
        headerAnalysisTime: 0
    };
    
    // Memory management
    const memoryManager = {
        maxHistoryEntries: 50,
        maxCacheSize: 10 * 1024 * 1024, // 10MB
        cache: new Map(),
        
        // Clean up old cache entries
        cleanupCache() {
            if (this.cache.size > this.maxHistoryEntries) {
                const entries = Array.from(this.cache.entries());
                const toDelete = entries.slice(0, entries.length - this.maxHistoryEntries);
                toDelete.forEach(([key]) => this.cache.delete(key));
            }
        },
        
        // Get memory usage estimate
        getMemoryUsage() {
            let totalSize = 0;
            this.cache.forEach((value) => {
                totalSize += JSON.stringify(value).length;
            });
            return totalSize;
        },
        
        // Store with automatic cleanup
        set(key, value) {
            this.cache.set(key, value);
            this.cleanupCache();
        },
        
        get(key) {
            return this.cache.get(key);
        }
    };

    // Initialize UI state
    loadingSpinner.classList.add('hidden');
    resultsDiv.classList.add('hidden');
    scanningUi.classList.add('hidden');
    
    let scanInProgress = false;
    let currentScanMode = 'quick';
    let realtimeScanning = false;
    let realtimeInterval = null;
    let virusTotalApiKey = "0d2045a84cddc0d16ffab0eeed55e564503d6ee871785b401aa92d8e06a9361a"; // VirusTotal API Key
    let urlVoidApiKey = "YOUR_URLVOID_API_KEY";
    let hybridAnalysisApiKey = "YOUR_HYBRIDANALYSIS_API_KEY";
    let googleSafeBrowsingApiKey = "YOUR_GOOGLE_SAFEBROWSING_API_KEY";
    
    // Additional free APIs (no registration required)
    const freeApis = {
        urlVoid: 'https://api.urlvoid.com/v1/pay-as-you-go/',
        phishTank: 'https://checkurl.phishtank.com/checkurl/',
        abuseIPDB: 'https://api.abuseipdb.com/api/v2/check',
        hybridAnalysis: 'https://www.hybrid-analysis.com/api/v2/quick-scan/url'
    };

    // Helper function to render a result item
    function renderResult(elementId, iconClass, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<span class="icon ${iconClass}">${getIcon(iconClass)}</span><span class="result-text">${text}</span>`;
        }
    }

    // Helper to get Ionic icon
    function getIcon(iconClass) {
        if (iconClass.includes('success-icon')) return '<ion-icon name="checkmark-circle-outline"></ion-icon>';
        if (iconClass.includes('warning-icon')) return '<ion-icon name="warning-outline"></ion-icon>';
        if (iconClass.includes('error-icon')) return '<ion-icon name="close-circle-outline"></ion-icon>';
        if (iconClass.includes('info-icon')) return '<ion-icon name="information-circle-outline"></ion-icon>';
        return '<ion-icon name="help-circle-outline"></ion-icon>';
    }

    // Enhanced security assessment with weighted scoring system
    function calculateSecurityAssessment(domData, headerData = {}, url = '') {
        let score = 100;
        let criticalIssues = 0;
        let highRiskIssues = 0;
        let mediumRiskIssues = 0;
        let lowRiskIssues = 0;
        let recommendations = [];
        let securityMetrics = {
            encryption: { weight: 25, status: 'unknown' },
            headers: { weight: 20, status: 'unknown' },
            content: { weight: 15, status: 'unknown' },
            malware: { weight: 20, status: 'unknown' },
            cookies: { weight: 10, status: 'unknown' },
            forms: { weight: 5, status: 'unknown' },
            traffic: { weight: 5, status: 'unknown' }
        };

        // HTTPS Check (Critical - Weight: 25)
        const isHttps = !!url && url.startsWith('https://');
        if (!isHttps) {
            score -= 25;
            criticalIssues++;
            recommendations.push('Enable HTTPS encryption');
            securityMetrics.encryption.status = 'critical';
        } else {
            securityMetrics.encryption.status = 'secure';
        }

        // Content Security Policy (Critical - Weight: 20)
        const hasCsp = !!domData.hasCSP || !!(headerData && headerData['content-security-policy']);
        if (!hasCsp) {
            score -= 20;
            criticalIssues++;
            recommendations.push('Implement Content Security Policy');
            securityMetrics.headers.status = 'critical';
        } else {
            // Check CSP quality
            const cspHeader = headerData && headerData['content-security-policy'];
            if (cspHeader) {
                const risks = [];
                if (/'unsafe-inline'/.test(cspHeader)) risks.push("'unsafe-inline'");
                if (/'unsafe-eval'/.test(cspHeader)) risks.push("'unsafe-eval'");
                if (/\ballow\s+\*/i.test(cspHeader) || /\*\s*(;|$)/.test(cspHeader)) risks.push('wildcard * sources');
                if (/data:/i.test(cspHeader)) risks.push('data: URIs');
                
                if (risks.length > 0) {
                    score -= 5;
                    mediumRiskIssues++;
                    recommendations.push(`Strengthen CSP by removing: ${risks.join(', ')}`);
                    securityMetrics.headers.status = 'warning';
                } else {
                    securityMetrics.headers.status = 'secure';
                }
            } else {
                securityMetrics.headers.status = 'secure';
            }
        }

        // Mixed Content (High Risk - Weight: 15)
        if (domData.hasMixedContent) {
            score -= 15;
            highRiskIssues++;
            recommendations.push('Fix mixed content issues');
            securityMetrics.content.status = 'high';
        } else {
            securityMetrics.content.status = 'secure';
        }

        // Security Headers Assessment (Weight: 20)
        let headerScore = 0;
        const maxHeaderScore = 20;

        // X-Frame-Options (High Risk)
        const hasXfo = !!domData.hasXFrameOptions || !!(headerData && headerData['x-frame-options']);
        if (hasXfo) headerScore += 4;
        else {
            recommendations.push('Add X-Frame-Options header');
            highRiskIssues++;
        }

        // HSTS (High Risk)
        if (headerData && headerData['strict-transport-security']) {
            headerScore += 4;
        } else {
            recommendations.push('Enable HSTS (Strict-Transport-Security)');
            highRiskIssues++;
        }

        // X-Content-Type-Options (Medium Risk)
        const xctoOk = headerData && headerData['x-content-type-options'] === 'nosniff';
        if (xctoOk) headerScore += 3;
        else {
            recommendations.push('Set X-Content-Type-Options: nosniff');
            mediumRiskIssues++;
        }

        // Referrer-Policy (Medium Risk)
        if (headerData && headerData['referrer-policy']) {
            headerScore += 2;
        } else {
            recommendations.push('Set Referrer-Policy header');
            mediumRiskIssues++;
        }

        // Permissions-Policy (Medium Risk)
        if (headerData && headerData['permissions-policy']) {
            headerScore += 2;
        } else {
            recommendations.push('Implement Permissions-Policy');
            mediumRiskIssues++;
        }

        // COOP/CORP (Low Risk)
        if (headerData && headerData['cross-origin-opener-policy']) headerScore += 2;
        if (headerData && headerData['cross-origin-resource-policy']) headerScore += 2;
        if (headerData && headerData['x-xss-protection']) headerScore += 1;

        score -= (maxHeaderScore - headerScore);
        securityMetrics.headers.status = headerScore >= 15 ? 'secure' : headerScore >= 10 ? 'warning' : 'critical';

        // Malware Detection (Critical - Weight: 20)
        const malwareIssues = domData.malwareReputationIssues || [];
        let malwareScore = 20;
        
        if (malwareIssues.length > 0) {
            malwareScore -= 20;
            criticalIssues++;
            recommendations.push('Address malware reputation issues');
            securityMetrics.malware.status = 'critical';
        }

        // Suspicious Scripts (High Risk)
        if (domData.suspiciousExternalScripts) {
            malwareScore -= 10;
            highRiskIssues++;
            recommendations.push('Review suspicious external scripts');
            if (securityMetrics.malware.status !== 'critical') {
                securityMetrics.malware.status = 'high';
            }
        }

        // Crypto Mining (Critical)
        if (domData.cryptoMiningDetected) {
            malwareScore -= 20;
            criticalIssues++;
            recommendations.push('Remove cryptocurrency mining scripts');
            securityMetrics.malware.status = 'critical';
        }

        // Multi-API Detection (disabled; using on-device model instead)
        const externalApisEnabled = true;
        const multiApiData = externalApisEnabled ? (currentAnalysisData.multiApiResults || {}) : {};
        const totalDetections = externalApisEnabled ? [
            multiApiData.virusTotal?.detected,
            multiApiData.phishTank?.detected,
            multiApiData.urlVoid?.detected,
            multiApiData.hybridAnalysis?.detected,
            multiApiData.googleSafeBrowsing?.detected
        ].filter(Boolean).length : 0;

        if (totalDetections > 0) {
            malwareScore -= (totalDetections * 4);
            criticalIssues++;
            recommendations.push('Address malware detection by antivirus engines');
            securityMetrics.malware.status = 'critical';
        }

        score -= (20 - malwareScore);
        if (securityMetrics.malware.status === 'unknown') {
            securityMetrics.malware.status = 'secure';
        }

        // Cookie Security (Medium Risk - Weight: 10)
        let cookieScore = 10;
        if (!domData.secureCookies) {
            cookieScore -= 5;
            mediumRiskIssues++;
            recommendations.push('Use Secure flag for cookies');
        }

        if (!domData.httpOnlyCookies) {
            cookieScore -= 5;
            mediumRiskIssues++;
            recommendations.push('Use HttpOnly flag for cookies');
        }

        score -= (10 - cookieScore);
        securityMetrics.cookies.status = cookieScore >= 8 ? 'secure' : cookieScore >= 5 ? 'warning' : 'critical';

        // Form Security (Low Risk - Weight: 5)
        let formScore = 5;
        if (domData.sensitiveAutocomplete) {
            formScore -= 2;
            lowRiskIssues++;
            recommendations.push('Disable sensitive autocomplete on input fields');
        }

        if (domData.passwordInputTypeError) {
            formScore -= 3;
            mediumRiskIssues++;
            recommendations.push("Ensure password fields use type='password'");
        }

        score -= (5 - formScore);
        securityMetrics.forms.status = formScore >= 4 ? 'secure' : formScore >= 2 ? 'warning' : 'critical';

        // Traffic Analysis (Low Risk - Weight: 5)
        let trafficScore = 5;
        if (domData.externalRequests > 10) {
            trafficScore -= 2;
            lowRiskIssues++;
            recommendations.push('Review high number of external requests');
        }

        if (domData.hasLargeResources) {
            trafficScore -= 2;
            lowRiskIssues++;
            recommendations.push('Optimize large resources for better performance');
        }

        if (domData.totalRequests > 50) {
            trafficScore -= 1;
            lowRiskIssues++;
        }

        score -= (5 - trafficScore);
        securityMetrics.traffic.status = trafficScore >= 4 ? 'secure' : trafficScore >= 2 ? 'warning' : 'critical';

        // Ensure score doesn't go below 0
        score = Math.max(0, score);

        // Determine overall status with enhanced thresholds
        let overallStatus, riskLevel, statusClass, riskClass;
        
        if (score >= 95) {
            overallStatus = 'EXCELLENT';
            riskLevel = 'VERY LOW';
            statusClass = 'secure';
            riskClass = 'low';
        } else if (score >= 85) {
            overallStatus = 'SECURE';
            riskLevel = 'LOW';
            statusClass = 'secure';
            riskClass = 'low';
        } else if (score >= 70) {
            overallStatus = 'MOSTLY SECURE';
            riskLevel = 'MEDIUM';
            statusClass = 'warning';
            riskClass = 'medium';
        } else if (score >= 50) {
            overallStatus = 'AT RISK';
            riskLevel = 'HIGH';
            statusClass = 'danger';
            riskClass = 'high';
        } else if (score >= 25) {
            overallStatus = 'HIGH RISK';
            riskLevel = 'VERY HIGH';
            statusClass = 'danger';
            riskClass = 'critical';
        } else {
            overallStatus = 'CRITICAL RISK';
            riskLevel = 'CRITICAL';
            statusClass = 'danger';
            riskClass = 'critical';
        }

        // Remove ML adjustments; rely solely on rules and external APIs
        return {
            score: Math.round(score),
            overallStatus,
            riskLevel,
            statusClass,
            riskClass,
            criticalIssues,
            highRiskIssues,
            mediumRiskIssues,
            lowRiskIssues,
            securityMetrics,
            recommendations: recommendations.slice(0, 8),
            detailedBreakdown: {
                encryption: { score: securityMetrics.encryption.status === 'secure' ? 25 : 0, max: 25 },
                headers: { score: headerScore, max: maxHeaderScore },
                content: { score: domData.hasMixedContent ? 0 : 15, max: 15 },
                malware: { score: malwareScore, max: 20 },
                cookies: { score: cookieScore, max: 10 },
                forms: { score: formScore, max: 5 },
                traffic: { score: trafficScore, max: 5 }
            }
        };
    }

    // Enhanced security assessment display with detailed breakdown
    function updateSecurityAssessment(assessment) {
        const verdictEl = document.getElementById('security-verdict');
        const scoreEl = document.getElementById('security-score');
        const statusEl = document.getElementById('overall-status');
        const riskEl = document.getElementById('risk-level');
        const recommendationsEl = document.getElementById('recommendations-count');

        if (verdictEl) {
            const icons = {
                'EXCELLENT': '🏆',
                'SECURE': '🛡️',
                'MOSTLY SECURE': '⚠️',
                'AT RISK': '🚨',
                'HIGH RISK': '🔥',
                'CRITICAL RISK': '💀'
            };
            verdictEl.textContent = `${icons[assessment.overallStatus] || '🔍'} ${assessment.overallStatus}`;
        }

        if (scoreEl) {
            scoreEl.textContent = `Security Score: ${assessment.score}/100`;
        }

        // Animate progress bar
        const progressBar = document.getElementById('security-progress-bar');
        if (progressBar) {
            // Reset and animate to new score
            progressBar.style.width = '0%';
            setTimeout(() => {
                progressBar.style.width = `${assessment.score}%`;
                
                // Update progress bar color based on score
                progressBar.className = 'security-progress-bar';
                if (assessment.score >= 85) {
                    progressBar.classList.add('success');
                } else if (assessment.score >= 70) {
                    progressBar.classList.add('warning');
                } else {
                    progressBar.classList.add('danger');
                }
            }, 100);
        }

        if (statusEl) {
            statusEl.textContent = assessment.overallStatus;
            statusEl.className = `status-badge ${assessment.statusClass}`;
        }

        if (riskEl) {
            riskEl.textContent = assessment.riskLevel;
            riskEl.className = `risk-badge ${assessment.riskClass}`;
        }

        if (recommendationsEl) {
            const totalIssues = assessment.criticalIssues + assessment.highRiskIssues + assessment.mediumRiskIssues + assessment.lowRiskIssues;
            recommendationsEl.textContent = `${totalIssues} issues found (${assessment.criticalIssues} critical, ${assessment.highRiskIssues} high, ${assessment.mediumRiskIssues} medium, ${assessment.lowRiskIssues} low)`;
        }

        // Add detailed breakdown to the security summary
        const securitySummary = document.getElementById('security-summary');
        if (securitySummary && assessment.detailedBreakdown) {
            // Create detailed breakdown section
            let breakdownHtml = `
                <div class="summary-item">
                    <span class="summary-label">Issues Breakdown:</span>
                    <span class="text-sm">
                        Critical: ${assessment.criticalIssues} | 
                        High: ${assessment.highRiskIssues} | 
                        Medium: ${assessment.mediumRiskIssues} | 
                        Low: ${assessment.lowRiskIssues}
                    </span>
                </div>
            `;
            
            // Add security metrics breakdown
            if (assessment.securityMetrics) {
                breakdownHtml += `
                    <div class="summary-item">
                        <span class="summary-label">Security Categories:</span>
                        <div class="flex flex-wrap gap-2 mt-2">
                `;
                
                Object.entries(assessment.securityMetrics).forEach(([category, metric]) => {
                    const statusClass = metric.status === 'secure' ? 'success' : 
                                     metric.status === 'warning' ? 'warning' : 
                                     metric.status === 'critical' ? 'danger' : 'info';
                    breakdownHtml += `
                        <span class="px-2 py-1 text-xs rounded-full bg-${statusClass}-100 text-${statusClass}-800">
                            ${category}: ${metric.status}
                        </span>
                    `;
                });
                
                breakdownHtml += `
                        </div>
                    </div>
                `;
            }
            
            // Insert breakdown after existing summary items
            const existingItems = securitySummary.querySelectorAll('.summary-item');
            const lastItem = existingItems[existingItems.length - 1];
            if (lastItem) {
                lastItem.insertAdjacentHTML('afterend', breakdownHtml);
            }
        }
    }

    // Render all analysis data into the popup UI
    function displayResults(domData, headerData = {}, url = '') {
        // Calculate and display security assessment
        const assessment = calculateSecurityAssessment(domData, headerData, url);
        updateSecurityAssessment(assessment);
        // Clear AI section (disabled)
        if (llmOutputDiv) llmOutputDiv.classList.add('hidden');
        if (llmOutputLoading) llmOutputLoading.classList.add('hidden');
        // General Security Checks
        const isHttps = !!url && url.startsWith('https://');
        renderResult('https-check', isHttps ? 'success-icon' : 'error-icon', 
            isHttps ? '✅ HTTPS enabled - Secure connection' : '❌ Missing HTTPS - Using insecure HTTP');

        renderResult('mixed-content-check', domData.hasMixedContent ? 'warning-icon' : 'success-icon', 
            domData.hasMixedContent ? '⚠️ Mixed content detected - Security risk' : '✅ No mixed content - Secure');

        const hasCsp = !!domData.hasCSP || !!(headerData && headerData['content-security-policy']);
        renderResult('csp-check', hasCsp ? 'success-icon' : 'error-icon', 
            hasCsp ? '✅ Content Security Policy present' : '❌ Missing Content Security Policy - High risk');

        // CSP evaluator — flag risky directives if header exists
        const cspHeader = headerData && headerData['content-security-policy'];
        if (cspHeader) {
            const risks = [];
            if (/'unsafe-inline'/.test(cspHeader)) risks.push("'unsafe-inline'");
            if (/'unsafe-eval'/.test(cspHeader)) risks.push("'unsafe-eval'");
            if (/\ballow\s+\*/i.test(cspHeader) || /\*\s*(;|$)/.test(cspHeader)) risks.push('wildcard * sources');
            if (/data:/i.test(cspHeader)) risks.push('data: URIs');
            const msg = risks.length === 0 ? 'CSP looks reasonably strict' : `CSP risks: ${risks.join(', ')}`;
            renderResult('csp-evaluator', risks.length === 0 ? 'success-icon' : 'warning-icon', msg);
        } else {
            renderResult('csp-evaluator', 'info-icon', 'No CSP header detected to evaluate');
        }

        const hasXfo = !!domData.hasXFrameOptions || !!(headerData && headerData['x-frame-options']);
        renderResult('x-frame-options-check', hasXfo ? 'success-icon' : 'warning-icon', 
            hasXfo ? '✅ X-Frame-Options present - Clickjacking protection' : '⚠️ X-Frame-Options missing - Clickjacking risk');

        renderResult('hsts-check', headerData && headerData['strict-transport-security'] ? 'success-icon' : 'warning-icon', 
            headerData && headerData['strict-transport-security'] ? '✅ HSTS enabled - HTTPS enforcement' : '⚠️ Strict-Transport-Security not set - HTTPS downgrade risk');

        const xctoOk = headerData && headerData['x-content-type-options'] === 'nosniff';
        renderResult('x-content-type-options-check', xctoOk ? 'success-icon' : 'warning-icon', 
            xctoOk ? '✅ X-Content-Type-Options: nosniff - MIME protection' : '❌ X-Content-Type-Options missing - MIME sniffing risk');

        const xssHeader = headerData && headerData['x-xss-protection'];
        const xssMsg = xssHeader && xssHeader.startsWith('1') ? '✅ X-XSS-Protection enabled (deprecated)' : '⚠️ X-XSS-Protection not enabled - XSS risk';
        renderResult('x-xss-protection-check', xssHeader && xssHeader.startsWith('1') ? 'info-icon' : 'warning-icon', xssMsg);

        renderResult('referrer-policy-check', headerData && headerData['referrer-policy'] ? 'success-icon' : 'warning-icon', 
            headerData && headerData['referrer-policy'] ? `✅ Referrer-Policy: ${headerData['referrer-policy']} - Privacy protection` : '⚠️ Referrer-Policy missing - Privacy risk');

        renderResult('permissions-policy-check', headerData && headerData['permissions-policy'] ? 'success-icon' : 'warning-icon', 
            headerData && headerData['permissions-policy'] ? '✅ Permissions-Policy present - Feature control' : '⚠️ Permissions-Policy missing - Feature risk');

        renderResult('coop-check', headerData && headerData['cross-origin-opener-policy'] ? 'success-icon' : 'info-icon', 
            headerData && headerData['cross-origin-opener-policy'] ? '✅ COOP present - Isolation protection' : 'ℹ️ COOP not set - Isolation risk');

        renderResult('corp-check', headerData && headerData['cross-origin-resource-policy'] ? 'success-icon' : 'info-icon', 
            headerData && headerData['cross-origin-resource-policy'] ? '✅ CORP present - Resource protection' : 'ℹ️ CORP not set - Resource risk');

        // Cookie Security
        const cookieResults = document.getElementById('cookie-results');
        if (cookieResults) {
            cookieResults.innerHTML = '';
            if (domData.cookies && domData.cookies.length > 0) {
                domData.cookies.forEach(cookie => {
                    const status = [];
                    if (!cookie.secure) status.push('Not Secure');
                    if (!cookie.httpOnlyDetected) status.push('Not HttpOnly');
                    // Attempt SameSite detection from response header where available
                    let sameSiteLabel = '';
                    const setCookie = headerData && headerData['set-cookie'];
                    if (setCookie && setCookie.toLowerCase().includes(`${cookie.name.toLowerCase()}=`)) {
                        const m = setCookie.match(/samesite=([^;]+)/i);
                        if (m) sameSiteLabel = m[1];
                    }
                    if (!sameSiteLabel) {
                        status.push('SameSite unknown');
                    } else if (!/^(strict|lax)$/i.test(sameSiteLabel)) {
                        status.push(`SameSite=${sameSiteLabel}`);
                    }
                    if (status.length === 0) status.push('Secure & HttpOnly');
                    const div = document.createElement('div');
                    div.className = 'result-item';
                    const ok = status.includes('Secure & HttpOnly');
                    div.innerHTML = `<span class="icon ${ok ? 'success-icon' : 'warning-icon'}">${getIcon(ok ? 'success-icon' : 'warning-icon')}</span> <span>${cookie.name}: ${status.join(', ')}</span>`;
                    cookieResults.appendChild(div);
                });
            } else {
                const div = document.createElement('div');
                div.className = 'result-item';
                div.innerHTML = `<span class="icon info-icon">${getIcon('info-icon')}</span> <span>No cookies accessible via JavaScript</span>`;
                cookieResults.appendChild(div);
            }
        }

        // Form Security
        renderResult('form-autocomplete-check', domData.sensitiveAutocomplete ? 'warning-icon' : 'success-icon', domData.sensitiveAutocomplete ? 'Sensitive autocomplete enabled on input fields' : 'Sensitive autocomplete not detected');
        renderResult('password-type-check', domData.passwordInputTypeError ? 'error-icon' : 'success-icon', domData.passwordInputTypeError ? "Password fields not using type='password'" : "Password inputs use correct type");
        renderResult('password-encryption-note', 'info-icon', 'Client-side cannot verify password hashing; ensure strong server-side hashing.');

        // Malware Detection
        renderResult('suspicious-scripts-check', domData.suspiciousExternalScripts ? 'warning-icon' : 'success-icon', 
            domData.suspiciousExternalScripts ? '⚠️ Suspicious external scripts detected - Security risk' : '✅ No suspicious external scripts detected - Safe');
        
        // Malware reputation check
        const malwareIssues = domData.malwareReputationIssues || [];
        if (malwareIssues.length > 0) {
            renderResult('malware-reputation-check', 'error-icon', `❌ Malware reputation issues: ${malwareIssues.join(', ')}`);
        } else {
            renderResult('malware-reputation-check', 'success-icon', '✅ No malware reputation issues detected - Clean');
        }
        
        // Multi-API Results Display
        const multiApiData = currentAnalysisData.multiApiResults || {};
        
        // VirusTotal Results
        const virusTotalData = multiApiData.virusTotal || currentAnalysisData.virusTotal;
        const virusTotalLink = document.getElementById('virus-total-link');
        
        if (virusTotalData && !virusTotalData.error) {
            if (virusTotalData.status === "submitted") {
                renderResult('virus-total-check', 'info-icon', `VirusTotal: ${virusTotalData.message}`);
                virusTotalLink.classList.add('hidden');
            } else if (virusTotalData.detected) {
                const threatLevel = virusTotalData.positives > 5 ? 'HIGH' : virusTotalData.positives > 2 ? 'MEDIUM' : 'LOW';
                renderResult('virus-total-check', 'error-icon', `VirusTotal: ${virusTotalData.positives}/${virusTotalData.total} engines detected malware (${threatLevel} threat)`);
                virusTotalLink.classList.remove('hidden');
            } else {
                const reputation = virusTotalData.reputation > 0 ? ` (Reputation: ${virusTotalData.reputation})` : '';
                renderResult('virus-total-check', 'success-icon', `VirusTotal: Clean (${virusTotalData.total} engines scanned)${reputation}`);
                virusTotalLink.classList.remove('hidden');
            }
        } else {
            renderResult('virus-total-check', 'warning-icon', virusTotalData?.error || 'VirusTotal API not configured');
            virusTotalLink.classList.add('hidden');
        }
        
        // PhishTank Results
        const phishTankData = multiApiData.phishTank;
        if (phishTankData && !phishTankData.error) {
            if (phishTankData.detected) {
                const verified = phishTankData.verified ? ' (Verified)' : ' (Unverified)';
                renderResult('phishtank-check', 'error-icon', `❌ PhishTank: Phishing site detected${verified}`);
            } else {
                renderResult('phishtank-check', 'success-icon', '✅ PhishTank: Not flagged as phishing - Safe');
            }
        } else {
            renderResult('phishtank-check', 'info-icon', 'ℹ️ PhishTank: Check unavailable');
        }
        
        // URLVoid Results
        const urlVoidData = multiApiData.urlVoid;
        if (urlVoidData && !urlVoidData.error) {
            if (urlVoidData.detected) {
                renderResult('urlvoid-check', 'error-icon', `❌ URLVoid: Detected by ${urlVoidData.engines.length} engines (Reputation: ${urlVoidData.reputation})`);
            } else {
                renderResult('urlvoid-check', 'success-icon', `✅ URLVoid: Clean (Reputation: ${urlVoidData.reputation})`);
            }
        } else {
            renderResult('urlvoid-check', 'info-icon', 'ℹ️ URLVoid: Check unavailable');
        }
        
        // Hybrid Analysis Results
        const hybridData = multiApiData.hybridAnalysis;
        if (hybridData && !hybridData.error) {
            if (hybridData.detected) {
                const threatLevel = hybridData.threatScore > 50 ? 'HIGH' : hybridData.threatScore > 20 ? 'MEDIUM' : 'LOW';
                renderResult('hybrid-analysis-check', 'error-icon', `❌ Hybrid Analysis: ${hybridData.verdict} (Threat Score: ${hybridData.threatScore} - ${threatLevel})`);
            } else {
                renderResult('hybrid-analysis-check', 'success-icon', `✅ Hybrid Analysis: Clean (Threat Score: ${hybridData.threatScore})`);
            }
        } else {
            renderResult('hybrid-analysis-check', 'info-icon', 'ℹ️ Hybrid Analysis: Check unavailable');
        }
        
        // Google Safe Browsing Results
        const googleData = multiApiData.googleSafeBrowsing;
        if (googleData && !googleData.error) {
            if (googleData.detected) {
                const threatTypes = googleData.threats.map(t => t.threatType).join(', ');
                renderResult('google-safebrowsing-check', 'error-icon', `❌ Google Safe Browsing: ${threatTypes} detected`);
            } else {
                renderResult('google-safebrowsing-check', 'success-icon', '✅ Google Safe Browsing: Safe');
            }
        } else {
            renderResult('google-safebrowsing-check', 'info-icon', 'ℹ️ Google Safe Browsing: Check unavailable');
        }
        
        // Multi-API Summary
        const totalDetections = [
            virusTotalData?.detected,
            phishTankData?.detected,
            urlVoidData?.detected,
            hybridData?.detected,
            googleData?.detected
        ].filter(Boolean).length;
        
        const totalEngines = 5;
        if (totalDetections > 0) {
            renderResult('multi-api-summary', 'error-icon', `❌ Multi-Engine Summary: ${totalDetections}/${totalEngines} engines detected threats - HIGH RISK`);
        } else {
            renderResult('multi-api-summary', 'success-icon', `✅ Multi-Engine Summary: All ${totalEngines} engines report clean - SAFE`);
        }
        
        // Suspicious domains
        const suspiciousDomains = domData.suspiciousDomains || [];
        if (suspiciousDomains.length > 0) {
            renderResult('suspicious-domains-check', 'warning-icon', `Suspicious domains: ${suspiciousDomains.join(', ')}`);
        } else {
            renderResult('suspicious-domains-check', 'success-icon', 'No suspicious domains detected');
        }
        
        renderResult('form-cross-origin-check', domData.formCrossOriginAction ? 'warning-icon' : 'success-icon', domData.formCrossOriginAction ? 'Form submits to different origin' : 'No cross-origin form actions detected');
        renderResult('obfuscated-js-check', domData.hasObfuscatedJS ? 'warning-icon' : 'success-icon', domData.hasObfuscatedJS ? 'Possible obfuscated JavaScript found' : 'No obvious obfuscated JavaScript detected');
        
        // Crypto mining detection
        renderResult('crypto-mining-check', domData.cryptoMiningDetected ? 'error-icon' : 'success-icon', domData.cryptoMiningDetected ? 'Crypto mining activity detected' : 'No crypto mining detected');

        // Subresource Integrity checks
        const missingScripts = domData.missingSRIExternalScripts || 0;
        const missingStyles = domData.missingSRIExternalStyles || 0;
        const totalMissing = missingScripts + missingStyles;
        renderResult('sri-check', totalMissing > 0 ? 'warning-icon' : 'success-icon', totalMissing > 0 ? `Missing SRI: ${missingScripts} external script(s), ${missingStyles} style(s)` : 'SRI present or no external resources');

        // Traffic Analysis
        renderResult('total-requests-check', 'info-icon', `Total network requests: ${domData.totalRequests || 0}`);
        renderResult('external-requests-check', domData.externalRequests > 5 ? 'warning-icon' : 'info-icon', `External network requests: ${domData.externalRequests || 0}`);
        renderResult('large-resources-check', domData.hasLargeResources ? 'warning-icon' : 'success-icon', domData.hasLargeResources ? 'Large resources (>1MB) detected' : 'No large resources detected');
    }

    // Function to call Gemini API with fallback
    async function callGeminiAPI(prompt) {
        llmOutputDiv.classList.add('hidden');
        llmOutputLoading.classList.remove('hidden');

        try {
            let chatHistory = [];
            chatHistory.push({ role: "user", parts: [{ text: prompt }] });
            const payload = { contents: chatHistory };
            // Use environment variable or config for API key in production
            const apiKey = "AIzaSyBnlUB0DA68gE4_CeuXC1cMjAZuWGkF_Lk"; // Replace with actual API key for production
            
            // Check if API key is properly configured
            if (!apiKey || apiKey === "AIzaSyBnlUB0DA68gE4_CeuXC1cMjAZuWGkF_Lk") {
                return generateFallbackAnalysis(prompt);
            }
            
            const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
            
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                console.error("API response not OK:", response.status, response.statusText);
                return generateFallbackAnalysis(prompt);
            }

            const result = await response.json();

            if (result.candidates && result.candidates.length > 0 &&
                result.candidates[0].content && result.candidates[0].content.parts &&
                result.candidates[0].content.parts.length > 0) {
                return result.candidates[0].content.parts[0].text;
            } else {
                console.error("Gemini API response structure unexpected:", result);
                return generateFallbackAnalysis(prompt);
            }
        } catch (error) {
            console.error("Error calling Gemini API:", error);
            return generateFallbackAnalysis(prompt);
        } finally {
            llmOutputLoading.classList.add('hidden');
            llmOutputDiv.classList.remove('hidden');
        }
    }
    
    // Fallback function when API is unavailable
    function generateFallbackAnalysis(prompt) {
        // Extract key information from the prompt
        const isSecuritySummaryPrompt = prompt.includes("Overall Client-Side Security Status");
        const isExplanationPrompt = prompt.includes("explain the security risks");
        
        if (isSecuritySummaryPrompt) {
            // Basic security analysis based on data we already have
            let securityIssues = [];
            let securityStrengths = [];
            
            // Check for HTTPS
            if (currentAnalysisData.url.startsWith('https://')) {
                securityStrengths.push("HTTPS is enabled");
            } else {
                securityIssues.push("HTTPS is not enabled");
            }
            
            // Check for CSP
            if (currentAnalysisData.domData.hasCSP || 
                (currentAnalysisData.headerData && currentAnalysisData.headerData['content-security-policy'])) {
                securityStrengths.push("Content Security Policy is implemented");
            } else {
                securityIssues.push("Content Security Policy is missing");
            }
            
            // Determine overall status
            let overallStatus = "Moderate";
            if (securityIssues.length > 3) {
                overallStatus = "Not Secure";
            } else if (securityIssues.length <= 1 && securityStrengths.length >= 3) {
                overallStatus = "Secure";
            }
            
            return `## Security Summary (Offline Analysis)

**Note:** This analysis was generated offline as the AI service is currently unavailable.

### Key Findings:

${securityStrengths.length > 0 ? '**Strengths:**\n- ' + securityStrengths.join('\n- ') : ''}

${securityIssues.length > 0 ? '**Issues:**\n- ' + securityIssues.join('\n- ') : ''}

**Overall Client-Side Security Posture: ${overallStatus}**

This is a basic offline assessment. For a more detailed analysis, please try again when the AI service is available.`;
        } else if (isExplanationPrompt) {
            // Extract issues from the prompt
            const issuesMatch = prompt.match(/Issues detected:\s*([\s\S]+)/i);
            const issues = issuesMatch ? issuesMatch[1].split('\n').filter(line => line.trim().length > 0) : [];
            
            let explanations = [];
            
            // Provide basic explanations for common issues
            issues.forEach(issue => {
                if (issue.includes("Missing HTTPS")) {
                    explanations.push("**Missing HTTPS**: Websites without HTTPS send data in plain text, making it vulnerable to interception. Implement HTTPS by obtaining an SSL/TLS certificate and configuring your server to use it.");
                } else if (issue.includes("Mixed Content")) {
                    explanations.push("**Mixed Content**: Loading resources over HTTP on an HTTPS page creates security vulnerabilities. Update all resource URLs to use HTTPS instead of HTTP.");
                } else if (issue.includes("Missing Content Security Policy")) {
                    explanations.push("**Missing Content Security Policy (CSP)**: Without CSP, your site is more vulnerable to XSS attacks. Implement CSP headers to restrict which resources can be loaded.");
                }
            });
            
            if (explanations.length === 0) {
                return "Unable to generate offline explanations for the specific issues detected. Please try again when the AI service is available.";
            }
            
            return `## Security Explanations (Offline Analysis)

**Note:** These explanations were generated offline as the AI service is currently unavailable.

${explanations.join('\n\n')}

This is a basic offline assessment. For more detailed explanations, please try again when the AI service is available.`;
        }
        
        return "The AI analysis service is currently unavailable. Please check your API key configuration or try again later.";
    }

    // Automated analysis and report generation flow
    async function runAnalysisAndReport() {
        try {
            // Step 1: Get active tab information
            scanningProgress.innerText = "Getting tab information...";
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
                .catch(error => {
                    console.error("Error querying tabs:", error);
                    throw new Error("Failed to access tab information");
                });
                
            if (tabs.length === 0) {
                throw new Error("No active tab found");
            }

            const activeTab = tabs[0];
            const url = activeTab.url;
            
            // Check if URL is valid for analysis
            if (!url || url.startsWith("chrome:") || url.startsWith("chrome-extension:") || url.startsWith("about:")) {
                throw new Error("Cannot analyze browser internal pages");
            }

            // Step 2: Request header data from background script with timeout
            scanningProgress.innerText = "Collecting HTTP headers...";
            const headerResponse = await Promise.race([
                new Promise(resolve => {
                    chrome.runtime.sendMessage({ action: "getHeaders", tabId: activeTab.id }, response => {
                        if (chrome.runtime.lastError) {
                            console.warn("Warning getting headers:", chrome.runtime.lastError.message);
                            // Continue with empty headers rather than failing
                            resolve({});
                        } else {
                            resolve(response || {});
                        }
                    });
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Header request timed out")), 5000))
            ]).catch(error => {
                console.warn("Header collection warning:", error);
                return {}; // Continue with empty headers
            });

            // Step 3: Execute content script for DOM analysis
            scanningProgress.innerText = "Analyzing page DOM...";
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: activeTab.id },
                    files: ['content.js']
                });
            } catch (error) {
                console.error("Script injection failed:", error);
                throw new Error("Failed to inject content script. Ensure permissions are granted.");
            }

            // Step 4: Send message to content script to request DOM analysis with timeout
            scanningProgress.innerText = "Processing client-side data...";
            const domResponse = await Promise.race([
                new Promise((resolve, reject) => {
                    chrome.tabs.sendMessage(activeTab.id, { action: "analyzePage" }, response => {
                        if (chrome.runtime.lastError) {
                            reject(new Error(chrome.runtime.lastError.message));
                        } else if (!response) {
                            reject(new Error("No response from content script"));
                        } else {
                            resolve(response);
                        }
                    });
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Content script analysis timed out")), 10000))
            ]).catch(error => {
                console.error("DOM analysis error:", error);
                throw new Error(`Failed to analyze page: ${error.message}. Try refreshing the page.`);
            });
            
            if (!domResponse) {
                throw new Error("No DOM analysis response received");
            }

            currentAnalysisData = { domData: domResponse, headerData: headerResponse, url: url };
            displayResults(domResponse, headerResponse, url);
            
            // Show security history after analysis is complete
            showSecurityHistory();
            
            // AI steps disabled
            if (llmOutputDiv) llmOutputDiv.classList.add('hidden');
            
            // Step 7: Finish scan and enable report download
            scanningProgress.innerText = "Scan Complete!";
            // Transition to results
            setTimeout(() => {
                scanningUi.classList.add('hidden');
                resultsDiv.classList.remove('hidden');
                const downloadBtn = document.getElementById('download-report-btn');
                if (downloadBtn) {
                    downloadBtn.disabled = false;
                }
            }, 1200);
        } catch (error) {
            console.error("Analysis error:", error);
            scanningUi.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
            renderResult('https-check', 'error-icon', `Error: ${error.message}`);
        }

        // These steps are now handled in the try-catch blocks above

// Enhanced real-time monitoring with configurable intervals and notifications
let monitoringInterval;
let monitoringConfig = {
    interval: 300000, // 5 minutes default
    enabled: false,
    notifications: true,
    scanMode: 'quick', // quick, deep, or adaptive
    lastScanTime: null,
    consecutiveFailures: 0,
    maxFailures: 3
};

const setupRealTimeMonitoring = () => {
    // Clear any existing monitoring
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
    }
    
    // Load monitoring configuration from storage
    chrome.storage.local.get(['monitoringConfig'], (result) => {
        if (result.monitoringConfig) {
            monitoringConfig = { ...monitoringConfig, ...result.monitoringConfig };
        }
        
        // Set up monitoring with configured interval
    monitoringInterval = setInterval(async () => {
            await performRealTimeSecurityCheck();
        }, monitoringConfig.interval);
        
        monitoringConfig.enabled = true;
        console.log(`Real-time monitoring started with ${monitoringConfig.interval/1000}s interval`);
    });
};

const performRealTimeSecurityCheck = async () => {
        console.log("Running real-time security monitoring...");
        try {
            // Get current active tab
            const tabs = await chrome.tabs.query({active: true, currentWindow: true});
            if (tabs.length === 0) return;
            
            const tab = tabs[0];
            const url = tab.url;
            
            // Skip monitoring for browser UI pages and empty tabs
            if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || 
                url.startsWith("about:") || url.startsWith("chrome-extension://")) {
                return;
            }
            
        // Adaptive scan mode based on previous results
        let scanMode = monitoringConfig.scanMode;
        if (scanMode === 'adaptive') {
            if (currentAnalysisData && currentAnalysisData.score < 70) {
                scanMode = 'deep'; // Use deep scan for risky sites
            } else {
                scanMode = 'quick'; // Use quick scan for secure sites
            }
        }
        
        // Perform security check
        const startTime = Date.now();
        const result = await performSecurityCheck(url, scanMode);
        const duration = Date.now() - startTime;
        
        if (result.success) {
            monitoringConfig.consecutiveFailures = 0;
            monitoringConfig.lastScanTime = Date.now();
            
            // Check for security changes
            if (currentAnalysisData && result.analysisData) {
                const scoreChange = result.analysisData.score - currentAnalysisData.score;
                const criticalChange = result.analysisData.criticalIssues - currentAnalysisData.criticalIssues;
                
                // Notify about significant changes
                if (monitoringConfig.notifications && (Math.abs(scoreChange) > 10 || criticalChange !== 0)) {
                    const notification = {
                        type: scoreChange > 0 ? 'improvement' : 'deterioration',
                        scoreChange: scoreChange,
                        criticalChange: criticalChange,
                        url: url,
                        timestamp: Date.now()
                    };
                    
                    // Send notification to background script
                    chrome.runtime.sendMessage({
                        action: "showSecurityNotification",
                        notification: notification
                    });
                }
            }
            
            // Update current data
            currentAnalysisData = result.analysisData;
            
            console.log(`Real-time scan completed in ${duration}ms (${scanMode} mode)`);
        } else {
            monitoringConfig.consecutiveFailures++;
            console.error(`Real-time scan failed (${monitoringConfig.consecutiveFailures}/${monitoringConfig.maxFailures})`);
            
            // Disable monitoring if too many consecutive failures
            if (monitoringConfig.consecutiveFailures >= monitoringConfig.maxFailures) {
                console.warn("Disabling real-time monitoring due to consecutive failures");
                stopRealTimeMonitoring();
                
                if (monitoringConfig.notifications) {
                    chrome.runtime.sendMessage({
                        action: "showSecurityNotification",
                        notification: {
                            type: 'monitoring_disabled',
                            message: 'Real-time monitoring disabled due to repeated failures',
                            timestamp: Date.now()
                        }
                    });
                }
            }
        }
        
        } catch (error) {
            console.error("Real-time monitoring error:", error);
        monitoringConfig.consecutiveFailures++;
    }
};

const performSecurityCheck = async (url, scanMode = 'quick') => {
    try {
        // Get headers
        const headerResponse = await Promise.race([
            new Promise(resolve => {
                chrome.runtime.sendMessage({ action: "getHeaders", tabId: chrome.tabs.getCurrent().id }, response => {
                    resolve(response || {});
                });
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000))
        ]).catch(() => ({}));
        
        let domData = {};
        
        if (scanMode === 'deep') {
            // Perform full DOM analysis
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: chrome.tabs.getCurrent().id },
                    files: ['content.js']
                });
                
                domData = await Promise.race([
                    new Promise((resolve) => {
                        chrome.tabs.sendMessage(chrome.tabs.getCurrent().id, { action: "analyzePage" }, response => {
                            resolve(response || {});
                        });
                    }),
                    new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 10000))
                ]).catch(() => ({}));
            } catch (error) {
                console.warn("DOM analysis failed in real-time scan:", error);
            }
        } else {
            // Quick scan - minimal DOM data
            domData = {
                hasMixedContent: false,
                hasCSP: false,
                hasXFrameOptions: false,
                cookies: [],
                suspiciousExternalScripts: false,
                malwareReputationIssues: [],
                cryptoMiningDetected: false
            };
        }
        
        // Calculate security assessment
        const assessment = calculateSecurityAssessment(domData, headerResponse, url);
        
        return {
            success: true,
            analysisData: {
                domData: domData,
                headerData: headerResponse,
                url: url,
                assessment: assessment,
                scanMode: scanMode,
                timestamp: Date.now()
            }
        };
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
};

const stopRealTimeMonitoring = () => {
    if (monitoringInterval) {
        clearInterval(monitoringInterval);
        monitoringInterval = null;
    }
    monitoringConfig.enabled = false;
    chrome.storage.local.set({ monitoringEnabled: false });
    console.log("Real-time monitoring stopped");
};

// Enhanced security history with comprehensive tracking and comparison features
async function showSecurityHistory() {
    try {
        // Get current tab URL
        const tabs = await chrome.tabs.query({active: true, currentWindow: true});
        if (tabs.length === 0) return;
        
        const url = tabs[0].url;
        
        // Skip for browser UI pages and empty tabs
        if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || 
            url.startsWith("about:") || url.startsWith("chrome-extension://")) {
            announceToScreenReader("Cannot show history for browser internal pages");
            return;
        }
        
        // Get comprehensive security history for this URL
        chrome.runtime.sendMessage({action: "getSecurityHistory", url: url}, function(history) {
            if (!history || history.length === 0) {
                document.getElementById('securityHistoryContent').innerHTML = 
                    '<p class="text-gray-500 italic">No security history available for this URL.</p>';
                document.getElementById('securityHistorySection').classList.remove('hidden');
                return;
            }
            
            // Show the history section
            document.getElementById('securityHistorySection').classList.remove('hidden');
            
            // Populate enhanced history entries
            const historyContent = document.getElementById('securityHistoryContent');
            historyContent.innerHTML = '';
            
            // Create enhanced history display with comparison features
            const historyContainer = document.createElement('div');
            historyContainer.className = 'history-container';
            
            // Add comparison controls
            const comparisonControls = document.createElement('div');
            comparisonControls.className = 'comparison-controls mb-4 p-4 bg-gray-50 rounded-lg';
            comparisonControls.innerHTML = `
                <h3 class="font-semibold mb-2">Compare Scans</h3>
                <div class="flex gap-2 mb-2">
                    <select id="compare-scan-1" class="px-2 py-1 border rounded text-sm">
                        <option value="">Select first scan</option>
                    </select>
                    <select id="compare-scan-2" class="px-2 py-1 border rounded text-sm">
                        <option value="">Select second scan</option>
                    </select>
                    <button id="compare-scans-btn" class="px-3 py-1 bg-blue-500 text-white rounded text-sm hover:bg-blue-600">
                        Compare
                    </button>
                </div>
                <div id="comparison-result" class="hidden mt-2 p-2 bg-white rounded border"></div>
            `;
            historyContainer.appendChild(comparisonControls);
            
            // Create history table with enhanced information
            const historyTable = document.createElement('table');
            historyTable.className = 'w-full text-left border-collapse';
            historyTable.innerHTML = `
                <thead>
                    <tr class="bg-gray-100">
                        <th class="py-2 px-3 border-b">Date/Time</th>
                        <th class="py-2 px-3 border-b">Score</th>
                        <th class="py-2 px-3 border-b">Status</th>
                        <th class="py-2 px-3 border-b">Issues</th>
                        <th class="py-2 px-3 border-b">Actions</th>
                    </tr>
                </thead>
                <tbody id="history-entries"></tbody>
            `;
            historyContainer.appendChild(historyTable);
            
            // Populate comparison selects and history entries
            const compareSelect1 = historyContainer.querySelector('#compare-scan-1');
            const compareSelect2 = historyContainer.querySelector('#compare-scan-2');
            const historyEntries = historyContainer.querySelector('#history-entries');
            
            history.forEach((entry, index) => {
                const date = new Date(entry.timestamp);
                const formattedDate = `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
                
                // Calculate security score for this entry
                const assessment = entry.assessment || calculateSecurityAssessment(
                    entry.domData || {}, 
                    entry.headerData || {}, 
                    entry.url || ''
                );
                
                // Create option for comparison selects
                const option1 = document.createElement('option');
                option1.value = index;
                option1.textContent = `${formattedDate} (Score: ${assessment.score})`;
                compareSelect1.appendChild(option1.cloneNode(true));
                compareSelect2.appendChild(option1.cloneNode(true));
                
                // Create history table row
                const row = document.createElement('tr');
                row.className = 'border-b hover:bg-gray-50';
                
                // Determine status color
                let statusColor = 'text-green-600';
                let statusText = 'Secure';
                if (assessment.score < 50) {
                    statusColor = 'text-red-600';
                    statusText = 'Critical';
                } else if (assessment.score < 70) {
                    statusColor = 'text-orange-600';
                    statusText = 'At Risk';
                } else if (assessment.score < 85) {
                    statusColor = 'text-yellow-600';
                    statusText = 'Moderate';
                }
                
                row.innerHTML = `
                    <td class="py-2 px-3">${formattedDate}</td>
                    <td class="py-2 px-3">
                        <div class="flex items-center">
                            <span class="font-semibold">${assessment.score}</span>
                            <div class="ml-2 w-16 h-2 bg-gray-200 rounded">
                                <div class="h-2 rounded ${assessment.score >= 85 ? 'bg-green-500' : assessment.score >= 70 ? 'bg-yellow-500' : 'bg-red-500'}" 
                                     style="width: ${assessment.score}%"></div>
                            </div>
                        </div>
                    </td>
                    <td class="py-2 px-3 ${statusColor} font-medium">${statusText}</td>
                    <td class="py-2 px-3">
                        <span class="text-xs">
                            ${assessment.criticalIssues}C / ${assessment.highRiskIssues}H / ${assessment.mediumRiskIssues}M
                        </span>
                    </td>
                    <td class="py-2 px-3">
                        <button class="text-blue-600 hover:text-blue-800 text-xs mr-2 view-details" data-index="${index}">
                            Details
                        </button>
                        <button class="text-green-600 hover:text-green-800 text-xs export-scan" data-index="${index}">
                            Export
                        </button>
                    </td>
                `;
                historyEntries.appendChild(row);
                
                // Add click handlers
                row.querySelector('.view-details').addEventListener('click', () => {
                    showHistoryDetails(entry, formattedDate, assessment);
                });
                
                row.querySelector('.export-scan').addEventListener('click', () => {
                    exportScanData(entry, formattedDate);
                });
            });
            
            // Add comparison functionality
            historyContainer.querySelector('#compare-scans-btn').addEventListener('click', () => {
                const scan1Index = parseInt(compareSelect1.value);
                const scan2Index = parseInt(compareSelect2.value);
                
                if (scan1Index !== scan2Index && scan1Index >= 0 && scan2Index >= 0) {
                    compareScans(history[scan1Index], history[scan2Index]);
                } else {
                    announceToScreenReader('Please select two different scans to compare');
                }
            });
            
            historyContent.appendChild(historyContainer);
        });
    } catch (error) {
        console.error("Error showing security history:", error);
        announceToScreenReader("Error loading security history: " + error.message);
    }
}

// AI-style analysis renderer (summarizes findings locally)
function renderAIAnalysis() { /* disabled */ }

// Enhanced history details modal
function showHistoryDetails(entry, formattedDate, assessment) {
                    const modal = document.getElementById('historyModal');
                    const modalContent = document.getElementById('historyModalContent');
                    
                    modalContent.innerHTML = `
                        <div class="mb-4">
                            <h4 class="font-medium mb-1">Scan Date:</h4>
                            <p>${formattedDate}</p>
                        </div>
                        <div class="mb-4">
                            <h4 class="font-medium mb-1">URL:</h4>
                            <p class="break-all">${entry.url}</p>
                        </div>
        <div class="mb-4">
            <h4 class="font-medium mb-1">Security Assessment:</h4>
            <div class="bg-gray-100 p-3 rounded">
                <p><strong>Score:</strong> ${assessment.score}/100</p>
                <p><strong>Status:</strong> ${assessment.overallStatus}</p>
                <p><strong>Risk Level:</strong> ${assessment.riskLevel}</p>
                <p><strong>Issues:</strong> ${assessment.criticalIssues} Critical, ${assessment.highRiskIssues} High, ${assessment.mediumRiskIssues} Medium</p>
            </div>
        </div>
        <div class="mb-4">
                            <h4 class="font-medium mb-1">HTTP Headers:</h4>
            <pre class="bg-gray-100 p-2 rounded overflow-auto text-xs mb-4 max-h-40">${JSON.stringify(entry.headerData || {}, null, 2)}</pre>
                        </div>
        <div class="mb-4">
            <h4 class="font-medium mb-1">DOM Analysis:</h4>
            <pre class="bg-gray-100 p-2 rounded overflow-auto text-xs mb-4 max-h-40">${JSON.stringify(entry.domData || {}, null, 2)}</pre>
        </div>
        ${entry.multiApiResults ? `
        <div class="mb-4">
            <h4 class="font-medium mb-1">Multi-API Results:</h4>
            <pre class="bg-gray-100 p-2 rounded overflow-auto text-xs mb-4 max-h-40">${JSON.stringify(entry.multiApiResults, null, 2)}</pre>
        </div>
        ` : ''}
                    `;
                    
                    // Show the modal
                    modal.classList.remove('hidden');
}

// Compare two scans
function compareScans(scan1, scan2) {
    const assessment1 = scan1.assessment || calculateSecurityAssessment(scan1.domData || {}, scan1.headerData || {}, scan1.url || '');
    const assessment2 = scan2.assessment || calculateSecurityAssessment(scan2.domData || {}, scan2.headerData || {}, scan2.url || '');
    
    const comparisonResult = document.getElementById('comparison-result');
    comparisonResult.classList.remove('hidden');
    
    const scoreChange = assessment2.score - assessment1.score;
    const issuesChange = {
        critical: assessment2.criticalIssues - assessment1.criticalIssues,
        high: assessment2.highRiskIssues - assessment1.highRiskIssues,
        medium: assessment2.mediumRiskIssues - assessment1.mediumRiskIssues
    };
    
    let comparisonHtml = `
        <h4 class="font-semibold mb-2">Scan Comparison</h4>
        <div class="grid grid-cols-2 gap-4 text-sm">
            <div>
                <h5 class="font-medium">Scan 1 (${new Date(scan1.timestamp).toLocaleDateString()})</h5>
                <p>Score: ${assessment1.score}/100</p>
                <p>Status: ${assessment1.overallStatus}</p>
                <p>Issues: ${assessment1.criticalIssues}C / ${assessment1.highRiskIssues}H / ${assessment1.mediumRiskIssues}M</p>
            </div>
            <div>
                <h5 class="font-medium">Scan 2 (${new Date(scan2.timestamp).toLocaleDateString()})</h5>
                <p>Score: ${assessment2.score}/100</p>
                <p>Status: ${assessment2.overallStatus}</p>
                <p>Issues: ${assessment2.criticalIssues}C / ${assessment2.highRiskIssues}H / ${assessment2.mediumRiskIssues}M</p>
            </div>
        </div>
        <div class="mt-3 p-2 rounded ${scoreChange > 0 ? 'bg-green-100 text-green-800' : scoreChange < 0 ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'}">
            <strong>Score Change:</strong> ${scoreChange > 0 ? '+' : ''}${scoreChange} points
        </div>
        <div class="mt-2 text-xs">
            <p><strong>Issue Changes:</strong></p>
            <p>Critical: ${issuesChange.critical > 0 ? '+' : ''}${issuesChange.critical}</p>
            <p>High: ${issuesChange.high > 0 ? '+' : ''}${issuesChange.high}</p>
            <p>Medium: ${issuesChange.medium > 0 ? '+' : ''}${issuesChange.medium}</p>
        </div>
    `;
    
    comparisonResult.innerHTML = comparisonHtml;
}

// Export scan data
function exportScanData(entry, formattedDate) {
    const exportData = {
        timestamp: entry.timestamp,
        formattedDate: formattedDate,
        url: entry.url,
        assessment: entry.assessment || calculateSecurityAssessment(entry.domData || {}, entry.headerData || {}, entry.url || ''),
        headerData: entry.headerData,
        domData: entry.domData,
        multiApiResults: entry.multiApiResults
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `security_scan_${formattedDate.replace(/[^\w\s]/gi, '_')}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    announceToScreenReader('Scan data exported successfully');
}

// Enhanced monitoring toggle functionality with configuration options
const monitoringCheckbox = document.getElementById('monitoring-toggle');
const monitoringStatus = document.getElementById('monitoring-status');

if (monitoringCheckbox) {
    monitoringCheckbox.addEventListener('change', function() {
        if (this.checked) {
            setupRealTimeMonitoring();
            chrome.storage.local.set({ 
                monitoringEnabled: true,
                monitoringConfig: monitoringConfig
            });
            if (monitoringStatus) {
                monitoringStatus.textContent = 'ON';
                monitoringStatus.style.color = '#10b981';
            }
        } else {
            stopRealTimeMonitoring();
            chrome.storage.local.set({ monitoringEnabled: false });
            if (monitoringStatus) {
                monitoringStatus.textContent = 'OFF';
                monitoringStatus.style.color = '#64748b';
            }
        }
    });
}

// Check if monitoring was previously enabled and restore configuration
chrome.storage.local.get(['monitoringEnabled', 'monitoringConfig'], function(result) {
    if (result.monitoringEnabled && monitoringCheckbox) {
        monitoringCheckbox.checked = true;
        
        // Restore monitoring configuration
        if (result.monitoringConfig) {
            monitoringConfig = { ...monitoringConfig, ...result.monitoringConfig };
        }
        
        setupRealTimeMonitoring();
        
        if (monitoringStatus) {
            monitoringStatus.textContent = 'ON';
            monitoringStatus.style.color = '#10b981';
        }
        
        // Notify background script that monitoring is starting
        chrome.runtime.sendMessage({ 
            action: "startMonitoring",
            config: monitoringConfig
        }, function(response) {
            console.log("Monitoring status:", response ? response.status : "No response");
        });
    } else if (monitoringStatus) {
        monitoringStatus.textContent = 'OFF';
        monitoringStatus.style.color = '#64748b';
    }
});

// Add monitoring configuration UI (if needed)
function createMonitoringConfigUI() {
    const configContainer = document.createElement('div');
    configContainer.className = 'monitoring-config hidden';
    configContainer.innerHTML = `
        <div class="config-section">
            <label class="config-label">Scan Interval:</label>
            <select id="monitoring-interval">
                <option value="60000">1 minute</option>
                <option value="300000" selected>5 minutes</option>
                <option value="900000">15 minutes</option>
                <option value="1800000">30 minutes</option>
            </select>
        </div>
        <div class="config-section">
            <label class="config-label">Scan Mode:</label>
            <select id="monitoring-mode">
                <option value="quick" selected>Quick</option>
                <option value="deep">Deep</option>
                <option value="adaptive">Adaptive</option>
            </select>
        </div>
        <div class="config-section">
            <label class="config-label">
                <input type="checkbox" id="monitoring-notifications" checked> 
                Enable Notifications
            </label>
        </div>
    `;
    
    // Add event listeners for configuration changes
    const intervalSelect = configContainer.querySelector('#monitoring-interval');
    const modeSelect = configContainer.querySelector('#monitoring-mode');
    const notificationsCheckbox = configContainer.querySelector('#monitoring-notifications');
    
    intervalSelect.addEventListener('change', () => {
        monitoringConfig.interval = parseInt(intervalSelect.value);
        chrome.storage.local.set({ monitoringConfig: monitoringConfig });
        
        // Restart monitoring with new interval if enabled
        if (monitoringConfig.enabled) {
            setupRealTimeMonitoring();
        }
    });
    
    modeSelect.addEventListener('change', () => {
        monitoringConfig.scanMode = modeSelect.value;
        chrome.storage.local.set({ monitoringConfig: monitoringConfig });
    });
    
    notificationsCheckbox.addEventListener('change', () => {
        monitoringConfig.notifications = notificationsCheckbox.checked;
        chrome.storage.local.set({ monitoringConfig: monitoringConfig });
    });
    
    return configContainer;
}

// (Removed duplicate showSecurityHistory implementation and dynamic history button)



// (Removed duplicate UI transition block)
    }

    // Fallback: open printable HTML and trigger print dialog (user can save as PDF)
    function openPrintableReport() {
        const safe = (s) => (s || '').toString();
        const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Web Security Analysis Report</title>
            <style>body{font-family:Arial,Helvetica,sans-serif;padding:20px;color:#111}h1{font-size:20px;margin:0 0 12px}
            h2{font-size:16px;margin:18px 0 8px}pre{background:#f4f4f5;padding:10px;border-radius:6px;white-space:pre-wrap}
            .kv{margin:4px 0}</style></head><body>
            <h1>Web Security Analysis Report</h1>
            <div class="kv"><strong>URL:</strong> ${safe(currentAnalysisData.url)}</div>
            <div class="kv"><strong>Date:</strong> ${new Date().toLocaleString()}</div>
            <h2>Overall Client-Side Security Posture</h2>
            <div>${safe(currentLlmOverallSecurityAssessment || 'Not available')}</div>
            <h2>General Security Checks</h2>
            <pre>${[
                `HTTPS: ${currentAnalysisData.url && currentAnalysisData.url.startsWith('https://') ? 'Enabled' : 'Disabled'}`,
                `Mixed Content: ${currentAnalysisData.domData?.hasMixedContent ? 'Detected' : 'None'}`,
                `CSP: ${(currentAnalysisData.domData?.hasCSP || currentAnalysisData.headerData?.['content-security-policy']) ? 'Detected' : 'Missing'}`,
                `X-Frame-Options: ${(currentAnalysisData.domData?.hasXFrameOptions || currentAnalysisData.headerData?.['x-frame-options']) ? 'Detected' : 'Missing'}`,
                `HSTS: ${currentAnalysisData.headerData?.['strict-transport-security'] ? 'Detected' : 'Missing'}`,
                `X-Content-Type-Options: ${currentAnalysisData.headerData?.['x-content-type-options'] === 'nosniff' ? 'nosniff' : 'Missing/Incorrect'}`,
                `Referrer-Policy: ${currentAnalysisData.headerData?.['referrer-policy'] || 'Missing'}`,
                `Permissions-Policy: ${currentAnalysisData.headerData?.['permissions-policy'] ? 'Detected' : 'Missing'}`,
                `COOP: ${currentAnalysisData.headerData?.['cross-origin-opener-policy'] ? 'Detected' : 'Missing'}`,
                `CORP: ${currentAnalysisData.headerData?.['cross-origin-resource-policy'] ? 'Detected' : 'Missing'}`
            ].join('\n')}</pre>
            <h2>Cookie Security</h2>
            <pre>${(currentAnalysisData.domData?.cookies || []).map(c=>`${c.name}: ${(!c.secure?'Not Secure':'Secure')}, ${(!c.httpOnlyDetected?'Not HttpOnly':'HttpOnly')}`).join('\n') || 'No cookies accessible via JS'}</pre>
            <h2>Form Security</h2>
            <pre>${[
                `Sensitive Autocomplete: ${currentAnalysisData.domData?.sensitiveAutocomplete ? 'Detected' : 'None'}`,
                `Password Input Type: ${currentAnalysisData.domData?.passwordInputTypeError ? 'Incorrect' : 'Correct'}`
            ].join('\n')}</pre>
            <h2>Potential Malware Indicators</h2>
            <pre>${[
                `Suspicious External Scripts: ${currentAnalysisData.domData?.suspiciousExternalScripts ? 'Detected' : 'None'}`,
                `Form Cross-Origin Action: ${currentAnalysisData.domData?.formCrossOriginAction ? 'Detected' : 'None'}`,
                `Obfuscated JavaScript: ${currentAnalysisData.domData?.hasObfuscatedJS ? 'Detected' : 'None'}`
            ].join('\n')}</pre>
            <h2>Traffic Analysis</h2>
            <pre>${[
                `Total Network Requests: ${currentAnalysisData.domData?.totalRequests ?? 0}`,
                `External Network Requests: ${currentAnalysisData.domData?.externalRequests ?? 0}`,
                `Large Resources (>1MB): ${currentAnalysisData.domData?.hasLargeResources ? 'Detected' : 'None'}`
            ].join('\n')}</pre>
            ${currentLlmSummary ? `<h2>AI-Powered Security Summary</h2><pre>${safe(currentLlmSummary)}</pre>` : ''}
            ${currentLlmExplanations ? `<h2>AI-Powered Explanations & Fixes</h2><pre>${safe(currentLlmExplanations)}</pre>` : ''}
            <script>setTimeout(()=>window.print(), 200);</script>
        </body></html>`;
        const w = window.open('about:blank');
        if (!w) return;
        w.document.write(html);
        w.document.close();
        w.focus();
    }

    // Enhanced PDF Report generation with better formatting and data visualization
    async function generatePdfReport() {
        pdfLoadingText.classList.remove('hidden');

        try {
            if (typeof window.jspdf === 'undefined' || typeof window.jspdf.jsPDF === 'undefined') {
                // Fallback for MV3 where external CDN is blocked: open printable report
                openPrintableReport();
                pdfLoadingText.innerText = "Opened printable report. Use 'Save as PDF' to download.";
                return;
            }

            const jsPDF = window.jspdf.jsPDF;
            const doc = new jsPDF();
            let y = 10;
            const lineHeight = 7;
            const margin = 10;
            const maxWidth = 190;

            // Enhanced header with styling
            doc.setFontSize(20);
            doc.setTextColor(102, 126, 234); // Primary color
            doc.text("Web Security Analysis Report", margin, y);
            y += lineHeight * 1.5;

            // Add decorative line
            doc.setDrawColor(102, 126, 234);
            doc.setLineWidth(0.5);
            doc.line(margin, y, margin + 180, y);
            y += lineHeight;

            // Report metadata with better formatting
            doc.setFontSize(12);
            doc.setTextColor(0, 0, 0);
            doc.text(`Website URL: ${currentAnalysisData.url}`, margin, y);
            y += lineHeight;
            doc.text(`Analysis Date: ${new Date().toLocaleString()}`, margin, y);
            y += lineHeight;
            doc.text(`Report Generated By: Web Security Analyzer Extension`, margin, y);
            y += lineHeight * 2;

            const addSection = (title, content, isCritical = false) => {
                if (y + lineHeight * 3 > doc.internal.pageSize.height - margin) {
                    doc.addPage();
                    y = margin;
                }
                
                // Section title with styling
                doc.setFontSize(14);
                doc.setTextColor(isCritical ? 239 : 102, isCritical ? 68 : 126, isCritical ? 68 : 234);
                doc.text(title, margin, y);
                y += lineHeight;
                
                // Content with proper formatting
                doc.setFontSize(10);
                doc.setTextColor(0, 0, 0);
                const splitText = doc.splitTextToSize(content, maxWidth);
                doc.text(splitText, margin, y);
                y += splitText.length * lineHeight + lineHeight;
            };

            // Enhanced security assessment summary with visual elements
            const assessment = calculateSecurityAssessment(
                currentAnalysisData.domData || {}, 
                currentAnalysisData.headerData || {}, 
                currentAnalysisData.url || ''
            );
            
            // Security score visualization
            const scoreColor = assessment.score >= 85 ? [16, 185, 129] : 
                             assessment.score >= 70 ? [245, 158, 11] : 
                             assessment.score >= 50 ? [239, 68, 68] : [124, 45, 18];
            
            doc.setFillColor(scoreColor[0], scoreColor[1], scoreColor[2]);
            doc.rect(margin, y, (assessment.score / 100) * 180, 8, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(12);
            doc.text(`Security Score: ${assessment.score}/100`, margin + 5, y + 5.5);
            y += lineHeight * 2;
            
            doc.setTextColor(0, 0, 0);
            addSection("Security Assessment Summary", 
                `Overall Security Status: ${assessment.overallStatus}\n` +
                `Risk Level: ${assessment.riskLevel}\n` +
                `Issues Breakdown:\n` +
                `• Critical Issues: ${assessment.criticalIssues}\n` +
                `• High Risk Issues: ${assessment.highRiskIssues}\n` +
                `• Medium Risk Issues: ${assessment.mediumRiskIssues}\n` +
                `• Low Risk Issues: ${assessment.lowRiskIssues}\n\n` +
                `Top Recommendations:\n${assessment.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n')}`,
                assessment.criticalIssues > 0
            );

            // Detailed security metrics breakdown
            if (assessment.detailedBreakdown) {
                let breakdownContent = "";
                Object.entries(assessment.detailedBreakdown).forEach(([category, data]) => {
                    const percentage = Math.round((data.score / data.max) * 100);
                    breakdownContent += `${category.charAt(0).toUpperCase() + category.slice(1)}: ${data.score}/${data.max} (${percentage}%)\n`;
                });
                addSection("Detailed Security Breakdown", breakdownContent);
            }

            // AI Analysis section
            if (currentLlmOverallSecurityAssessment) {
                addSection("AI-Powered Security Assessment", currentLlmOverallSecurityAssessment);
            }

            // Enhanced general security checks with status indicators
            let generalChecksContent = "";
            const securityChecks = [
                { name: "HTTPS", status: currentAnalysisData.url.startsWith('https://'), critical: true },
                { name: "Mixed Content", status: !currentAnalysisData.domData.hasMixedContent, critical: true },
                { name: "Content Security Policy", status: currentAnalysisData.domData.hasCSP || (currentAnalysisData.headerData && currentAnalysisData.headerData['content-security-policy']), critical: true },
                { name: "X-Frame-Options", status: currentAnalysisData.domData.hasXFrameOptions || (currentAnalysisData.headerData && currentAnalysisData.headerData['x-frame-options']), critical: false },
                { name: "HSTS", status: currentAnalysisData.headerData && currentAnalysisData.headerData['strict-transport-security'], critical: false },
                { name: "X-Content-Type-Options", status: currentAnalysisData.headerData && currentAnalysisData.headerData['x-content-type-options'] === 'nosniff', critical: false },
                { name: "Referrer-Policy", status: currentAnalysisData.headerData && currentAnalysisData.headerData['referrer-policy'], critical: false },
                { name: "Permissions-Policy", status: currentAnalysisData.headerData && currentAnalysisData.headerData['permissions-policy'], critical: false }
            ];

            securityChecks.forEach(check => {
                const status = check.status ? "✓ PASS" : "✗ FAIL";
                const criticality = check.critical ? " (CRITICAL)" : "";
                generalChecksContent += `${check.name}: ${status}${criticality}\n`;
            });
            addSection("General Security Checks", generalChecksContent);

            // Enhanced cookie security analysis
            let cookieContent = "";
            if (currentAnalysisData.domData.cookies && currentAnalysisData.domData.cookies.length > 0) {
                cookieContent += `Total Cookies Found: ${currentAnalysisData.domData.cookies.length}\n\n`;
                currentAnalysisData.domData.cookies.forEach((cookie, index) => {
                    let status = [];
                    let securityScore = 0;
                    if (!cookie.secure) status.push('Not Secure');
                    else securityScore += 50;
                    if (!cookie.httpOnlyDetected) status.push('Not HttpOnly');
                    else securityScore += 50;
                    
                    const securityLevel = securityScore === 100 ? "SECURE" : securityScore === 50 ? "PARTIAL" : "INSECURE";
                    cookieContent += `${index + 1}. ${cookie.name}: ${securityLevel} (${status.length > 0 ? status.join(', ') : 'Secure & HttpOnly'})\n`;
                });
            } else {
                cookieContent = "No cookies found or accessible via JavaScript.\n";
            }
            addSection("Cookie Security Analysis", cookieContent);

            // Enhanced form security
            let formContent = `Sensitive Autocomplete: ${currentAnalysisData.domData.sensitiveAutocomplete ? '⚠️ DETECTED' : '✓ Not Detected'}\n`;
            formContent += `Password Input Type: ${currentAnalysisData.domData.passwordInputTypeError ? '⚠️ INCORRECT' : '✓ Correct'}\n`;
            formContent += `\nNote: This extension cannot verify server-side password encryption or hashing. Ensure strong hashing algorithms (bcrypt, Argon2, scrypt) are used server-side.\n`;
            addSection("Form Security Analysis", formContent);

            // Enhanced malware detection with multi-API results
            let malwareContent = "";
            const multiApiData = currentAnalysisData.multiApiResults || {};
            
            malwareContent += `Suspicious External Scripts: ${currentAnalysisData.domData.suspiciousExternalScripts ? '⚠️ DETECTED' : '✓ None Detected'}\n`;
            malwareContent += `Form Cross-Origin Action: ${currentAnalysisData.domData.formCrossOriginAction ? '⚠️ DETECTED' : '✓ None Detected'}\n`;
            malwareContent += `Obfuscated JavaScript: ${currentAnalysisData.domData.hasObfuscatedJS ? '⚠️ DETECTED' : '✓ None Detected'}\n`;
            malwareContent += `Crypto Mining: ${currentAnalysisData.domData.cryptoMiningDetected ? '🚨 DETECTED' : '✓ None Detected'}\n\n`;
            
            // Multi-API detection results
            malwareContent += "Multi-Engine Detection Results:\n";
            const apis = [
                { name: "VirusTotal", data: multiApiData.virusTotal },
                { name: "PhishTank", data: multiApiData.phishTank },
                { name: "URLVoid", data: multiApiData.urlVoid },
                { name: "Hybrid Analysis", data: multiApiData.hybridAnalysis },
                { name: "Google Safe Browsing", data: multiApiData.googleSafeBrowsing }
            ];
            
            apis.forEach(api => {
                if (api.data && !api.data.error) {
                    const status = api.data.detected ? "🚨 THREAT DETECTED" : "✓ CLEAN";
                    malwareContent += `• ${api.name}: ${status}\n`;
                } else {
                    malwareContent += `• ${api.name}: ⚠️ UNAVAILABLE\n`;
                }
            });
            
            addSection("Malware Detection Analysis", malwareContent, 
                currentAnalysisData.domData.cryptoMiningDetected || 
                (multiApiData.virusTotal && multiApiData.virusTotal.detected) ||
                (multiApiData.phishTank && multiApiData.phishTank.detected)
            );

            // Enhanced traffic analysis
            let trafficContent = `Total Network Requests: ${currentAnalysisData.domData.totalRequests || 0}\n`;
            trafficContent += `External Network Requests: ${currentAnalysisData.domData.externalRequests || 0}\n`;
            trafficContent += `Large Resources (>1MB): ${currentAnalysisData.domData.hasLargeResources ? '⚠️ DETECTED' : '✓ None Detected'}\n`;
            trafficContent += `Missing SRI (Scripts): ${currentAnalysisData.domData.missingSRIExternalScripts || 0}\n`;
            trafficContent += `Missing SRI (Styles): ${currentAnalysisData.domData.missingSRIExternalStyles || 0}\n`;
            addSection("Traffic Analysis", trafficContent);

            // AI-Powered Analysis sections
            if (currentLlmSummary) {
                addSection("AI-Powered Security Summary", currentLlmSummary);
            }
            if (currentLlmExplanations) {
                addSection("AI-Powered Explanations & Remediation", currentLlmExplanations);
            }

            // Footer with generation info
            y = doc.internal.pageSize.height - 20;
            doc.setFontSize(8);
            doc.setTextColor(128, 128, 128);
            doc.text(`Generated by Web Security Analyzer Extension v1.1`, margin, y);
            doc.text(`Report ID: ${Date.now()}`, margin + 100, y);

            // Save with timestamp
            const timestamp = new Date().toISOString().slice(0,19).replace(/:/g, '-');
            doc.save(`security_report_${timestamp}.pdf`);
            pdfLoadingText.innerText = "PDF report generated successfully!";

        } catch (error) {
            console.error("Error generating PDF:", error);
            // As a fallback, open printable report
            openPrintableReport();
            pdfLoadingText.innerText = "Opened printable report. Use 'Save as PDF' to download.";
        } finally {
            setTimeout(() => { pdfLoadingText.classList.add('hidden'); }, 5000); // Hide message after 5 seconds
        }
    }

    // Enhanced VirusTotal API integration with improved error handling
    async function checkUrlWithVirusTotal(url) {
        if (!virusTotalApiKey || virusTotalApiKey === "YOUR_VIRUSTOTAL_API_KEY") {
            return { error: "VirusTotal API key not configured", source: "VirusTotal API" };
        }
        
        try {
            // Hash the URL for VirusTotal API
            const urlHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url));
            const urlHashHex = Array.from(new Uint8Array(urlHash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            
            // Try to get existing analysis first
            const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlHashHex}`, {
                method: 'GET',
                headers: {
                    'x-apikey': virusTotalApiKey,
                    'Accept': 'application/json',
                    'User-Agent': 'SecurityExtension/1.0'
                }
            });
            
            if (!response.ok) {
                if (response.status === 404) {
                    // URL not found, try to submit for scanning
                    return await submitUrlForScanning(url);
                } else if (response.status === 429) {
                    return { error: "VirusTotal API rate limit exceeded", source: "VirusTotal API" };
                } else if (response.status === 403) {
                    return { error: "VirusTotal API key invalid or expired", source: "VirusTotal API" };
                }
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            const analysis = data.data?.attributes?.last_analysis_stats;
            
            if (analysis) {
                const positives = analysis.malicious || 0;
                const suspicious = analysis.suspicious || 0;
                const total = (analysis.malicious || 0) + (analysis.harmless || 0) + (analysis.suspicious || 0) + (analysis.undetected || 0);
                
                // Enhanced threat assessment
                let threatLevel = 'clean';
                if (positives >= 5) threatLevel = 'high';
                else if (positives >= 2) threatLevel = 'medium';
                else if (positives > 0 || suspicious > 0) threatLevel = 'low';
                
                return {
                    detected: positives > 0 || suspicious > 0,
                    positives: positives,
                    suspicious: suspicious,
                    total: total,
                    threatLevel: threatLevel,
                    scan_date: data.data?.attributes?.last_analysis_date,
                    permalink: `https://www.virustotal.com/gui/url/${data.data?.id}`,
                    reputation: data.data?.attributes?.reputation || 0,
                    categories: data.data?.attributes?.categories || {},
                    source: "VirusTotal API",
                    success: true
                };
            }
            
            return { error: "Invalid response format", source: "VirusTotal API" };
        } catch (error) {
            console.error("VirusTotal API error:", error);
            return { 
                error: error.message, 
                source: "VirusTotal API",
                success: false
            };
        }
    }
    
    // Enhanced URL submission for scanning with better error handling
    async function submitUrlForScanning(url) {
        try {
            const response = await fetch('https://www.virustotal.com/api/v3/urls', {
                method: 'POST',
                headers: {
                    'x-apikey': virusTotalApiKey,
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'SecurityExtension/1.0'
                },
                body: `url=${encodeURIComponent(url)}`
            });
            
            if (response.ok) {
                const data = await response.json();
                return { 
                    status: "submitted", 
                    message: "URL submitted for scanning. Results will be available shortly.",
                    scanId: data.data?.id,
                    source: "VirusTotal API",
                    success: true
                };
            } else if (response.status === 429) {
                return { 
                    error: "VirusTotal API rate limit exceeded. Please try again later.",
                    source: "VirusTotal API"
                };
            } else if (response.status === 403) {
                return { 
                    error: "VirusTotal API key invalid or expired",
                    source: "VirusTotal API"
                };
            } else {
                return { 
                    error: `Failed to submit URL for scanning: HTTP ${response.status}`,
                    source: "VirusTotal API"
                };
            }
        } catch (error) {
            return { 
                error: `Submission failed: ${error.message}`,
                source: "VirusTotal API",
                success: false
            };
        }
    }
    
    // PhishTank API with fallback heuristics
    async function checkPhishTank(url) {
        try {
            // Try PhishTank API first
            const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'SecurityExtension/1.0'
                },
                body: `url=${encodeURIComponent(url)}&format=json`
            });
            
            if (response.ok) {
                const data = await response.json();
                return {
                    detected: data.results && data.results.in_database,
                    verified: data.results && data.results.verified,
                    phishTankUrl: data.results && data.results.phish_detail_page,
                    source: 'PhishTank API'
                };
            }
        } catch (error) {
            console.log('PhishTank API failed, using heuristic fallback');
        }
        
        // Fallback to heuristic analysis
        return checkPhishTankHeuristic(url);
    }

    // Enhanced heuristic phishing detection with ML-inspired patterns
    function checkPhishTankHeuristic(url) {
        const domain = new URL(url).hostname.toLowerCase();
        const pathname = new URL(url).pathname.toLowerCase();
        const fullUrl = url.toLowerCase();
        
        // Advanced phishing patterns with scoring
        const phishingPatterns = {
            // Brand impersonation patterns (high risk)
            brandImpersonation: [
                { pattern: /paypal.*security|paypal.*verify/i, score: 80, type: 'PayPal phishing' },
                { pattern: /amazon.*account|amazon.*verify/i, score: 80, type: 'Amazon phishing' },
                { pattern: /microsoft.*verify|microsoft.*security/i, score: 80, type: 'Microsoft phishing' },
                { pattern: /apple.*id|apple.*security/i, score: 80, type: 'Apple phishing' },
                { pattern: /google.*account|google.*security/i, score: 80, type: 'Google phishing' },
                { pattern: /facebook.*security|facebook.*verify/i, score: 80, type: 'Facebook phishing' },
                { pattern: /bank.*login|bank.*security/i, score: 90, type: 'Banking phishing' }
            ],
            
            // Urgency and social engineering patterns (medium-high risk)
            urgencyPatterns: [
                { pattern: /urgent.*action|immediate.*action/i, score: 70, type: 'Urgency scam' },
                { pattern: /verify.*account|confirm.*account/i, score: 60, type: 'Account verification scam' },
                { pattern: /suspended.*account|locked.*account/i, score: 70, type: 'Account suspension scam' },
                { pattern: /update.*information|update.*details/i, score: 60, type: 'Information update scam' },
                { pattern: /security.*breach|data.*breach/i, score: 75, type: 'Security breach scam' },
                { pattern: /limited.*time|expires.*soon/i, score: 65, type: 'Time pressure scam' }
            ],
            
            // Technical indicators (medium risk)
            technicalIndicators: [
                { pattern: /\.tk$|\.ml$|\.ga$|\.cf$/i, score: 50, type: 'Suspicious TLD' },
                { pattern: /^\d+\.\d+\.\d+\.\d+/, score: 60, type: 'IP address URL' },
                { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|short\.ly/i, score: 40, type: 'URL shortener' },
                { pattern: /[0-9]{4,}/, score: 30, type: 'Numerical domain' },
                { pattern: /[a-z]{1,3}[0-9]{3,}/, score: 35, type: 'Random character pattern' }
            ],
            
            // Domain structure analysis (low-medium risk)
            domainStructure: [
                { pattern: /.*-.*-.*-.*/, score: 25, type: 'Multiple hyphens' },
                { pattern: /.*\..*\..*\..*/, score: 20, type: 'Multiple subdomains' },
                { pattern: /.*[0-9]{2,}.*/, score: 30, type: 'Numbers in domain' }
            ]
        };
        
        let totalScore = 0;
        let detectedPatterns = [];
        let riskFactors = [];
        
        // Analyze each category
        Object.entries(phishingPatterns).forEach(([category, patterns]) => {
            patterns.forEach(({ pattern, score, type }) => {
                if (pattern.test(fullUrl) || pattern.test(domain) || pattern.test(pathname)) {
                    totalScore += score;
                    detectedPatterns.push(type);
                    
                    // Add risk factors based on category
                    if (category === 'brandImpersonation') {
                        riskFactors.push('Brand impersonation detected');
                    } else if (category === 'urgencyPatterns') {
                        riskFactors.push('Social engineering tactics detected');
                    } else if (category === 'technicalIndicators') {
                        riskFactors.push('Suspicious technical indicators');
                    }
                }
            });
        });
        
        // Additional heuristics
        const additionalChecks = {
            // Check for typosquatting
            typosquatting: checkTyposquatting(domain),
            
            // Check for homograph attacks
            homographAttack: checkHomographAttack(domain),
            
            // Check domain age (if available)
            domainAge: checkDomainAge(domain),
            
            // Check for suspicious subdomains
            suspiciousSubdomains: checkSuspiciousSubdomains(domain)
        };
        
        // Add scores from additional checks
        Object.entries(additionalChecks).forEach(([check, result]) => {
            if (result.score > 0) {
                totalScore += result.score;
                detectedPatterns.push(result.type);
                if (result.riskFactor) {
                    riskFactors.push(result.riskFactor);
                }
            }
        });
        
        // Calculate final risk level
        let riskLevel = 'low';
        if (totalScore >= 100) riskLevel = 'critical';
        else if (totalScore >= 70) riskLevel = 'high';
        else if (totalScore >= 40) riskLevel = 'medium';
        
        return {
            detected: totalScore >= 40,
            verified: false,
            source: 'Enhanced Heuristic Analysis',
            riskScore: Math.min(totalScore, 100),
            riskLevel: riskLevel,
            detectedPatterns: detectedPatterns,
            riskFactors: riskFactors,
            details: {
                method: 'enhanced_pattern_matching',
                total_patterns_checked: Object.values(phishingPatterns).flat().length + Object.keys(additionalChecks).length,
                score_breakdown: {
                    phishing_patterns: totalScore - Object.values(additionalChecks).reduce((sum, check) => sum + (check.score || 0), 0),
                    additional_checks: Object.values(additionalChecks).reduce((sum, check) => sum + (check.score || 0), 0)
                }
            }
        };
    }
    
    // Additional heuristic functions
    function checkTyposquatting(domain) {
        const commonBrands = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'twitter', 'instagram'];
        const typosquattingPatterns = [
            /paypa1|paypaI|paypa1/i,
            /amaz0n|amaz0n|amazom/i,
            /micr0soft|micr0s0ft|micr0s0ft/i,
            /g00gle|g00g1e|g00gle/i,
            /app1e|app1e|app1e/i
        ];
        
        for (const pattern of typosquattingPatterns) {
            if (pattern.test(domain)) {
                return {
                    score: 60,
                    type: 'Typosquatting detected',
                    riskFactor: 'Domain appears to impersonate a legitimate brand'
                };
            }
        }
        
        return { score: 0 };
    }
    
    function checkHomographAttack(domain) {
        // Check for homograph attacks using Unicode characters
        const homographPatterns = [
            /[а-я]/i, // Cyrillic characters
            /[α-ω]/i, // Greek characters
            /[٠-٩]/i  // Arabic-Indic digits
        ];
        
        for (const pattern of homographPatterns) {
            if (pattern.test(domain)) {
                return {
                    score: 70,
                    type: 'Homograph attack detected',
                    riskFactor: 'Domain uses characters that look like Latin but are from different scripts'
                };
            }
        }
        
        return { score: 0 };
    }
    
    function checkDomainAge(domain) {
        // This would typically require WHOIS data, but we can make educated guesses
        const suspiciousNewDomainPatterns = [
            /.*new.*/i,
            /.*temp.*/i,
            /.*test.*/i,
            /.*demo.*/i,
            /.*trial.*/i
        ];
        
        for (const pattern of suspiciousNewDomainPatterns) {
            if (pattern.test(domain)) {
                return {
                    score: 30,
                    type: 'Suspicious new domain',
                    riskFactor: 'Domain name suggests it may be temporary or newly created'
                };
            }
        }
        
        return { score: 0 };
    }
    
    function checkSuspiciousSubdomains(domain) {
        const suspiciousSubdomains = [
            'secure', 'security', 'login', 'account', 'verify', 'update', 'support',
            'admin', 'www', 'mail', 'ftp', 'api', 'app', 'mobile'
        ];
        
        const subdomains = domain.split('.');
        if (subdomains.length > 2) {
            const subdomain = subdomains[0];
            if (suspiciousSubdomains.includes(subdomain.toLowerCase())) {
                return {
                    score: 25,
                    type: 'Suspicious subdomain',
                    riskFactor: 'Subdomain name commonly used in phishing attacks'
                };
            }
        }
        
        return { score: 0 };
    }
    
    // URLVoid API with domain reputation heuristics
    async function checkUrlVoid(url) {
        try {
            const domain = new URL(url).hostname;
            
            // Try URLVoid API first (requires registration)
            if (!urlVoidApiKey || urlVoidApiKey === "YOUR_URLVOID_API_KEY") {
                throw new Error('URLVoid API key not configured');
            }
            const response = await fetch(`https://api.urlvoid.com/v1/pay-as-you-go/?host=${domain}&key=${encodeURIComponent(urlVoidApiKey)}`);
            
            if (response.ok) {
                const data = await response.json();
                return {
                    detected: data.detected_by && data.detected_by.length > 0,
                    engines: data.detected_by || [],
                    reputation: data.reputation_score || 0,
                    source: 'URLVoid API'
                };
            }
        } catch (error) {
            console.log('URLVoid API failed, using domain reputation heuristics');
        }
        
        // Fallback to domain reputation heuristics
        return checkDomainReputation(url);
    }

    // Domain reputation heuristics
    function checkDomainReputation(url) {
        const domain = new URL(url).hostname.toLowerCase();
        
        // Known malicious TLDs and patterns
        const maliciousPatterns = [
            // Suspicious TLDs
            /\.tk$|\.ml$|\.ga$|\.cf$|\.tk$/i,
            // Free hosting services often used for malicious sites
            /000webhost|freehostia|infinityfree|byethost/i,
            // Common malicious subdomains
            /malware|virus|phish|scam|fake/i,
            // Recently registered domains (common in attacks)
            /new|temp|test|demo/i
        ];
        
        // Domain age heuristics (simplified)
        const isNewDomain = domain.includes('new') || domain.includes('temp') || domain.includes('test');
        const hasSuspiciousTLD = /\.tk$|\.ml$|\.ga$|\.cf$/i.test(domain);
        const hasSuspiciousKeywords = /malware|virus|phish|scam|fake/i.test(domain);
        
        const riskScore = (isNewDomain ? 30 : 0) + (hasSuspiciousTLD ? 40 : 0) + (hasSuspiciousKeywords ? 50 : 0);
        const isDetected = riskScore > 50;
        
        return {
            detected: isDetected,
            reputation: Math.max(0, 100 - riskScore),
            engines: isDetected ? ['Heuristic Analysis'] : [],
            source: 'Domain Reputation Heuristics',
            details: {
                risk_score: riskScore,
                new_domain: isNewDomain,
                suspicious_tld: hasSuspiciousTLD,
                suspicious_keywords: hasSuspiciousKeywords
            }
        };
    }
    
    // Hybrid Analysis API with threat heuristics
    async function checkHybridAnalysis(url) {
        try {
            // Try Hybrid Analysis API first
            if (!hybridAnalysisApiKey || hybridAnalysisApiKey === "YOUR_HYBRIDANALYSIS_API_KEY") {
                throw new Error('Hybrid Analysis API key not configured');
            }
            const response = await fetch('https://www.hybrid-analysis.com/api/v2/quick-scan/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'api-key': hybridAnalysisApiKey,
                    'User-Agent': 'SecurityExtension/1.0'
                },
                body: `url=${encodeURIComponent(url)}`
            });
            
            if (response.ok) {
                const data = await response.json();
                return {
                    detected: data.threat_score > 0,
                    threatScore: data.threat_score || 0,
                    verdict: data.verdict || 'unknown',
                    source: 'Hybrid Analysis API'
                };
            }
        } catch (error) {
            console.log('Hybrid Analysis API failed, using threat heuristics');
        }
        
        // Fallback to threat heuristics
        return checkThreatHeuristics(url);
    }

    // Enhanced threat heuristics analysis with ML-inspired patterns
    function checkThreatHeuristics(url) {
        const domain = new URL(url).hostname.toLowerCase();
        const pathname = new URL(url).pathname.toLowerCase();
        const fullUrl = url.toLowerCase();
        
        // Advanced threat analysis with scoring
        const threatAnalysis = {
            // Malware indicators (high risk)
            malwareIndicators: [
                { pattern: /malware|virus|trojan|worm|backdoor|rootkit/i, score: 80, type: 'Malware keywords' },
                { pattern: /\.exe$|\.scr$|\.bat$|\.cmd$|\.com$|\.pif$|\.msi$/i, score: 90, type: 'Executable file extension' },
                { pattern: /exploit|payload|injection|bypass|evasion/i, score: 75, type: 'Attack patterns' },
                { pattern: /keylogger|spyware|adware|ransomware/i, score: 85, type: 'Spyware/malware types' }
            ],
            
            // Cryptocurrency mining (medium-high risk)
            cryptoMining: [
                { pattern: /miner|mining|crypto|bitcoin|monero|ethereum/i, score: 70, type: 'Cryptocurrency mining' },
                { pattern: /coinhive|miningpool|pool.*mining/i, score: 80, type: 'Mining pool references' },
                { pattern: /hashrate|hash.*rate|mining.*rig/i, score: 60, type: 'Mining terminology' }
            ],
            
            // Command and control (high risk)
            commandControl: [
                { pattern: /c2|c&c|command.*control/i, score: 85, type: 'C2 infrastructure' },
                { pattern: /botnet|zombie|infected.*host/i, score: 80, type: 'Botnet indicators' },
                { pattern: /remote.*access|backdoor|shell/i, score: 75, type: 'Remote access tools' }
            ],
            
            // Suspicious hosting and domains (medium risk)
            suspiciousHosting: [
                { pattern: /torrent|warez|crack|keygen|serial/i, score: 50, type: 'Pirated content hosting' },
                { pattern: /hack|exploit|vulnerability/i, score: 60, type: 'Hacking-related content' },
                { pattern: /anonymous|proxy|vpn|tor/i, score: 40, type: 'Anonymity services' },
                { pattern: /bulletproof|offshore|bullet.*proof/i, score: 70, type: 'Bulletproof hosting' }
            ],
            
            // Domain structure analysis (low-medium risk)
            domainStructure: [
                { pattern: /[0-9]{6,}/, score: 30, type: 'High numerical content' },
                { pattern: /[a-z]{1,2}[0-9]{4,}/, score: 35, type: 'Random character pattern' },
                { pattern: /.*-.*-.*-.*-.*/, score: 25, type: 'Excessive hyphens' }
            ]
        };
        
        let totalScore = 0;
        let detectedThreats = [];
        let riskFactors = [];
        
        // Analyze each threat category
        Object.entries(threatAnalysis).forEach(([category, patterns]) => {
            patterns.forEach(({ pattern, score, type }) => {
                if (pattern.test(fullUrl) || pattern.test(domain) || pattern.test(pathname)) {
                    totalScore += score;
                    detectedThreats.push(type);
                    
                    // Add risk factors based on category
                    if (category === 'malwareIndicators') {
                        riskFactors.push('Malware-related content detected');
                    } else if (category === 'cryptoMining') {
                        riskFactors.push('Cryptocurrency mining activity detected');
                    } else if (category === 'commandControl') {
                        riskFactors.push('Command and control infrastructure detected');
                    } else if (category === 'suspiciousHosting') {
                        riskFactors.push('Suspicious hosting environment detected');
                    }
                }
            });
        });
        
        // Additional advanced checks
        const advancedChecks = {
            // Check for suspicious file paths
            suspiciousPaths: checkSuspiciousPaths(pathname),
            
            // Check for encoded content
            encodedContent: checkEncodedContent(fullUrl),
            
            // Check for suspicious parameters
            suspiciousParams: checkSuspiciousParams(url),
            
            // Check for known malicious domains patterns
            maliciousPatterns: checkMaliciousPatterns(domain)
        };
        
        // Add scores from advanced checks
        Object.entries(advancedChecks).forEach(([check, result]) => {
            if (result.score > 0) {
                totalScore += result.score;
                detectedThreats.push(result.type);
                if (result.riskFactor) {
                    riskFactors.push(result.riskFactor);
                }
            }
        });
        
        // Calculate final threat level
        let threatLevel = 'low';
        let verdict = 'clean';
        
        if (totalScore >= 100) {
            threatLevel = 'critical';
            verdict = 'malicious';
        } else if (totalScore >= 70) {
            threatLevel = 'high';
            verdict = 'suspicious';
        } else if (totalScore >= 40) {
            threatLevel = 'medium';
            verdict = 'suspicious';
        }
        
        return {
            detected: totalScore >= 40,
            threatScore: Math.min(totalScore, 100),
            threatLevel: threatLevel,
            verdict: verdict,
            source: 'Enhanced Threat Heuristics',
            detectedThreats: detectedThreats,
            riskFactors: riskFactors,
            details: {
                method: 'enhanced_threat_analysis',
                total_patterns_checked: Object.values(threatAnalysis).flat().length + Object.keys(advancedChecks).length,
                score_breakdown: {
                    threat_patterns: totalScore - Object.values(advancedChecks).reduce((sum, check) => sum + (check.score || 0), 0),
                    advanced_checks: Object.values(advancedChecks).reduce((sum, check) => sum + (check.score || 0), 0)
                }
            }
        };
    }
    
    // Additional threat analysis functions
    function checkSuspiciousPaths(pathname) {
        const suspiciousPaths = [
            '/admin/', '/wp-admin/', '/administrator/', '/phpmyadmin/',
            '/cgi-bin/', '/scripts/', '/temp/', '/tmp/',
            '/uploads/', '/files/', '/download/', '/backup/'
        ];
        
        for (const path of suspiciousPaths) {
            if (pathname.includes(path)) {
                return {
                    score: 40,
                    type: 'Suspicious path detected',
                    riskFactor: 'URL contains paths commonly targeted by attackers'
                };
            }
        }
        
        return { score: 0 };
    }
    
    function checkEncodedContent(url) {
        const encodedPatterns = [
            /%[0-9a-f]{2}/i, // URL encoding
            /base64/i, // Base64 encoding
            /hex/i, // Hex encoding
            /unicode/i // Unicode encoding
        ];
        
        for (const pattern of encodedPatterns) {
            if (pattern.test(url)) {
                return {
                    score: 30,
                    type: 'Encoded content detected',
                    riskFactor: 'URL contains encoded content that may hide malicious intent'
                };
            }
        }
        
        return { score: 0 };
    }
    
    function checkSuspiciousParams(url) {
        const suspiciousParams = [
            'cmd', 'exec', 'eval', 'system', 'shell',
            'php', 'asp', 'jsp', 'cgi',
            'file', 'path', 'dir', 'include'
        ];
        
        try {
            const urlObj = new URL(url);
            const params = urlObj.searchParams;
            
            for (const [key, value] of params) {
                if (suspiciousParams.includes(key.toLowerCase()) || 
                    suspiciousParams.some(param => value.toLowerCase().includes(param))) {
        return {
                        score: 50,
                        type: 'Suspicious parameters detected',
                        riskFactor: 'URL contains parameters commonly used in attacks'
                    };
                }
            }
        } catch (e) {
            // Invalid URL, skip parameter check
        }
        
        return { score: 0 };
    }
    
    function checkMaliciousPatterns(domain) {
        const maliciousPatterns = [
            /.*malware.*/i,
            /.*virus.*/i,
            /.*trojan.*/i,
            /.*exploit.*/i,
            /.*hack.*/i,
            /.*crack.*/i,
            /.*keygen.*/i,
            /.*warez.*/i
        ];
        
        for (const pattern of maliciousPatterns) {
            if (pattern.test(domain)) {
                return {
                    score: 60,
                    type: 'Malicious domain pattern',
                    riskFactor: 'Domain name contains malicious keywords'
                };
            }
        }
        
        return { score: 0 };
    }
    
    // Google Safe Browsing API with safety heuristics
    async function checkGoogleSafeBrowsing(url) {
        try {
            // Try Google Safe Browsing API first
            if (!googleSafeBrowsingApiKey || googleSafeBrowsingApiKey === "YOUR_GOOGLE_SAFEBROWSING_API_KEY") {
                throw new Error('Google Safe Browsing API key not configured');
            }
            const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(googleSafeBrowsingApiKey)}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'SecurityExtension/1.0'
                },
                body: JSON.stringify({
                    client: {
                        clientId: "security-extension",
                        clientVersion: "1.0"
                    },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url: url }]
                    }
                })
            });
            
            if (response.ok) {
                const data = await response.json();
                return {
                    detected: data.matches && data.matches.length > 0,
                    threats: data.matches || [],
                    safe: !data.matches || data.matches.length === 0,
                    source: 'Google Safe Browsing API'
                };
            }
        } catch (error) {
            console.log('Google Safe Browsing API failed, using safety heuristics');
        }
        
        // Fallback to safety heuristics
        return checkSafetyHeuristics(url);
    }

    // Safety heuristics analysis
    function checkSafetyHeuristics(url) {
        const domain = new URL(url).hostname.toLowerCase();
        const fullUrl = url.toLowerCase();
        
        // Safety indicators
        const safetyPatterns = [
            // Known safe domains
            /google\.com|microsoft\.com|apple\.com|amazon\.com|facebook\.com|twitter\.com|linkedin\.com/i,
            // Educational institutions
            /\.edu$|\.ac\./i,
            // Government domains
            /\.gov$|\.mil$/i,
            // Major CDNs and trusted services
            /cloudflare|amazonaws|googleapis|microsoft\.com/i
        ];
        
        // Unsafe indicators
        const unsafePatterns = [
            // Suspicious domains
            /malware|virus|phish|scam|fake|fraud/i,
            // Adult content
            /adult|porn|xxx|sex/i,
            // Gambling
            /casino|gambling|bet|poker/i,
            // Potentially unwanted software
            /crack|keygen|warez|torrent/i
        ];
        
        const isKnownSafe = safetyPatterns.some(pattern => 
            pattern.test(domain) || pattern.test(fullUrl)
        );
        
        const hasUnsafeIndicators = unsafePatterns.some(pattern => 
            pattern.test(domain) || pattern.test(fullUrl)
        );
        
        // Check for HTTPS
        const isHttps = url.startsWith('https://');
        
        // Calculate safety score
        let safetyScore = 50; // Base score
        if (isKnownSafe) safetyScore += 40;
        if (isHttps) safetyScore += 20;
        if (hasUnsafeIndicators) safetyScore -= 60;
        
        const isDetected = safetyScore < 30;
        
        return {
            detected: isDetected,
            safe: !isDetected,
            threats: isDetected ? ['Heuristic Analysis'] : [],
            source: 'Safety Heuristics',
            details: {
                known_safe: isKnownSafe,
                unsafe_indicators: hasUnsafeIndicators,
                https_enabled: isHttps,
                safety_score: safetyScore
            }
        };
    }
    
    // Enhanced multi-API scan function with retry logic and better error handling
    async function performMultiApiScan(url) {
        const results = {
            virusTotal: null,
            phishTank: null,
            urlVoid: null,
            hybridAnalysis: null,
            googleSafeBrowsing: null,
            scanMetadata: {
                startTime: Date.now(),
                totalApis: 5,
                successfulApis: 0,
                failedApis: 0,
                scanDuration: 0
            }
        };
        
        // Enhanced API check functions with retry logic
        const apiChecks = [
            { name: 'virusTotal', fn: () => checkUrlWithVirusTotal(url), retries: 2 },
            { name: 'phishTank', fn: () => checkPhishTank(url), retries: 1 },
            { name: 'urlVoid', fn: () => checkUrlVoid(url), retries: 1 },
            { name: 'hybridAnalysis', fn: () => checkHybridAnalysis(url), retries: 1 },
            { name: 'googleSafeBrowsing', fn: () => checkGoogleSafeBrowsing(url), retries: 1 }
        ];
        
        // Run checks with timeout and retry logic
        const promises = apiChecks.map(async (apiCheck) => {
            let lastError = null;
            
            for (let attempt = 0; attempt <= apiCheck.retries; attempt++) {
                try {
                    // Track API call count for performance metrics
                    performanceMetrics.apiCallCount++;
                    
                    const result = await Promise.race([
                        apiCheck.fn(),
                        new Promise((_, reject) => 
                            setTimeout(() => reject(new Error('API timeout')), 8000)
                        )
                    ]);
                    
                    results[apiCheck.name] = {
                        ...result,
                        attempt: attempt + 1,
                        success: true,
                        timestamp: Date.now()
                    };
                    results.scanMetadata.successfulApis++;
                    return;
                } catch (error) {
                    lastError = error;
                    console.warn(`${apiCheck.name} attempt ${attempt + 1} failed:`, error.message);
                    
                    // Wait before retry (exponential backoff)
                    if (attempt < apiCheck.retries) {
                        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
                    }
                }
            }
            
            // All attempts failed
            results[apiCheck.name] = {
                error: lastError?.message || 'Unknown error',
                success: false,
                attempts: apiCheck.retries + 1,
                timestamp: Date.now()
            };
            results.scanMetadata.failedApis++;
        });
        
        try {
            await Promise.allSettled(promises);
            results.scanMetadata.scanDuration = Date.now() - results.scanMetadata.startTime;
            
            // Log scan summary
            console.log(`Multi-API scan completed: ${results.scanMetadata.successfulApis}/${results.scanMetadata.totalApis} APIs successful in ${results.scanMetadata.scanDuration}ms`);
            
            return results;
        } catch (error) {
            console.error("Multi-API scan error:", error);
            results.scanMetadata.scanDuration = Date.now() - results.scanMetadata.startTime;
            return results;
        }
    }
    
    // Scan control functions
    function startScan() {
        if (scanInProgress) return;
        
        scanInProgress = true;
        currentScanMode = document.querySelector('input[name="scan-mode"]:checked').value;
        
        // Initialize performance metrics
        performanceMetrics.scanStartTime = performance.now();
        performanceMetrics.apiCallCount = 0;
        performanceMetrics.memoryUsage = memoryManager.getMemoryUsage();
        
        // Add loading state to scan controls
        const scanControls = document.getElementById('scan-controls');
        scanControls.classList.add('loading');
        
        // Hide all UI except scanning animation
        scanControls.classList.add('hidden');
        document.getElementById('results').classList.add('hidden');
        document.getElementById('start-scan-btn').disabled = true;
        document.getElementById('stop-scan-btn').disabled = false;
        
        // Show only scanning UI
        scanningUi.classList.remove('hidden');
        
        // Announce scan start to screen readers
        announceToScreenReader(`Starting ${currentScanMode} security scan`);
        
        // Run analysis based on mode
        if (currentScanMode === 'realtime') {
            startRealtimeScanning();
        } else if (currentScanMode === 'quick') {
            runQuickScan();
        } else {
            runDeepScan();
        }
    }
    
    function stopScan() {
        scanInProgress = false;
        realtimeScanning = false;
        
        // Record performance metrics
        performanceMetrics.scanEndTime = performance.now();
        const scanDuration = performanceMetrics.scanEndTime - performanceMetrics.scanStartTime;
        
        // Log performance metrics
        console.log(`Scan Performance Metrics:
            Duration: ${scanDuration.toFixed(2)}ms
            API Calls: ${performanceMetrics.apiCallCount}
            Memory Usage: ${(performanceMetrics.memoryUsage / 1024).toFixed(2)}KB
            DOM Analysis: ${performanceMetrics.domAnalysisTime.toFixed(2)}ms
            Header Analysis: ${performanceMetrics.headerAnalysisTime.toFixed(2)}ms`);
        
        // Clear real-time interval
        if (realtimeInterval) {
            clearInterval(realtimeInterval);
            realtimeInterval = null;
        }
        
        // Hide real-time indicator
        document.getElementById('realtime-indicator').classList.add('hidden');
        
        // Remove loading state
        const scanControls = document.getElementById('scan-controls');
        scanControls.classList.remove('loading');
        
        // Show all UI elements again
        scanControls.classList.remove('hidden');
        document.getElementById('start-scan-btn').disabled = false;
        document.getElementById('stop-scan-btn').disabled = true;
        
        // Hide scanning UI
        scanningUi.classList.add('hidden');
        scanningProgress.innerText = 'Scan stopped by user';
        
        // Announce scan stop to screen readers
        announceToScreenReader('Security scan stopped');
        
        // Clean up memory
        optimizeMemoryUsage();
    }
    
    // Performance optimization functions
    function optimizeMemoryUsage() {
        // Clean up old analysis data
        if (Object.keys(currentAnalysisData).length > 0) {
            // Keep only essential data
            const essentialData = {
                url: currentAnalysisData.url,
                score: currentAnalysisData.assessment?.score || 0,
                timestamp: Date.now()
            };
            
            // Store in cache with URL as key
            memoryManager.set(currentAnalysisData.url, essentialData);
            
            // Clear large objects
            if (currentAnalysisData.domData) {
                currentAnalysisData.domData = null;
            }
            if (currentAnalysisData.headerData) {
                currentAnalysisData.headerData = null;
            }
            if (currentAnalysisData.multiApiResults) {
                currentAnalysisData.multiApiResults = null;
            }
        }
        
        // Force garbage collection if available
        if (window.gc) {
            window.gc();
        }
        
        // Update memory usage
        performanceMetrics.memoryUsage = memoryManager.getMemoryUsage();
    }
    
    // Debounced function for performance
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    // Throttled function for performance
    function throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
    
    // Optimized DOM analysis with performance monitoring
    async function performOptimizedDOMAnalysis(tabId) {
        const startTime = performance.now();
        
        try {
            await chrome.scripting.executeScript({
                target: { tabId: tabId },
                files: ['content.js']
            });
            
            const domResponse = await Promise.race([
                new Promise((resolve, reject) => {
                    chrome.tabs.sendMessage(tabId, { action: "analyzePage" }, response => {
                        if (chrome.runtime.lastError) {
                            reject(new Error(chrome.runtime.lastError.message));
                        } else if (!response) {
                            reject(new Error("No response from content script"));
                        } else {
                            resolve(response);
                        }
                    });
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error("DOM analysis timed out")), 10000))
            ]);
            
            performanceMetrics.domAnalysisTime = performance.now() - startTime;
            return domResponse;
            
        } catch (error) {
            performanceMetrics.domAnalysisTime = performance.now() - startTime;
            console.error("Optimized DOM analysis error:", error);
            throw error;
        }
    }
    
    // Optimized header analysis with performance monitoring
    async function performOptimizedHeaderAnalysis(tabId) {
        const startTime = performance.now();
        
        try {
            const headerResponse = await Promise.race([
                new Promise(resolve => {
                    chrome.runtime.sendMessage({ action: "getHeaders", tabId: tabId }, response => {
                        if (chrome.runtime.lastError) {
                            console.warn("Warning getting headers:", chrome.runtime.lastError.message);
                            resolve({});
                        } else {
                            resolve(response || {});
                        }
                    });
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Header request timed out")), 5000))
            ]);
            
            performanceMetrics.headerAnalysisTime = performance.now() - startTime;
            return headerResponse;
            
        } catch (error) {
            performanceMetrics.headerAnalysisTime = performance.now() - startTime;
            console.warn("Header analysis warning:", error);
            return {};
        }
    }

    // Screen reader announcement function
    function announceToScreenReader(message) {
        const announcement = document.createElement('div');
        announcement.setAttribute('aria-live', 'polite');
        announcement.setAttribute('aria-atomic', 'true');
        announcement.className = 'sr-only';
        announcement.textContent = message;
        
        document.body.appendChild(announcement);
        
        // Remove after announcement
        setTimeout(() => {
            document.body.removeChild(announcement);
        }, 1000);
    }
    
    async function runQuickScan() {
        try {
            scanningProgress.innerText = "Quick scan: Analyzing headers...";
            
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs.length === 0) throw new Error("No active tab found");
            
            const activeTab = tabs[0];
            const url = activeTab.url;
            
            if (!url || url.startsWith("chrome:") || url.startsWith("chrome-extension:") || url.startsWith("about:")) {
                throw new Error("Cannot analyze browser internal pages");
            }
            
            // Get headers only
            const headerResponse = await Promise.race([
                new Promise(resolve => {
                    chrome.runtime.sendMessage({ action: "getHeaders", tabId: activeTab.id }, response => {
                        if (chrome.runtime.lastError) {
                            resolve({});
                        } else {
                            resolve(response || {});
                        }
                    });
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Header request timed out")), 5000))
            ]).catch(() => ({}));
            
            // Create minimal DOM data for quick scan
            const quickDomData = {
                hasMixedContent: false,
                hasCSP: false,
                hasXFrameOptions: false,
                cookies: [],
                sensitiveAutocomplete: false,
                passwordInputTypeError: false,
                suspiciousExternalScripts: false,
                suspiciousDomains: [],
                malwareReputationIssues: [],
                cryptoMiningDetected: false,
                formCrossOriginAction: false,
                hasObfuscatedJS: false,
                totalRequests: 0,
                externalRequests: 0,
                hasLargeResources: false,
                missingSRIExternalScripts: 0,
                missingSRIExternalStyles: 0
            };
            
            currentAnalysisData = { domData: quickDomData, headerData: headerResponse, url: url };
            displayResults(quickDomData, headerResponse, url);
            
            scanningProgress.innerText = "Quick scan complete!";
            setTimeout(() => {
                scanningUi.classList.add('hidden');
                resultsDiv.classList.remove('hidden');
                document.getElementById('scan-controls').classList.remove('hidden');
                stopScan();
            }, 1000);
            
        } catch (error) {
            console.error("Quick scan error:", error);
            scanningUi.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
            renderResult('https-check', 'error-icon', `Error: ${error.message}`);
            stopScan();
        }
    }
    
    async function runDeepScan() {
        // Use the existing full analysis
        await runAnalysisAndReport();
        document.getElementById('scan-controls').classList.remove('hidden');
        stopScan();
    }
    
    async function startRealtimeScanning() {
        realtimeScanning = true;
        document.getElementById('realtime-indicator').classList.remove('hidden');
        
        scanningProgress.innerText = "Starting real-time monitoring...";
        
        // Initial scan
        await performRealtimeScan();
        
        // Set up continuous monitoring every 30 seconds
        realtimeInterval = setInterval(async () => {
            if (realtimeScanning) {
                await performRealtimeScan();
            }
        }, 30000);
    }
    
    async function performRealtimeScan() {
        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs.length === 0) return;
            
            const activeTab = tabs[0];
            const url = activeTab.url;
            
            if (!url || url.startsWith("chrome:") || url.startsWith("chrome-extension:") || url.startsWith("about:")) {
                scanningProgress.innerText = "Cannot monitor browser internal pages";
                return;
            }
            
            scanningProgress.innerText = `Real-time scan: ${new Date().toLocaleTimeString()}`;
            
            // Get headers
            const headerResponse = await Promise.race([
                new Promise(resolve => {
                    chrome.runtime.sendMessage({ action: "getHeaders", tabId: activeTab.id }, response => {
                        resolve(response || {});
                    });
                }),
                new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000))
            ]).catch(() => ({}));
            
            // Check with multiple APIs
            scanningProgress.innerText = `Checking with multiple antivirus engines...`;
            const multiApiResults = await performMultiApiScan(url);
            
            // Execute content script for DOM analysis
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: activeTab.id },
                    files: ['content.js']
                });
                
                const domResponse = await Promise.race([
                    new Promise((resolve) => {
                        chrome.tabs.sendMessage(activeTab.id, { action: "analyzePage" }, response => {
                            resolve(response || {});
                        });
                    }),
                    new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 10000))
                ]).catch(() => ({}));
                
                // Update analysis data
                currentAnalysisData = { 
                    domData: domResponse, 
                    headerData: headerResponse, 
                    url: url,
                    multiApiResults: multiApiResults,
                    lastScan: new Date().toISOString()
                };
                
                // Update malware detection with multi-API results
                const detectedEngines = [];
                if (multiApiResults.virusTotal?.detected) {
                    detectedEngines.push(`VirusTotal: ${multiApiResults.virusTotal.positives}/${multiApiResults.virusTotal.total}`);
                }
                if (multiApiResults.phishTank?.detected) {
                    detectedEngines.push('PhishTank: Phishing detected');
                }
                if (multiApiResults.urlVoid?.detected) {
                    detectedEngines.push(`URLVoid: ${multiApiResults.urlVoid.engines.length} engines`);
                }
                if (multiApiResults.hybridAnalysis?.detected) {
                    detectedEngines.push(`Hybrid Analysis: ${multiApiResults.hybridAnalysis.verdict}`);
                }
                if (multiApiResults.googleSafeBrowsing?.detected) {
                    detectedEngines.push('Google Safe Browsing: Threats detected');
                }
                
                if (detectedEngines.length > 0) {
                    domResponse.malwareReputationIssues = domResponse.malwareReputationIssues || [];
                    domResponse.malwareReputationIssues.push(`Multi-Engine Detection: ${detectedEngines.join(', ')}`);
                }
                
                // Show results if not already shown
                if (resultsDiv.classList.contains('hidden')) {
                    displayResults(domResponse, headerResponse, url);
                    scanningUi.classList.add('hidden');
                    resultsDiv.classList.remove('hidden');
                    document.getElementById('scan-controls').classList.remove('hidden');
                } else {
                    // Update existing results
                    displayResults(domResponse, headerResponse, url);
                }
                
            } catch (error) {
                console.error("Real-time scan error:", error);
                scanningProgress.innerText = `Scan error: ${error.message}`;
            }
            
        } catch (error) {
            console.error("Real-time monitoring error:", error);
            scanningProgress.innerText = `Monitoring error: ${error.message}`;
        }
    }
    
    // Enhanced scan controls with keyboard support
    const startScanBtn = document.getElementById('start-scan-btn');
    const stopScanBtn = document.getElementById('stop-scan-btn');
    
    if (startScanBtn) {
        startScanBtn.addEventListener('click', startScan);
        startScanBtn.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                startScan();
            }
        });
    }
    
    if (stopScanBtn) {
        stopScanBtn.addEventListener('click', stopScan);
        stopScanBtn.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                stopScan();
            }
        });
    }

    // Add keyboard navigation for scan modes
    document.querySelectorAll('input[name="scan-mode"]').forEach((radio, index) => {
        radio.addEventListener('keydown', (e) => {
            const radios = document.querySelectorAll('input[name="scan-mode"]');
            let newIndex = index;
            
            if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
                e.preventDefault();
                newIndex = (index + 1) % radios.length;
            } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
                e.preventDefault();
                newIndex = (index - 1 + radios.length) % radios.length;
            }
            
            if (newIndex !== index) {
                radios[newIndex].focus();
                radios[newIndex].checked = true;
                currentScanMode = radios[newIndex].value;
            }
        });
    });
    
    // Update scan mode when radio buttons change
    document.querySelectorAll('input[name="scan-mode"]').forEach(radio => {
        radio.addEventListener('change', () => {
            currentScanMode = radio.value;
        });
    });

    // Wire up Download button
    const downloadBtn = document.getElementById('download-report-btn');
    if (downloadBtn) {
        downloadBtn.disabled = true;
        downloadBtn.addEventListener('click', async () => {
            try {
                await generatePdfReport();
            } catch (e) {
                console.error('PDF generation failed:', e);
            }
        });
    }
    
    // Wire up VirusTotal link button
    const virusTotalBtn = document.getElementById('view-virustotal-btn');
    if (virusTotalBtn) {
        virusTotalBtn.addEventListener('click', () => {
            const virusTotalData = currentAnalysisData.virusTotal;
            if (virusTotalData && virusTotalData.permalink) {
                chrome.tabs.create({ url: virusTotalData.permalink });
            } else {
                // Fallback: open VirusTotal homepage
                chrome.tabs.create({ url: 'https://www.virustotal.com/' });
            }
        });
    }
});