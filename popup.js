// Website Security Scanner v2.0 - Enhanced Popup Logic
// Comprehensive security analysis with scoring, privacy evaluation, and advanced reporting

let currentTab = null;
let scanResults = {};
let geminiApiKey = '';
let darkMode = false;
let monitoringEnabled = false;
let statsRefreshInterval = null;

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Load saved settings
        const settings = await chrome.storage.local.get(['geminiApiKey', 'settings', 'scanHistory']);

        if (settings.geminiApiKey) {
            geminiApiKey = settings.geminiApiKey;
            if (document.getElementById('apiKey')) {
                document.getElementById('apiKey').value = geminiApiKey;
            }
        }

        // Load dark mode preference
        if (settings.settings?.darkMode) {
            darkMode = settings.settings.darkMode;
            applyDarkMode(darkMode);
        }

        // Get current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        currentTab = tab;
        document.getElementById('currentUrl').textContent = `Scanning: ${tab.url}`;

        // Event listeners
        setupEventListeners();

        // Load scan history preview
        if (settings.scanHistory && settings.scanHistory.length > 0) {
            updateHistoryPreview(settings.scanHistory.slice(0, 3));
        }

    } catch (error) {
        console.error('Initialization error:', error);
    }
});

function setupEventListeners() {
    const apiKeyInput = document.getElementById('apiKey');
    if (apiKeyInput) {
        apiKeyInput.addEventListener('change', saveApiKey);
    }

    document.getElementById('selectAllBtn').addEventListener('click', toggleSelectAll);
    document.getElementById('startScanBtn').addEventListener('click', startScan);

    const darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', toggleDarkMode);
    }

    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', showExportOptions);
    }

    const historyBtn = document.getElementById('historyBtn');
    if (historyBtn) {
        historyBtn.addEventListener('click', showScanHistory);
    }

    const monitoringToggle = document.getElementById('monitoringToggle');
    if (monitoringToggle) {
        monitoringToggle.addEventListener('change', toggleMonitoring);
    }

    // Listen for suspicious domain alerts from background
    chrome.runtime.onMessage.addListener((message) => {
        if (message.action === 'suspiciousDomainAlert') {
            showSuspiciousAlert(message.domain, message.reason, message.severity);
        }
    });
}

async function saveApiKey(e) {
    geminiApiKey = e.target.value.trim();
    await chrome.storage.local.set({ geminiApiKey });
}

function toggleSelectAll() {
    const checkboxes = document.querySelectorAll('.checkbox-item input[type="checkbox"]');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    checkboxes.forEach(cb => cb.checked = !allChecked);
    document.getElementById('selectAllBtn').textContent = allChecked ? 'Select All' : 'Deselect All';
}

function toggleDarkMode() {
    darkMode = !darkMode;
    applyDarkMode(darkMode);
    chrome.storage.local.get(['settings'], (result) => {
        const settings = result.settings || {};
        settings.darkMode = darkMode;
        chrome.storage.local.set({ settings });
    });
}

function applyDarkMode(enabled) {
    if (enabled) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
}

// Enhanced Scanning Logic
async function startScan() {
    const checks = {
        traffic: document.getElementById('check-traffic').checked,
        malware: document.getElementById('check-malware').checked,
        https: document.getElementById('check-https').checked,
        security: document.getElementById('check-security').checked,
        cookies: document.getElementById('check-cookies')?.checked || true,
        mixedContent: document.getElementById('check-mixed')?.checked || true,
        privacy: document.getElementById('check-privacy')?.checked || true,
        phishing: document.getElementById('check-phishing')?.checked || true,
        javascript: document.getElementById('check-javascript')?.checked || true
    };

    if (!Object.values(checks).some(v => v)) {
        alert('Please select at least one security check');
        return;
    }

    // UI Reset
    scanResults = {
        url: currentTab.url,
        timestamp: new Date().toISOString(),
        checks: [],
        scores: {}
    };

    document.getElementById('resultsSection').classList.remove('active');
    document.getElementById('progressSection').classList.add('active');
    document.getElementById('startScanBtn').disabled = true;
    document.getElementById('scanBtnText').innerHTML = '<span class="loading-spinner"></span> Scanning...';

    try {
        let progress = 0;
        const activeChecks = Object.values(checks).filter(v => v).length;
        const increment = 100 / activeChecks;

        // Execute checks sequentially
        if (checks.phishing) await runCheck('Phishing Detection', performPhishingCheck, increment, progress);
        if (checks.malware) await runCheck('Malware Scan', performMalwareDetection, increment, progress += increment);
        if (checks.https) await runCheck('HTTPS Verification', performHttpsVerification, increment, progress += increment);
        if (checks.security) await runCheck('Security Headers', performSecurityHeadersAnalysis, increment, progress += increment);
        if (checks.cookies) await runCheck('Cookie Security', performCookieAnalysis, increment, progress += increment);
        if (checks.mixedContent) await runCheck('Mixed Content Check', performMixedContentCheck, increment, progress += increment);
        if (checks.traffic) await runCheck('Traffic Analysis', performTrafficAnalysis, increment, progress += increment);
        if (checks.privacy) await runCheck('Privacy Analysis', performPrivacyAnalysis, increment, progress += increment);
        if (checks.javascript) await runCheck('JavaScript Security', performJavaScriptSecurityCheck, increment, progress += increment);

        updateProgress(100, 'Calculating scores...');

        // Calculate overall scores
        calculateScores();

        // Save to history
        await chrome.runtime.sendMessage({
            action: 'saveScanResult',
            scanData: scanResults
        });

        // Increment scan count
        await chrome.runtime.sendMessage({ action: 'incrementScanCount' });

        updateProgress(100, 'Scan complete!');

        setTimeout(() => {
            displayResults();
            document.getElementById('progressSection').classList.remove('active');
            document.getElementById('resultsSection').classList.add('active');
            document.getElementById('startScanBtn').disabled = false;
            document.getElementById('scanBtnText').textContent = 'Start Security Scan';
        }, 500);

    } catch (error) {
        console.error('Scan failed:', error);
        alert(`Scan failed: ${error.message}`);
        document.getElementById('startScanBtn').disabled = false;
        document.getElementById('scanBtnText').textContent = 'Start Security Scan';
        document.getElementById('progressSection').classList.remove('active');
    }
}

async function runCheck(name, checkFn, increment, currentProgress) {
    updateProgress(currentProgress, `Running ${name}...`);
    try {
        await checkFn();
    } catch (e) {
        console.error(`${name} failed:`, e);
        scanResults.checks.push({
            category: name,
            severity: 'error',
            details: `Check failed: ${e.message}`
        });
    }
}

function updateProgress(percent, text) {
    document.getElementById('progressBar').style.width = `${percent}%`;
    document.getElementById('progressText').textContent = text;
}

// Individual Check Implementations

async function performPhishingCheck() {
    const response = await chrome.runtime.sendMessage({
        action: 'checkPhishing',
        url: currentTab.url
    });

    scanResults.checks.push({
        category: 'Phishing Detection',
        severity: response.isPhishing ? 'critical' : 'success',
        details: response.isPhishing ?
            `⚠️ PHISHING RISK DETECTED! Risk Score: ${response.riskScore}/100. Indicators: ${response.indicators.join(', ')}` :
            `No phishing indicators detected. Risk Score: ${response.riskScore}/100`,
        data: response
    });
}

async function performMalwareDetection() {
    const response = await chrome.runtime.sendMessage({
        action: 'checkMalwareDomain',
        url: currentTab.url
    });

    scanResults.checks.push({
        category: 'Malware Detection',
        severity: response.isMalware ? 'critical' : 'success',
        details: response.isMalware ?
            `⚠️ MALWARE DETECTED! Domain ${response.domain} is in blocklist.` :
            'No known malware domains detected.',
        data: response
    });
}

async function performHttpsVerification() {
    const isSecure = currentTab.url.startsWith('https');
    const hasValidCert = isSecure; // In real implementation, check cert validity

    scanResults.checks.push({
        category: 'HTTPS & SSL',
        severity: isSecure ? 'success' : 'critical',
        details: isSecure ?
            '✓ Connection is secure (HTTPS).' :
            '⚠️ Connection is NOT secure (HTTP). Data is vulnerable.',
        data: { isSecure, hasValidCert }
    });
}

async function performSecurityHeadersAnalysis() {
    const response = await chrome.runtime.sendMessage({
        action: 'analyzeSecurityHeaders',
        url: currentTab.url
    });

    const missing = response.missing || [];
    const warnings = response.warnings || [];
    const score = response.score || 0;

    let severity = 'success';
    if (missing.length > 3 || warnings.length > 0) severity = 'warning';
    if (missing.length > 5) severity = 'critical';

    const details = [];
    if (missing.length > 0) {
        details.push(`Missing ${missing.length} security headers: ${missing.slice(0, 3).map(h => h.name).join(', ')}${missing.length > 3 ? '...' : ''}`);
    }
    if (warnings.length > 0) {
        details.push(`${warnings.length} warning(s) found`);
    }
    if (missing.length === 0 && warnings.length === 0) {
        details.push('All key security headers are properly configured');
    }

    scanResults.checks.push({
        category: 'Security Headers',
        severity: severity,
        details: details.join('. '),
        data: response
    });
}

async function performCookieAnalysis() {
    const response = await chrome.runtime.sendMessage({
        action: 'checkCookieSecurity',
        url: currentTab.url
    });

    const insecure = response.insecure || 0;
    const total = response.total || 0;

    let severity = 'success';
    if (insecure > 0 && insecure < total / 2) severity = 'warning';
    if (insecure >= total / 2) severity = 'critical';

    scanResults.checks.push({
        category: 'Cookie Security',
        severity: severity,
        details: total === 0 ?
            'No cookies detected' :
            `${total} cookies found. ${insecure} insecure (${response.score}% secure)`,
        data: response
    });
}

async function performMixedContentCheck() {
    const result = await executeScript(detectMixedContent);
    const data = result || { hasMixedContent: false, count: 0 };

    scanResults.checks.push({
        category: 'Mixed Content',
        severity: data.hasMixedContent ? (data.severity === 'high' ? 'critical' : 'warning') : 'success',
        details: data.hasMixedContent ?
            `⚠️ ${data.count} insecure resources found on HTTPS page` :
            'No mixed content detected',
        data: data
    });
}

async function performTrafficAnalysis() {
    const result = await executeScript(analyzeTraffic);
    const data = result || { requestCount: 0, totalBytes: 0, breakdown: {} };

    const severity = data.requestCount > 100 ? 'warning' : data.requestCount > 50 ? 'info' : 'success';

    scanResults.checks.push({
        category: 'Traffic Analysis',
        severity: severity,
        details: `${data.requestCount} requests, ${(data.totalBytes / 1024).toFixed(2)} KB transferred`,
        data: data
    });
}

async function performPrivacyAnalysis() {
    const trafficData = await executeScript(analyzeTraffic);
    const thirdPartyData = await executeScript(getThirdPartyResources);
    const fingerprintData = await executeScript(detectFingerprinting);

    const resources = trafficData?.resources || [];
    const response = await chrome.runtime.sendMessage({
        action: 'detectTrackers',
        resources: resources
    });

    const trackerCount = response.totalTrackers || 0;
    const fingerprintCount = fingerprintData?.count || 0;
    const thirdPartyCount = thirdPartyData?.uniqueDomains || 0;

    let severity = 'success';
    if (trackerCount > 5 || fingerprintCount > 2) severity = 'warning';
    if (trackerCount > 10 || fingerprintCount > 3) severity = 'critical';

    scanResults.checks.push({
        category: 'Privacy Analysis',
        severity: severity,
        details: `${trackerCount} trackers, ${fingerprintCount} fingerprinting attempts, ${thirdPartyCount} third-party domains`,
        data: {
            trackers: response,
            fingerprinting: fingerprintData,
            thirdParty: thirdPartyData,
            privacyScore: response.privacyScore
        }
    });
}

async function performJavaScriptSecurityCheck() {
    const result = await executeScript(detectDangerousJavaScript);
    const data = result || { detected: false, totalIssues: 0, riskLevel: 'low', patterns: {}, issues: [] };

    let severity = 'success';
    if (data.riskLevel === 'critical') severity = 'critical';
    else if (data.riskLevel === 'high') severity = 'critical';
    else if (data.riskLevel === 'medium') severity = 'warning';
    else if (data.detected) severity = 'info';

    const details = [];
    if (data.patterns.cryptoMining > 0) {
        details.push(`⚠️ CRYPTO-MINING DETECTED (${data.patterns.cryptoMining} script(s))`);
    }
    if (data.patterns.evalUsage > 0) {
        details.push(`${data.patterns.evalUsage} eval() or similar usage`);
    }
    if (data.patterns.obfuscated > 0) {
        details.push(`${data.patterns.obfuscated} obfuscated script(s)`);
    }
    if (data.patterns.inlineScripts > 0) {
        details.push(`${data.patterns.inlineScripts} inline script(s)`);
    }
    if (data.patterns.documentWrite > 0) {
        details.push(`${data.patterns.documentWrite} document.write() usage`);
    }
    if (data.patterns.inlineHandlers > 0) {
        details.push(`${data.patterns.inlineHandlers} inline event handler(s)`);
    }

    const detailsText = details.length > 0 ? details.join(', ') : 'No dangerous JavaScript patterns detected';

    scanResults.checks.push({
        category: 'JavaScript Security',
        severity: severity,
        details: `${data.totalIssues} issue(s) found. ${detailsText}`,
        data: data
    });
}

// Helper function to detect dangerous JavaScript (injected into page)
function detectDangerousJavaScript() {
    const issues = [];
    const patterns = {
        inlineScripts: 0,
        evalUsage: 0,
        documentWrite: 0,
        obfuscated: 0,
        cryptoMining: 0,
        inlineHandlers: 0
    };

    // Count inline scripts
    const inlineScripts = document.querySelectorAll('script:not([src])');
    patterns.inlineScripts = inlineScripts.length;

    // Count inline handlers
    const inlineHandlers = document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover], [onfocus]');
    patterns.inlineHandlers = inlineHandlers.length;

    // Analyze scripts
    const allScripts = document.querySelectorAll('script');
    allScripts.forEach((script) => {
        const scriptContent = script.textContent || script.innerText || '';
        if (scriptContent.length === 0) return;

        if (/\beval\s*\(/.test(scriptContent)) patterns.evalUsage++;
        if (/document\.write/.test(scriptContent)) patterns.documentWrite++;
        if (/coinhive|cryptoloot|webminer|monero/i.test(scriptContent)) patterns.cryptoMining++;

        // Simple obfuscation check
        const hasHexEscape = (scriptContent.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 20;
        const hasBase64 = /[A-Za-z0-9+/]{50,}={0,2}/.test(scriptContent);
        if (hasHexEscape || hasBase64) patterns.obfuscated++;
    });

    const totalIssues = Object.values(patterns).reduce((a, b) => a + b, 0);
    let riskLevel = 'low';
    if (patterns.cryptoMining > 0) riskLevel = 'critical';
    else if (patterns.evalUsage > 2 || patterns.obfuscated > 2) riskLevel = 'high';
    else if (totalIssues > 10) riskLevel = 'medium';

    return {
        detected: totalIssues > 0,
        riskLevel: riskLevel,
        totalIssues: totalIssues,
        patterns: patterns,
        issues: issues
    };
}

// Helper to run content script functions
async function executeScript(func) {
    const result = await chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        func: func
    });
    return result[0]?.result;
}

// Content Script Functions (injected)
function analyzeTraffic() {
    const resources = performance.getEntriesByType('resource');
    const breakdown = {
        script: 0,
        stylesheet: 0,
        img: 0,
        xmlhttprequest: 0,
        fetch: 0,
        other: 0
    };

    let totalBytes = 0;

    resources.forEach(resource => {
        const type = resource.initiatorType || 'other';
        if (breakdown.hasOwnProperty(type)) {
            breakdown[type]++;
        } else {
            breakdown.other++;
        }
        totalBytes += resource.transferSize || 0;
    });

    return {
        requestCount: resources.length,
        totalBytes: totalBytes,
        breakdown: breakdown,
        resources: resources.map(r => ({
            url: r.name,
            type: r.initiatorType,
            size: r.transferSize
        }))
    };
}

function getThirdPartyResources() {
    const currentDomain = window.location.hostname;
    const resources = performance.getEntriesByType('resource');
    const domains = new Set();

    resources.forEach(resource => {
        try {
            const url = new URL(resource.name);
            if (url.hostname !== currentDomain) {
                domains.add(url.hostname);
            }
        } catch (e) { }
    });

    return {
        uniqueDomains: domains.size,
        domains: Array.from(domains)
    };
}

function detectFingerprinting() {
    const indicators = [];
    const canvasElements = document.querySelectorAll('canvas');
    if (canvasElements.length > 0) {
        indicators.push({ type: 'canvas', count: canvasElements.length });
    }
    return {
        detected: indicators.length > 0,
        count: indicators.length,
        indicators: indicators
    };
}

function detectMixedContent() {
    if (window.location.protocol !== 'https:') {
        return { hasMixedContent: false, reason: 'Page is not HTTPS', count: 0 };
    }

    const mixedResources = [];

    document.querySelectorAll('img[src], script[src], link[rel="stylesheet"], iframe[src]').forEach(el => {
        const src = el.src || el.href;
        if (src && src.startsWith('http:')) {
            mixedResources.push({
                type: el.tagName.toLowerCase(),
                url: src,
                severity: (el.tagName === 'SCRIPT' || el.tagName === 'IFRAME') ? 'high' : 'medium'
            });
        }
    });

    return {
        hasMixedContent: mixedResources.length > 0,
        count: mixedResources.length,
        mixedResources: mixedResources,
        severity: mixedResources.some(r => r.severity === 'high') ? 'high' : 'medium'
    };
}

// Score Calculation
function calculateScores() {
    let securityScore = 100;
    let privacyScore = 100;

    scanResults.checks.forEach(check => {
        if (check.severity === 'critical') {
            securityScore -= 20;
            if (check.category.includes('Privacy')) privacyScore -= 25;
        } else if (check.severity === 'warning') {
            securityScore -= 10;
            if (check.category.includes('Privacy')) privacyScore -= 15;
        } else if (check.severity === 'info') {
            securityScore -= 5;
        }
    });

    // Privacy-specific adjustments
    const privacyCheck = scanResults.checks.find(c => c.category === 'Privacy Analysis');
    if (privacyCheck && privacyCheck.data) {
        privacyScore = privacyCheck.data.privacyScore || privacyScore;
    }

    scanResults.scores = {
        security: Math.max(0, securityScore),
        privacy: Math.max(0, privacyScore),
        overall: Math.max(0, Math.round((securityScore + privacyScore) / 2))
    };
}

// Results Display
function displayResults() {
    const container = document.getElementById('resultsContent');
    container.innerHTML = '';

    // Display Security Score
    const scoreCard = createScoreCard();
    container.appendChild(scoreCard);

    // Display individual checks
    scanResults.checks.forEach(check => {
        const div = document.createElement('div');
        div.className = `result-item ${check.severity}`;

        const suggestions = generateSuggestions(check);

        div.innerHTML = `
      <div class="result-header">
        <strong>${check.category}</strong>
        <span class="badge ${check.severity}">${check.severity.toUpperCase()}</span>
      </div>
      <p>${check.details}</p>
      ${suggestions ? `<div class="suggestions">💡 ${suggestions}</div>` : ''}
    `;
        container.appendChild(div);
    });
}

function createScoreCard() {
    const div = document.createElement('div');
    div.className = 'score-card';

    const securityGrade = getGrade(scanResults.scores.security);
    const privacyGrade = getGrade(scanResults.scores.privacy);
    const overallGrade = getGrade(scanResults.scores.overall);

    div.innerHTML = `
    <h3>Security Assessment</h3>
    <div class="score-grid">
      <div class="score-item">
        <div class="score-label">Overall</div>
        <div class="score-value grade-${overallGrade.toLowerCase()}">${overallGrade}</div>
        <div class="score-number">${scanResults.scores.overall}/100</div>
      </div>
      <div class="score-item">
        <div class="score-label">Security</div>
        <div class="score-value grade-${securityGrade.toLowerCase()}">${securityGrade}</div>
        <div class="score-number">${scanResults.scores.security}/100</div>
      </div>
      <div class="score-item">
        <div class="score-label">Privacy</div>
        <div class="score-value grade-${privacyGrade.toLowerCase()}">${privacyGrade}</div>
        <div class="score-number">${scanResults.scores.privacy}/100</div>
      </div>
    </div>
  `;

    return div;
}

function getGrade(score) {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
}

function generateSuggestions(check) {
    if (check.severity === 'success') return '';

    const suggestions = {
        'Phishing Detection': 'Verify the URL carefully. Look for misspellings or unusual characters.',
        'Malware Detection': 'Leave this site immediately and run a virus scan.',
        'HTTPS & SSL': 'Only enter sensitive information on HTTPS sites.',
        'Security Headers': 'Contact the website administrator to configure proper security headers.',
        'Cookie Security': 'Clear insecure cookies or use incognito mode.',
        'Mixed Content': 'The site should serve all resources over HTTPS.',
        'Privacy Analysis': 'Consider using privacy-focused browser extensions or VPN.',
        'Traffic Analysis': 'High resource count may indicate tracking or poor optimization.',
        'JavaScript Security': 'Dangerous JavaScript patterns detected. Avoid entering sensitive data. Consider using a script blocker.'
    };

    return suggestions[check.category] || 'Review security settings.';
}

// Real-Time Monitoring Functions

async function toggleMonitoring() {
    const toggle = document.getElementById('monitoringToggle');
    monitoringEnabled = toggle.checked;

    if (monitoringEnabled) {
        // Start monitoring
        const response = await chrome.runtime.sendMessage({
            action: 'startMonitoring',
            tabId: currentTab.id
        });

        if (response.success) {
            document.getElementById('monitoringStats').style.display = 'grid';
            document.getElementById('monitoringIndicator').textContent = '🟢';
            document.getElementById('monitoringIndicator').classList.add('monitoring-active');

            // Start auto-refresh
            startStatsRefresh();
        } else {
            alert('Failed to start monitoring: ' + response.error);
            toggle.checked = false;
        }
    } else {
        // Stop monitoring
        const response = await chrome.runtime.sendMessage({
            action: 'stopMonitoring'
        });

        document.getElementById('monitoringStats').style.display = 'none';
        document.getElementById('monitoringIndicator').textContent = '🔴';
        document.getElementById('monitoringIndicator').classList.remove('monitoring-active');
        document.getElementById('alertContainer').innerHTML = '';

        // Stop auto-refresh
        stopStatsRefresh();
    }
}

function startStatsRefresh() {
    // Update stats every second
    statsRefreshInterval = setInterval(updateMonitoringStats, 1000);
    updateMonitoringStats(); // Initial update
}

function stopStatsRefresh() {
    if (statsRefreshInterval) {
        clearInterval(statsRefreshInterval);
        statsRefreshInterval = null;
    }
}

async function updateMonitoringStats() {
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'getMonitoringStats'
        });

        if (response.enabled && response.stats) {
            const stats = response.stats;

            // Update request count
            document.getElementById('requestCount').textContent = stats.totalRequests;

            // Update blocked count
            document.getElementById('blockedCount').textContent =
                `${stats.blockedRequests} (${stats.blockedPercentage}%)`;

            // Update data flow
            const dataKB = (stats.bytesReceived / 1024).toFixed(1);
            const dataMB = (stats.bytesReceived / 1024 / 1024).toFixed(2);
            document.getElementById('dataFlow').textContent =
                stats.bytesReceived > 1024 * 1024 ? `${dataMB} MB` : `${dataKB} KB`;
        }
    } catch (error) {
        console.error('Error updating monitoring stats:', error);
    }
}

function showSuspiciousAlert(domain, reason, severity) {
    const alertContainer = document.getElementById('alertContainer');

    // Check if alert for this domain already exists
    if (alertContainer.querySelector(`[data-domain="${domain}"]`)) {
        return;
    }

    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-item ${severity}`;
    alertDiv.setAttribute('data-domain', domain);
    alertDiv.innerHTML = `
        <strong>${severity === 'critical' ? '🚨' : '⚠️'} ${domain}</strong>
        ${reason}
    `;

    alertContainer.insertBefore(alertDiv, alertContainer.firstChild);

    // Keep only last 5 alerts
    while (alertContainer.children.length > 5) {
        alertContainer.removeChild(alertContainer.lastChild);
    }
}

// Export Functions
async function showExportOptions() {
    const format = prompt('Export format:\n1. JSON\n2. CSV\n3. HTML\n\nEnter 1, 2, or 3:');

    if (format === '1') {
        exportJSON();
    } else if (format === '2') {
        exportCSV();
    } else if (format === '3') {
        exportHTML();
    }
}

function exportJSON() {
    const dataStr = JSON.stringify(scanResults, null, 2);
    downloadFile(dataStr, 'security-scan.json', 'application/json');
}

function exportCSV() {
    let csv = 'Category,Severity,Details\n';
    scanResults.checks.forEach(check => {
        csv += `"${check.category}","${check.severity}","${check.details}"\n`;
    });
    downloadFile(csv, 'security-scan.csv', 'text/csv');
}

function exportHTML() {
    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Security Scan Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { color: #667eea; }
    .score { font-size: 48px; font-weight: bold; }
    .check { margin: 15px 0; padding: 10px; border-left: 4px solid #ccc; }
    .critical { border-color: #e53e3e; background: #fff5f5; }
    .warning { border-color: #f59e0b; background: #fffbeb; }
    .success { border-color: #10b981; background: #f0fdf4; }
  </style>
</head>
<body>
  <h1>Security Scan Report</h1>
  <p><strong>URL:</strong> ${scanResults.url}</p>
  <p><strong>Date:</strong> ${new Date(scanResults.timestamp).toLocaleString()}</p>
  <p><strong>Overall Score:</strong> <span class="score">${scanResults.scores.overall}/100 (${getGrade(scanResults.scores.overall)})</span></p>
  <h2>Scan Results</h2>
  ${scanResults.checks.map(check => `
    <div class="check ${check.severity}">
      <h3>${check.category} [${check.severity.toUpperCase()}]</h3>
      <p>${check.details}</p>
    </div>
  `).join('')}
</body>
</html>
  `;
    downloadFile(html, 'security-scan.html', 'text/html');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Scan History
async function showScanHistory() {
    const response = await chrome.runtime.sendMessage({
        action: 'getScanHistory',
        limit: 10
    });

    const history = response.history || [];

    if (history.length === 0) {
        alert('No scan history available');
        return;
    }

    let historyHTML = '<h3>Recent Scans</h3>';
    history.forEach((scan, index) => {
        const date = new Date(scan.timestamp).toLocaleString();
        const grade = getGrade(scan.scores?.overall || 0);
        historyHTML += `
      <div class="history-item">
        <strong>${index + 1}. ${scan.url}</strong><br>
        <small>${date} - Grade: ${grade}</small>
      </div>
    `;
    });

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
    <div class="modal-content">
      ${historyHTML}
      <button onclick="this.parentElement.parentElement.remove()">Close</button>
    </div>
  `;
    document.body.appendChild(modal);
}

function updateHistoryPreview(history) {
    const preview = document.getElementById('historyPreview');
    if (!preview) return;

    preview.innerHTML = `Last scan: ${new Date(history[0].timestamp).toLocaleString()}`;
}

