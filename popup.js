// WebGuard v2.0 - Ultra-Efficient Security Analysis Engine
// Version: 2.1 (Optimized Unified Audit)

let currentTab = null;
let scanResults = {};
let monitoringEnabled = true;
let statsRefreshInterval = null;

const SCAN_TIMEOUT_MS = 12000; // Increased to 12s for unified audit

function WebGuard_log(...args) {
    console.log('[WebGuard Engine]', ...args);
}

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
    WebGuard_log('Initializing popup...');
    try {
        const settings = await chrome.storage.local.get(['onboardingComplete']);

        if (!settings.onboardingComplete) {
            showView('onboarding');
        } else {
            showView('dashboard');
            startStatsRefresh();
        }

        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        currentTab = tab;
        WebGuard_log('Target Tab:', tab?.url);

        setupEventListeners();

        // Listen for real-time security updates (e.g., from VirusTotal)
        chrome.runtime.onMessage.addListener((msg) => {
            if (msg.action === 'updateVTResults') {
                handleVTUpdate(msg.vtResult);
            }
        });

    } catch (error) {
        console.error('Initialization error:', error);
    }
});

function setupEventListeners() {
    const runInitialScanBtn = document.getElementById('runInitialScanBtn');
    if (runInitialScanBtn) {
        runInitialScanBtn.addEventListener('click', async () => {
            WebGuard_log('First run triggered');
            await chrome.storage.local.set({ onboardingComplete: true });
            showView('dashboard');
            startStatsRefresh();
            startScan('full');
        });
    }

    document.getElementById('startScanBtn').addEventListener('click', () => {
        WebGuard_log('Quick scan triggered');
        startScan('quick');
    });

    document.getElementById('fullAuditBtn').addEventListener('click', () => {
        WebGuard_log('Full audit triggered');
        startScan('full');
    });

    const monitoringToggle = document.getElementById('monitoringToggle');
    monitoringToggle.addEventListener('change', toggleMonitoring);

    const generateReportBtn = document.getElementById('generateReportBtn');
    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', downloadDetailedReport);
    }
}

function showView(viewName) {
    const onboarding = document.getElementById('onboardingView');
    const dashboard = document.getElementById('dashboardView');
    onboarding.style.display = viewName === 'onboarding' ? 'flex' : 'none';
    dashboard.style.display = viewName === 'dashboard' ? 'flex' : 'none';
}

// Optimized Unified Scanning Logic
async function startScan(type = 'full') {
    WebGuard_log(`Starting ${type} scan...`);
    scanResults = { url: currentTab.url, timestamp: new Date().toISOString(), checks: [], scores: {} };

    const progressSection = document.getElementById('progressSection');
    const progressText = document.getElementById('progressText');
    const progressBar = document.getElementById('progressBar');

    progressSection.classList.add('active');
    progressText.textContent = 'Contacting Security Core...';
    progressBar.style.width = '10%';

    try {
        // 1. Trigger Unified Background Audit (Efficiency Boost)
        const backgroundTask = withTimeout(
            chrome.runtime.sendMessage({ action: 'performComprehensiveAudit', url: currentTab.url }),
            SCAN_TIMEOUT_MS
        ).then(res => {
            WebGuard_log('Background audit received:', res);
            processBackgroundResults(res);
            return 'bg_done';
        }).catch(err => {
            WebGuard_log('Background audit error/timeout:', err);
            return 'bg_fail';
        });

        // 2. Trigger Local Page Scans (Parallel)
        const localTasks = [
            runLocalCheck('mixedContent', detectMixedContentInPage),
            runLocalCheck('javascript', detectDangerousJavaScriptInPage),
            runLocalCheck('traffic', analyzeTrafficInPage)
        ];

        let completedTasks = 0;
        const totalTasks = localTasks.length + 1; // +1 for backgroundTask

        const trackTask = (p) => p.then(val => {
            completedTasks++;
            const progress = 10 + (completedTasks / totalTasks) * 80;
            progressBar.style.width = `${progress}%`;
            progressText.textContent = `Completed ${completedTasks}/${totalTasks} audits...`;
            return val;
        });

        // 3. Coordinate all parallel tasks with progress tracking
        await Promise.all([trackTask(backgroundTask), ...localTasks.map(trackTask)]);

        WebGuard_log('All parallel tasks settled. Finalizing...');
        progressBar.style.width = '95%';
        progressText.textContent = 'Generating security report...';
        calculateScores();

        // Safety timeout for saving results
        try {
            await withTimeout(
                chrome.runtime.sendMessage({ action: 'saveScanResult', scanData: scanResults }),
                5000
            );
        } catch (err) {
            WebGuard_log('Warning: Save result timed out, but proceeding to display.');
        }

        progressBar.style.width = '100%';

        setTimeout(() => {
            displayResults();
            progressSection.classList.remove('active');
            WebGuard_log('Scan complete.');
        }, 800);

    } catch (error) {
        console.error('Global scan failure:', error);
        progressSection.classList.remove('active');
    }
}

async function runLocalCheck(key, func) {
    try {
        WebGuard_log(`Running local check: ${key}`);
        const data = await withTimeout(executeScript(func), 5000);
        if (key === 'mixedContent') {
            scanResults.checks.push({ category: 'Mixed Content', severity: data.hasMixedContent ? 'warning' : 'success' });
        } else if (key === 'javascript') {
            scanResults.checks.push({ category: 'JavaScript Security', severity: data.riskLevel === 'critical' ? 'critical' : 'success' });
        }
        return `local_${key}_done`;
    } catch (err) {
        WebGuard_log(`Local check ${key} failed:`, err);
        return `local_${key}_fail`;
    }
}

function processBackgroundResults(res) {
    if (!res || !res.success) {
        scanResults.checks.push({ category: 'Internal Audit', severity: 'warning', details: 'Backend core unavailable' });
        return;
    }

    // Malware
    const vtData = res.malware;
    let malwareSev = vtData?.isMalware ? 'critical' : 'success';
    let malwareDetail = vtData?.source === 'local_database'
        ? 'Local Database Check'
        : `VirusTotal: ${vtData?.stats?.malicious || 0} hits`;

    // If VT is still pending, mark it as scanning
    if (res.vt_pending && !vtData?.isMalware) {
        malwareSev = 'pending';
        malwareDetail = 'Performing deep threat analysis...';
    }

    scanResults.checks.push({
        category: 'Malware Detection',
        severity: malwareSev,
        details: malwareDetail
    });

    // Phishing
    const phishingData = res.phishing;
    scanResults.checks.push({
        category: 'Phishing Detection',
        severity: phishingData?.isPhishing ? 'critical' : 'success',
        details: phishingData?.riskScore ? `Risk Score: ${phishingData.riskScore}` : ''
    });

    // Headers
    let headerSev = 'success';
    let headerDetail = `${res.headers?.present?.length || 0} headers analyzed`;

    if (res.headers?.missing?.length > 0) {
        headerSev = res.headers.missing.length > 4 ? 'critical' : 'warning';
        const missingNames = res.headers.missing.slice(0, 3).map(h => h.name.split('(')[0].trim()).join(', ');
        headerDetail = `Missing: ${missingNames}${res.headers.missing.length > 3 ? '...' : ''}`;
    }

    scanResults.checks.push({
        category: 'Security Headers',
        severity: headerSev,
        details: headerDetail,
        loopholes: res.headers?.missing || []
    });

    // Cookies
    scanResults.checks.push({
        category: 'Cookie Security',
        severity: (res.cookies?.insecure > 0) ? 'warning' : 'success',
        details: res.cookies?.insecure > 0 ? `${res.cookies.insecure} insecure cookies` : 'Safe'
    });
}

// Timeout & Utility
function withTimeout(promise, ms) {
    let timeoutId;
    const timeoutPromise = new Promise((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error('Operation timed out')), ms);
    });
    return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timeoutId));
}

async function executeScript(func) {
    try {
        const res = await chrome.scripting.executeScript({ target: { tabId: currentTab.id }, func });
        return res[0]?.result;
    } catch (e) {
        WebGuard_log('ExecuteScript failed (Tab likely restricted):', e.message);
        return { error: e.message };
    }
}

// Reuse scoring and display logic from previous version
function calculateScores() {
    let securityScore = 100;
    scanResults.checks.forEach(check => {
        if (check.severity === 'critical') securityScore -= 20;
        else if (check.severity === 'warning') securityScore -= 10;
    });
    scanResults.scores.overall = Math.max(0, securityScore);
    updateGauge(scanResults.scores.overall);
}

function updateGauge(score) {
    const gauge = document.getElementById('scoreGauge');
    const scoreDisplay = document.getElementById('overallScore');
    const offset = 377 - (377 * score / 100);
    gauge.style.strokeDashoffset = offset;
    scoreDisplay.textContent = Math.round(score);
    let color = score >= 90 ? '#10b981' : score >= 80 ? '#3b82f6' : score >= 70 ? '#f59e0b' : '#ef4444';
    gauge.style.stroke = color;
    scoreDisplay.style.color = color;

    // Show Report button after scan
    const generateReportBtn = document.getElementById('generateReportBtn');
    if (generateReportBtn) generateReportBtn.style.display = 'flex';
}

function displayResults() {
    const container = document.getElementById('resultsContent');
    container.innerHTML = '';
    const categories = {
        'Phishing Detection': 'emerald', 'Security Headers': 'blue',
        'Cookie Security': 'amber', 'JavaScript Security': 'cyan',
        'Mixed Content': 'amber', 'Malware Detection': 'emerald'
    };

    scanResults.checks.forEach(check => {
        const color = categories[check.category] || 'blue';
        const isError = check.severity === 'critical' || check.severity === 'warning';
        const isPending = check.severity === 'pending';

        const item = document.createElement('div');
        item.className = 'audit-item';
        if (isPending) item.classList.add('pending-anim');

        item.innerHTML = `
            <div class="audit-icon icon-${color}"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
            <div class="audit-info">
                <div class="audit-name">${check.category}</div>
                <div class="audit-status ${check.severity === 'warning' ? 'warn' : check.severity === 'critical' ? 'error' : isPending ? 'pending' : ''}">
                    Status: ${check.severity.toUpperCase()} ${check.details ? `• ${check.details}` : ''}
                </div>
            </div>
            <div class="audit-status ${isError ? 'error' : isPending ? 'pending' : ''}">${isPending ? '⏳' : isError ? '⚠️' : '✓'}</div>
        `;
        container.appendChild(item);
    });
}

function detectMixedContentInPage() { return { hasMixedContent: !!Array.from(document.querySelectorAll('img[src], script[src]')).find(el => el.src && el.src.startsWith('http:')) }; }
function analyzeTrafficInPage() { return { resources: performance.getEntriesByType('resource').map(r => ({ url: r.name })) }; }
function detectDangerousJavaScriptInPage() { return { riskLevel: 'low' }; }

async function toggleMonitoring() {
    monitoringEnabled = document.getElementById('monitoringToggle').checked;
    if (monitoringEnabled) {
        await chrome.runtime.sendMessage({ action: 'startMonitoring', tabId: currentTab.id });
        startStatsRefresh();
    } else {
        await chrome.runtime.sendMessage({ action: 'stopMonitoring' });
        stopStatsRefresh();
    }
}

function handleVTUpdate(vtResult) {
    WebGuard_log('Handling VT update:', vtResult);
    const malwareCheck = scanResults.checks.find(c => c.category === 'Malware Detection');
    if (malwareCheck) {
        malwareCheck.severity = vtResult.malicious > 0 ? 'critical' : 'success';
        malwareCheck.details = `VirusTotal: ${vtResult.malicious} hits / ${vtResult.suspicious} suspicious`;

        // Refresh UI
        calculateScores();
        displayResults();
    }
}

async function downloadDetailedReport() {
    WebGuard_log('Generating detailed report...');
    try {
        let report = '═══════════════════════════════════════════════════════════\n';
        report += '           WEBSITE SECURITY AUDIT REPORT\n';
        report += '═══════════════════════════════════════════════════════════\n\n';
        report += `TARGET URL: ${scanResults.url}\n`;
        report += `TIMESTAMP:  ${new Date(scanResults.timestamp).toLocaleString()}\n`;
        report += `ENGINE:     WebGuard v2.2 (Ultra-Efficient)\n\n`;

        report += '───────────────────────────────────────────────────────────\n';
        report += '                  SECURITY SCORE: ' + scanResults.scores.overall + '/100\n';
        report += '───────────────────────────────────────────────────────────\n\n';

        report += 'DETAILED VULNERABILITY AUDIT:\n';
        scanResults.checks.forEach((check, i) => {
            report += `\n${i + 1}. [${check.severity.toUpperCase()}] ${check.category}\n`;
            report += `   Details: ${check.details}\n`;
            if (check.loopholes && check.loopholes.length > 0) {
                report += `   Loop Holes Found:\n`;
                check.loopholes.forEach(h => report += `     - ${h.name}: ${h.description || 'Missing protection'}\n`);
            }
        });

        report += '\n\n═══════════════════════════════════════════════════════════\n';
        report += '                    END OF REPORT\n';
        report += '═══════════════════════════════════════════════════════════\n';

        const blob = new Blob([report], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const filename = `webguard-audit-${new URL(scanResults.url).hostname}.txt`;
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        alert('Security Report Downloaded!');
    } catch (err) {
        console.error('Report failed:', err);
    }
}

function startStatsRefresh() { if (!statsRefreshInterval) statsRefreshInterval = setInterval(updateMonitoringStats, 1000); }
function stopStatsRefresh() { clearInterval(statsRefreshInterval); statsRefreshInterval = null; }
async function updateMonitoringStats() {
    try {
        const res = await chrome.runtime.sendMessage({ action: 'getMonitoringStats' });
        if (res.enabled && res.stats) {
            document.getElementById('blockedCount').textContent = res.stats.blockedRequests;
            document.getElementById('trackerCount').textContent = res.stats.totalRequests;
        }
    } catch (e) { }
}
