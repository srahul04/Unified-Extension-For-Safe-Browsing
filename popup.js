// Website Security Scanner v2.0 - Enhanced Popup Logic
// Comprehensive security analysis with scoring, privacy evaluation, and advanced reporting

let currentTab = null;
let scanResults = {};
let geminiApiKey = '';
let darkMode = false;

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
    document.getElementById('generatePdfBtn').addEventListener('click', generatePDF);

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
        phishing: document.getElementById('check-phishing')?.checked || true
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
        'Traffic Analysis': 'High resource count may indicate tracking or poor optimization.'
    };

    return suggestions[check.category] || 'Review security settings.';
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

// PDF Generation (Enhanced with better download support)
async function generatePDF() {
    try {
        // Check if jsPDF is loaded
        if (!window.jspdf) {
            alert('PDF library is loading... Please try again in a moment.');
            return;
        }

        const { jsPDF } = window.jspdf;

        if (!jsPDF) {
            alert('PDF generation library not available. Please reload the extension.');
            return;
        }

        // Check if scan results exist
        if (!scanResults || !scanResults.checks || scanResults.checks.length === 0) {
            alert('No scan results available. Please run a scan first.');
            return;
        }

        const doc = new jsPDF();

        // Title
        doc.setFontSize(20);
        doc.setTextColor(102, 126, 234);
        doc.text('Website Security Report', 20, 20);

        // Metadata
        doc.setFontSize(12);
        doc.setTextColor(0, 0, 0);
        doc.text(`URL: ${scanResults.url}`, 20, 35);
        doc.text(`Date: ${new Date(scanResults.timestamp).toLocaleString()}`, 20, 42);

        // Scores
        doc.setFontSize(16);
        doc.text('Security Assessment', 20, 55);
        doc.setFontSize(12);
        doc.text(`Overall Score: ${scanResults.scores.overall}/100 (${getGrade(scanResults.scores.overall)})`, 20, 65);
        doc.text(`Security: ${scanResults.scores.security}/100 (${getGrade(scanResults.scores.security)})`, 20, 72);
        doc.text(`Privacy: ${scanResults.scores.privacy}/100 (${getGrade(scanResults.scores.privacy)})`, 20, 79);

        // Detailed Results
        let y = 95;
        doc.setFontSize(14);
        doc.text('Detailed Results', 20, y);
        y += 10;

        scanResults.checks.forEach(check => {
            if (y > 270) {
                doc.addPage();
                y = 20;
            }

            doc.setFontSize(12);
            doc.setTextColor(check.severity === 'critical' ? [255, 0, 0] : [0, 0, 0]);
            doc.text(`${check.category} [${check.severity.toUpperCase()}]`, 20, y);

            doc.setFontSize(10);
            doc.setTextColor(50, 50, 50);
            const lines = doc.splitTextToSize(check.details, 170);
            doc.text(lines, 20, y + 7);

            y += 15 + (lines.length * 5);
        });

        // Generate filename with timestamp
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
        const filename = `security-report-${timestamp}.pdf`;

        // Save the PDF (triggers download)
        doc.save(filename);

        // Show success message
        console.log('PDF generated successfully:', filename);

        // Show a brief success indicator
        const btn = document.getElementById('generatePdfBtn');
        const originalText = btn.textContent;
        btn.textContent = '✓ PDF Downloaded!';
        btn.style.background = '#10b981';
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
        }, 2000);

    } catch (error) {
        console.error('PDF generation error:', error);
        alert(`Failed to generate PDF: ${error.message}\n\nPlease try again or use the export options instead.`);
    }
}