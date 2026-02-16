import { CONFIG } from './config.js';

// Store headers from web requests
const headersCache = new Map();
const vtCache = new Map(); // Global cache for VT results

// Real-Time Monitoring State
let monitoringState = {
  enabled: false,
  tabId: null,
  stats: {
    totalRequests: 0,
    blockedRequests: 0,
    bytesReceived: 0,
    bytesSent: 0,
    suspiciousDomains: [],
    requestLog: []
  },
  startTime: null
};

// Listen for web request completion to capture headers
chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.responseHeaders) {
      const headers = {};
      details.responseHeaders.forEach(header => {
        headers[header.name.toLowerCase()] = header.value;
      });
      headersCache.set(details.url, headers);

      // Clean up old entries (keep only last 50)
      if (headersCache.size > 50) {
        const firstKey = headersCache.keys().next().value;
        headersCache.delete(firstKey);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

/**
 * Security Headers Database
 * Defines expected security headers and their importance
 */
const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'HTTP Strict Transport Security (HSTS)',
    severity: 'high',
    description: 'Enforces HTTPS connections'
  },
  'content-security-policy': {
    name: 'Content Security Policy (CSP)',
    severity: 'high',
    description: 'Prevents XSS and injection attacks'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    severity: 'medium',
    description: 'Prevents clickjacking attacks'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    description: 'Prevents MIME-sniffing attacks'
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    severity: 'low',
    description: 'Legacy XSS protection (deprecated but still useful)'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    severity: 'medium',
    description: 'Controls referrer information'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    severity: 'medium',
    description: 'Controls browser features and APIs'
  }
};

/**
 * Phishing Indicators Database
 * Patterns and keywords commonly used in phishing attacks
 */
const PHISHING_INDICATORS = {
  suspiciousKeywords: [
    'verify', 'suspend', 'urgent', 'confirm', 'account', 'security',
    'update', 'validate', 'click here', 'act now', 'limited time',
    'unusual activity', 'locked', 'expired', 'winner', 'prize'
  ],
  suspiciousTLDs: [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.date', '.racing', '.download', '.stream', '.loan', '.win'
  ],
  urlPatterns: [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP addresses
    /[a-z0-9-]{20,}/, // Very long subdomains
    /@/, // @ symbol in URL (often used to hide real domain)
    /\-{2,}/, // Multiple consecutive hyphens
  ]
};

/**
 * Tracker and Fingerprinting Domains
 * Common tracking and analytics services
 */
const TRACKER_DOMAINS = [
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'facebook.com/tr', 'connect.facebook.net', 'analytics.twitter.com',
  'ads.linkedin.com', 'pixel.adsafeprotected.com', 'scorecardresearch.com',
  'quantserve.com', 'hotjar.com', 'mouseflow.com', 'crazyegg.com',
  'mixpanel.com', 'segment.com', 'amplitude.com', 'heap.io'
];

const FINGERPRINTING_SCRIPTS = [
  'fingerprintjs', 'clientjs', 'creepjs', 'canvas', 'webgl',
  'audiocontext', 'font-detect', 'evercookie'
];

/**
 * Malware and Phishing Domains Database
 */
const knownMalwareDomains = [
  'malware.com', 'phishing-site.net', 'virus-download.org',
  'fake-update.com', 'suspicious-ads.net', 'scam-alert.org',
  'fake-bank.com', 'phishing-paypal.net', 'secure-login-verify.com'
];

const adultContentDomains = [
  'pornhub.com', 'xvideos.com', 'xnxx.com', 'redtube.com',
  'youporn.com', 'tube8.com', 'spankbang.com', 'eporner.com'
];

/**
 * Scan History Storage
 * Stores recent scan results for comparison
 */
const MAX_HISTORY_SIZE = 50;

/**
 * Unified message handler for all runtime messages
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received action:', request.action, 'for URL:', request.url);

  switch (request.action) {
    case 'performComprehensiveAudit':
      const url = request.url;
      // Perform local/fast checks immediately
      Promise.all([
        analyzeSecurityHeaders(url),
        checkCookieSecurity(url),
        Promise.resolve(checkPhishingIndicators(url)),
        Promise.resolve(checkLocalMalware(url)),
        Promise.resolve(checkAdultDomainLogic(url))
      ]).then(async ([headers, cookies, phishing, malware, adult]) => {
        // Send immediate results
        sendResponse({
          success: true,
          headers,
          cookies,
          phishing,
          malware,
          adult,
          vt_pending: true,
          timestamp: new Date().toISOString()
        });

        // 2. Perform VirusTotal analysis in the background (Non-blocking)
        if (CONFIG.VIRUS_TOTAL_API_KEY) {
          try {
            const vtResult = await checkVirusTotalURL(url);
            if (vtResult) {
              // Send an update message back to the popup
              chrome.runtime.sendMessage({
                action: 'updateVTResults',
                url: url,
                vtResult: vtResult
              }).catch(() => { }); // Popup might be closed
            }
          } catch (err) {
            console.error('VT background analysis error:', err);
          }
        }
      }).catch(err => {
        console.error('Audit failure:', err);
        sendResponse({ success: false, error: err.message });
      });
      return true;

    case 'getHeaders':
      const headers = headersCache.get(request.url) || {};
      sendResponse({ headers });
      break;

    case 'analyzeSecurityHeaders':
      analyzeSecurityHeaders(request.url).then(result => {
        sendResponse(result);
      }).catch(err => sendResponse({ error: err.message }));
      return true;

    case 'checkCookieSecurity':
      checkCookieSecurity(request.url).then(result => {
        sendResponse(result);
      }).catch(err => sendResponse({ error: err.message }));
      return true;

    case 'checkPhishing':
      try {
        const phishingResult = checkPhishingIndicators(request.url);
        sendResponse(phishingResult);
      } catch (err) {
        sendResponse({ error: err.message, isPhishing: false, indicators: [] });
      }
      break; // No longer returning true as it is sync

    case 'detectTrackers':
      try {
        const trackerResult = detectTrackers(request.resources || []);
        sendResponse(trackerResult);
      } catch (err) {
        sendResponse({ error: err.message, totalTrackers: 0, trackers: [] });
      }
      break; // Sync

    case 'incrementScanCount':
      chrome.storage.local.get(['scanCount'], (result) => {
        const newCount = (result.scanCount || 0) + 1;
        chrome.storage.local.set({ scanCount: newCount });
        sendResponse({ scanCount: newCount });
      });
      return true;

    case 'saveScanResult':
      saveScanResult(request.scanData)
        .then(result => sendResponse(result))
        .catch(err => {
          console.error('Save result failed:', err);
          sendResponse({ success: false, error: err.message });
        });
      return true;

    case 'getScanHistory':
      getScanHistory(request.limit || 10)
        .then(history => sendResponse({ history }))
        .catch(err => {
          console.error('History fetch failed:', err);
          sendResponse({ history: [] });
        });
      return true;

    case 'getNetworkStats':
      const stats = networkStats.get(request.tabId) || {
        requestCount: 0,
        totalBytes: 0,
        requestTypes: {},
        startTime: Date.now()
      };
      sendResponse({ stats });
      break;

    case 'checkMalwareDomain':
      sendResponse(checkMalwareDomainLogic(request.url));
      break;

    case 'checkAdultDomain':
      sendResponse(checkAdultDomainLogic(request.url));
      break;

    case 'startMonitoring':
      startMonitoring(request.tabId).then(result => {
        sendResponse(result);
      }).catch(err => sendResponse({ error: err.message }));
      return true;

    case 'stopMonitoring':
      stopMonitoring().then(result => {
        sendResponse(result);
      }).catch(err => sendResponse({ error: err.message }));
      return true;

    case 'getMonitoringStats':
      sendResponse(getMonitoringStats());
      break;

    case 'clearMonitoringStats':
      clearMonitoringStats();
      sendResponse({ success: true });
      break;

    default:
      console.warn('Unknown action:', request.action);
      sendResponse({ error: 'Unknown action' });
  }
});

/**
 * Analyze Security Headers
 */
async function analyzeSecurityHeaders(url) {
  const headers = headersCache.get(url) || {};
  const missing = [];
  const present = [];
  const warnings = [];

  for (const [headerKey, headerInfo] of Object.entries(SECURITY_HEADERS)) {
    if (headers[headerKey]) {
      present.push({
        name: headerInfo.name,
        value: headers[headerKey],
        severity: headerInfo.severity
      });
    } else {
      missing.push({
        name: headerInfo.name,
        severity: headerInfo.severity,
        description: headerInfo.description
      });
    }
  }

  // Check for weak CSP
  if (headers['content-security-policy']) {
    const csp = headers['content-security-policy'];
    if (csp.includes('unsafe-inline') || csp.includes('unsafe-eval')) {
      warnings.push({
        header: 'Content-Security-Policy',
        issue: 'Contains unsafe directives (unsafe-inline or unsafe-eval)',
        severity: 'medium'
      });
    }
  }

  return {
    missing,
    present,
    warnings,
    score: calculateHeaderScore(missing, present, warnings)
  };
}

/**
 * Calculate security header score
 */
function calculateHeaderScore(missing, present, warnings) {
  const totalHeaders = Object.keys(SECURITY_HEADERS).length;
  const presentCount = present.length;
  const warningPenalty = warnings.length * 5;

  const baseScore = (presentCount / totalHeaders) * 100;
  return Math.max(0, Math.round(baseScore - warningPenalty));
}

/**
 * Check Cookie Security
 */
async function checkCookieSecurity(url) {
  try {
    const urlObj = new URL(url);
    const cookies = await chrome.cookies.getAll({ url: url });

    const insecureCookies = [];
    const secureCookies = [];

    cookies.forEach(cookie => {
      const issues = [];

      if (!cookie.secure && urlObj.protocol === 'https:') {
        issues.push('Missing Secure flag');
      }

      if (!cookie.httpOnly) {
        issues.push('Missing HttpOnly flag');
      }

      if (cookie.sameSite === 'no_restriction') {
        issues.push('No SameSite protection');
      }

      if (issues.length > 0) {
        insecureCookies.push({
          name: cookie.name,
          domain: cookie.domain,
          issues: issues
        });
      } else {
        secureCookies.push(cookie.name);
      }
    });

    return {
      total: cookies.length,
      secure: secureCookies.length,
      insecure: insecureCookies.length,
      insecureCookies: insecureCookies,
      score: cookies.length > 0 ? Math.round((secureCookies.length / cookies.length) * 100) : 100
    };
  } catch (error) {
    console.error('Error checking cookies:', error);
    return {
      total: 0,
      secure: 0,
      insecure: 0,
      insecureCookies: [],
      score: 0,
      error: error.message
    };
  }
}

/**
 * Check for Phishing Indicators
 */
function checkPhishingIndicators(url) {
  try {
    const urlObj = new URL(url);
    const indicators = [];
    let riskScore = 0;

    // Check for IP address instead of domain
    if (PHISHING_INDICATORS.urlPatterns[0].test(urlObj.hostname)) {
      indicators.push('URL uses IP address instead of domain name');
      riskScore += 30;
    }

    // Check for suspicious TLDs
    const tld = urlObj.hostname.split('.').pop();
    if (PHISHING_INDICATORS.suspiciousTLDs.includes('.' + tld)) {
      indicators.push(`Suspicious top-level domain: .${tld}`);
      riskScore += 20;
    }

    // Check for @ symbol (often used to hide real domain)
    if (urlObj.href.includes('@')) {
      indicators.push('URL contains @ symbol (potential domain hiding)');
      riskScore += 40;
    }

    // Check for excessive hyphens
    if (PHISHING_INDICATORS.urlPatterns[3].test(urlObj.hostname)) {
      indicators.push('Domain contains multiple consecutive hyphens');
      riskScore += 15;
    }

    // Check for very long subdomains
    const parts = urlObj.hostname.split('.');
    const hasLongSubdomain = parts.some(part => part.length > 20);
    if (hasLongSubdomain) {
      indicators.push('Unusually long subdomain detected');
      riskScore += 15;
    }

    // Check for suspicious keywords in URL
    const urlLower = url.toLowerCase();
    const foundKeywords = PHISHING_INDICATORS.suspiciousKeywords.filter(
      keyword => urlLower.includes(keyword)
    );
    if (foundKeywords.length > 2) {
      indicators.push(`Multiple suspicious keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
      riskScore += foundKeywords.length * 5;
    }

    // Check for HTTPS
    if (urlObj.protocol !== 'https:') {
      indicators.push('Not using HTTPS encryption');
      riskScore += 25;
    }

    return {
      isPhishing: riskScore >= 50,
      riskScore: Math.min(riskScore, 100),
      indicators: indicators,
      severity: riskScore >= 70 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 30 ? 'medium' : 'low'
    };
  } catch (error) {
    console.error('Error checking phishing indicators:', error);
    return {
      isPhishing: false,
      riskScore: 0,
      indicators: [],
      severity: 'low',
      error: error.message
    };
  }
}

/**
 * Logic for Malware Domain Check (Local Speed Only)
 */
function checkLocalMalware(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const isLocalMalware = knownMalwareDomains.some(d => domain.includes(d));
    return {
      isMalware: isLocalMalware,
      domain,
      source: 'local_database'
    };
  } catch (error) {
    return { isMalware: false, domain: '', error: error.message };
  }
}

/**
 * VirusTotal API Wrapper with Base64URL Encoding
 */
async function checkVirusTotalURL(url) {
  // Check Cache First
  if (vtCache.has(url)) return vtCache.get(url);

  try {
    // Proper Base64URL encoding (RFC 4648)
    // 1. Standard Base64
    const base64 = btoa(url);
    // 2. Replace + with -, / with _, and remove = padding
    const urlBase64URL = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const response = await fetch(`${CONFIG.API_ENDPOINTS.VIRUS_TOTAL}${urlBase64URL}`, {
      method: 'GET',
      headers: {
        'x-apikey': CONFIG.VIRUS_TOTAL_API_KEY,
        'Accept': 'application/json'
      }
    });

    if (response.status === 429) {
      console.warn('VirusTotal API Rate Limit Exceeded');
      return null;
    }

    if (!response.ok) throw new Error(`VT API Error: ${response.statusText}`);

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    const result = {
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      source: 'virustotal'
    };

    vtCache.set(url, result);
    return result;

  } catch (error) {
    console.error('VirusTotal fetch error:', error);
    return null;
  }
}

/**
 * Logic for Adult Content Check
 */
function checkAdultDomainLogic(url) {
  try {
    const urlObj = new URL(url);
    const isAdult = adultContentDomains.some(domain =>
      urlObj.hostname.includes(domain)
    );
    return { isAdult, domain: urlObj.hostname };
  } catch (error) {
    console.error('Error checking adult domain:', error);
    return { isAdult: false, domain: '', error: error.message };
  }
}

/**
 * Detect Trackers and Fingerprinting Scripts
 */
function detectTrackers(resources) {
  const trackers = [];
  const fingerprinting = [];

  resources.forEach(resource => {
    const url = resource.url || resource;
    const urlLower = url.toLowerCase();

    // Check for tracking domains
    TRACKER_DOMAINS.forEach(domain => {
      if (urlLower.includes(domain)) {
        trackers.push({
          url: url,
          type: 'tracker',
          domain: domain
        });
      }
    });

    // Check for fingerprinting scripts
    FINGERPRINTING_SCRIPTS.forEach(script => {
      if (urlLower.includes(script)) {
        fingerprinting.push({
          url: url,
          type: 'fingerprinting',
          script: script
        });
      }
    });
  });

  return {
    trackers: trackers,
    fingerprinting: fingerprinting,
    totalTrackers: trackers.length,
    totalFingerprinting: fingerprinting.length,
    privacyScore: calculatePrivacyScore(trackers.length, fingerprinting.length)
  };
}

/**
 * Calculate Privacy Score
 */
function calculatePrivacyScore(trackerCount, fingerprintCount) {
  const trackerPenalty = trackerCount * 5;
  const fingerprintPenalty = fingerprintCount * 10;
  const totalPenalty = trackerPenalty + fingerprintPenalty;

  return Math.max(0, 100 - totalPenalty);
}

/**
 * Save Scan Result to History
 */
async function saveScanResult(scanData) {
  try {
    const result = await chrome.storage.local.get(['scanHistory']);
    let history = result.scanHistory || [];

    // Add new scan with timestamp
    history.unshift({
      ...scanData,
      timestamp: new Date().toISOString(),
      id: Date.now()
    });

    // Keep only last MAX_HISTORY_SIZE scans
    if (history.length > MAX_HISTORY_SIZE) {
      history = history.slice(0, MAX_HISTORY_SIZE);
    }

    await chrome.storage.local.set({ scanHistory: history });
    return { success: true, historySize: history.length };
  } catch (error) {
    console.error('Error saving scan result:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Real-Time Monitoring Functions
 */

async function startMonitoring(tabId) {
  try {
    monitoringState.enabled = true;
    monitoringState.tabId = tabId;
    monitoringState.startTime = Date.now();
    monitoringState.stats = {
      totalRequests: 0,
      blockedRequests: 0,
      bytesReceived: 0,
      bytesSent: 0,
      suspiciousDomains: [],
      requestLog: []
    };

    // Update badge to show monitoring is active
    chrome.action.setBadgeText({ text: '●', tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId: tabId });

    console.log('Real-time monitoring started for tab:', tabId);
    return { success: true, message: 'Monitoring started' };
  } catch (error) {
    console.error('Error starting monitoring:', error);
    return { success: false, error: error.message };
  }
}

async function stopMonitoring() {
  try {
    const tabId = monitoringState.tabId;
    monitoringState.enabled = false;
    monitoringState.tabId = null;

    // Clear badge
    if (tabId) {
      chrome.action.setBadgeText({ text: '', tabId: tabId });
    }

    console.log('Real-time monitoring stopped');
    return { success: true, message: 'Monitoring stopped' };
  } catch (error) {
    console.error('Error stopping monitoring:', error);
    return { success: false, error: error.message };
  }
}

function getMonitoringStats() {
  if (!monitoringState.enabled) {
    return {
      enabled: false,
      stats: null
    };
  }

  const uptime = Date.now() - monitoringState.startTime;
  const requestsPerSecond = monitoringState.stats.totalRequests / (uptime / 1000);

  return {
    enabled: true,
    tabId: monitoringState.tabId,
    uptime: uptime,
    stats: {
      ...monitoringState.stats,
      requestsPerSecond: requestsPerSecond.toFixed(2),
      blockedPercentage: monitoringState.stats.totalRequests > 0
        ? ((monitoringState.stats.blockedRequests / monitoringState.stats.totalRequests) * 100).toFixed(1)
        : 0
    }
  };
}

function clearMonitoringStats() {
  monitoringState.stats = {
    totalRequests: 0,
    blockedRequests: 0,
    bytesReceived: 0,
    bytesSent: 0,
    suspiciousDomains: [],
    requestLog: []
  };
  monitoringState.startTime = Date.now();
}

function checkSuspiciousDomain(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;

    // Check against malware domains
    const isMalware = knownMalwareDomains.some(domain => hostname.includes(domain));
    if (isMalware) {
      return { suspicious: true, reason: 'Known malware domain', severity: 'critical' };
    }

    // Check against tracker domains
    const isTracker = TRACKER_DOMAINS.some(domain => hostname.includes(domain));
    if (isTracker) {
      return { suspicious: true, reason: 'Tracking domain', severity: 'warning' };
    }

    // Check phishing indicators
    const phishingCheck = checkPhishingIndicators(url);
    if (phishingCheck.riskScore >= 50) {
      return { suspicious: true, reason: 'Phishing indicators detected', severity: 'critical' };
    }

    return { suspicious: false };
  } catch (error) {
    return { suspicious: false };
  }
}

/**
 * Get Scan History
 */
async function getScanHistory(limit = 10) {
  try {
    const result = await chrome.storage.local.get(['scanHistory']);
    const history = result.scanHistory || [];
    return history.slice(0, limit);
  } catch (error) {
    console.error('Error getting scan history:', error);
    return [];
  }
}

// Extension installation handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('WebGuard v3.3 installed');
    chrome.storage.local.set({
      installDate: new Date().toISOString(),
      scanCount: 0,
      scanHistory: [],
      webguard_settings: {
        defaultScanType: 'full',
        autoScan: true,
        notifications: true,
        theme: 'dark'
      }
    });
  } else if (details.reason === 'update') {
    console.log('WebGuard updated to v3.3');
    chrome.storage.local.get(['webguard_settings'], (data) => {
      if (!data.webguard_settings) {
        chrome.storage.local.set({
          webguard_settings: {
            defaultScanType: 'full',
            autoScan: true,
            notifications: true,
            theme: 'dark'
          }
        });
      }
    });
  }
});

// Handle tab updates to perform auto-scans if enabled
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && !tab.url.startsWith('chrome://')) {
    chrome.storage.local.get(['webguard_settings'], async (result) => {
      const settings = result.webguard_settings || { autoScan: false, defaultScanType: 'full' };

      if (settings.autoScan) {
        console.log(`Auto-Scan triggered [${settings.defaultScanType}] for: ${tab.url}`);

        try {
          const response = await fetch(`${CONFIG.API_ENDPOINTS.WEBGUARD_BACKEND}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: tab.url,
              scan_type: settings.defaultScanType
            })
          });

          const result = await response.json();
          console.log('Auto-Scan completed:', result.url, 'Status:', result.ml_results?.status_label);

          // Update badge based on risk
          const score = result.ml_results?.risk_score || 0;
          const color = score > 70 ? '#ef4444' : score > 40 ? '#f97316' : '#22c55e';
          chrome.action.setBadgeText({ text: score.toString(), tabId: tabId });
          chrome.action.setBadgeBackgroundColor({ color, tabId: tabId });

          // Send notification if critical and enabled
          if (settings.notifications && score > 70) {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icons/icon48.png',
              title: 'WebGuard Security Alert',
              message: `High risk detected on ${new URL(tab.url).hostname}. Risk Score: ${score}`,
              priority: 2
            });
          }
        } catch (error) {
          console.error('Auto-Scan failed:', error);
        }
      }
    });
  }
});

// Network request monitoring for traffic analysis
const networkStats = new Map();

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return;

    // Update network stats
    if (!networkStats.has(tabId)) {
      networkStats.set(tabId, {
        requestCount: 0,
        totalBytes: 0,
        requestTypes: {},
        startTime: Date.now()
      });
    }

    const stats = networkStats.get(tabId);
    stats.requestCount++;

    const type = details.type || 'other';
    stats.requestTypes[type] = (stats.requestTypes[type] || 0) + 1;

    // Real-time monitoring logic
    if (monitoringState.enabled && tabId === monitoringState.tabId) {
      monitoringState.stats.totalRequests++;

      // Check for suspicious domains
      const suspiciousCheck = checkSuspiciousDomain(details.url);
      if (suspiciousCheck.suspicious) {
        const domain = new URL(details.url).hostname;

        // Add to suspicious domains list if not already there
        if (!monitoringState.stats.suspiciousDomains.find(d => d.domain === domain)) {
          monitoringState.stats.suspiciousDomains.push({
            domain: domain,
            reason: suspiciousCheck.reason,
            severity: suspiciousCheck.severity,
            timestamp: Date.now()
          });

          // Send alert to popup
          chrome.runtime.sendMessage({
            action: 'suspiciousDomainAlert',
            domain: domain,
            reason: suspiciousCheck.reason,
            severity: suspiciousCheck.severity
          }).catch(() => { }); // Ignore if popup is closed

          // Log if critical (Blocking requires declarativeNetRequest in MV3)
          if (suspiciousCheck.severity === 'critical') {
            monitoringState.stats.blockedRequests++;
            console.warn('Suspicious activity detected on:', domain);
          }
        }
      }

      // Add to request log (keep last 100)
      monitoringState.stats.requestLog.unshift({
        url: details.url,
        type: details.type,
        timestamp: Date.now()
      });
      if (monitoringState.stats.requestLog.length > 100) {
        monitoringState.stats.requestLog.pop();
      }
    }
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0 || !networkStats.has(tabId)) return;

    const stats = networkStats.get(tabId);
    if (details.responseHeaders) {
      const contentLength = details.responseHeaders.find(
        h => h.name.toLowerCase() === 'content-length'
      );
      if (contentLength) {
        const bytes = parseInt(contentLength.value, 10) || 0;
        stats.totalBytes += bytes;

        // Update monitoring stats
        if (monitoringState.enabled && tabId === monitoringState.tabId) {
          monitoringState.stats.bytesReceived += bytes;
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

chrome.tabs.onRemoved.addListener((tabId) => {
  networkStats.delete(tabId);
  if (headersCache.size > 50) {
    const keysToDelete = Array.from(headersCache.keys()).slice(0, headersCache.size - 50);
    keysToDelete.forEach(key => headersCache.delete(key));
  }
});

// Keep service worker alive
chrome.alarms.create('keepAlive', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    console.log('Service worker heartbeat - v2.0');
  }
});

console.log('Website Security Scanner v2.0 background service worker initialized');
