// Website Security Scanner Content Script - Enhanced v2.0
// Runs inside web pages to collect security and privacy data

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'analyzeTraffic':
      sendResponse(analyzeTraffic());
      break;

    case 'checkSecurityHeaders':
      sendResponse(checkSecurityHeaders());
      break;

    case 'analyzeCookies':
      sendResponse(analyzeCookies());
      break;

    case 'detectMixedContent':
      sendResponse(detectMixedContent());
      break;

    case 'analyzeFormSecurity':
      sendResponse(analyzeFormSecurity());
      break;

    case 'getThirdPartyResources':
      sendResponse(getThirdPartyResources());
      break;

    case 'detectFingerprinting':
      sendResponse(detectFingerprinting());
      break;

    case 'checkIframeSecurity':
      sendResponse(checkIframeSecurity());
      break;

    case 'detectDangerousJavaScript':
      sendResponse(detectDangerousJavaScript());
      break;

    case 'getSecurityMetrics':
      // Consolidated metrics for comprehensive analysis
      sendResponse({
        traffic: analyzeTraffic(),
        securityHeaders: checkSecurityHeaders(),
        cookies: analyzeCookies(),
        mixedContent: detectMixedContent(),
        formSecurity: analyzeFormSecurity(),
        thirdParty: getThirdPartyResources(),
        fingerprinting: detectFingerprinting(),
        iframes: checkIframeSecurity(),
        dangerousJavaScript: detectDangerousJavaScript()
      });
      break;
  }

  return true;
});

/**
 * Analyze Network Traffic
 * Uses Performance API to get resource loading information
 */
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
      name: r.name,
      type: r.initiatorType,
      size: r.transferSize,
      duration: r.duration
    }))
  };
}

/**
 * Check Security Headers (Client-side limited check)
 * Note: Full header analysis happens in background.js
 */
function checkSecurityHeaders() {
  const metaTags = document.querySelectorAll('meta[http-equiv]');
  const headers = {};

  metaTags.forEach(meta => {
    const httpEquiv = meta.getAttribute('http-equiv');
    const content = meta.getAttribute('content');
    if (httpEquiv && content) {
      headers[httpEquiv.toLowerCase()] = content;
    }
  });

  return {
    metaHeaders: headers,
    hasCSPMeta: !!headers['content-security-policy'],
    missing: headers['content-security-policy'] ? [] : ['Content-Security-Policy']
  };
}

/**
 * Analyze Cookies (Client-side accessible)
 * Note: Full cookie analysis with flags happens in background.js
 */
function analyzeCookies() {
  const cookies = document.cookie.split(';').filter(c => c.trim());

  return {
    count: cookies.length,
    cookies: cookies.map(c => {
      const [name, ...valueParts] = c.trim().split('=');
      return {
        name: name,
        value: valueParts.join('=').substring(0, 20) + '...' // Truncate for privacy
      };
    }),
    hasFirstPartyCookies: cookies.length > 0
  };
}

/**
 * Detect Mixed Content
 * Finds HTTP resources loaded on HTTPS pages
 */
function detectMixedContent() {
  if (window.location.protocol !== 'https:') {
    return {
      hasMixedContent: false,
      reason: 'Page is not HTTPS',
      mixedResources: []
    };
  }

  const mixedResources = [];

  // Check images
  document.querySelectorAll('img[src]').forEach(img => {
    if (img.src.startsWith('http:')) {
      mixedResources.push({
        type: 'image',
        url: img.src,
        element: 'img'
      });
    }
  });

  // Check scripts
  document.querySelectorAll('script[src]').forEach(script => {
    if (script.src.startsWith('http:')) {
      mixedResources.push({
        type: 'script',
        url: script.src,
        element: 'script',
        severity: 'high'
      });
    }
  });

  // Check stylesheets
  document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
    if (link.href.startsWith('http:')) {
      mixedResources.push({
        type: 'stylesheet',
        url: link.href,
        element: 'link'
      });
    }
  });

  // Check iframes
  document.querySelectorAll('iframe[src]').forEach(iframe => {
    if (iframe.src.startsWith('http:')) {
      mixedResources.push({
        type: 'iframe',
        url: iframe.src,
        element: 'iframe',
        severity: 'high'
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

/**
 * Analyze Form Security
 * Checks for insecure forms and password fields
 */
function analyzeFormSecurity() {
  const forms = document.querySelectorAll('form');
  const issues = [];
  let insecureForms = 0;
  let passwordFieldsOnHttp = 0;

  forms.forEach((form, index) => {
    const action = form.action || window.location.href;
    const method = form.method.toLowerCase();
    const hasPasswordField = form.querySelector('input[type="password"]') !== null;

    // Check if form submits over HTTP
    if (action.startsWith('http:')) {
      insecureForms++;
      issues.push({
        formIndex: index,
        issue: 'Form submits over insecure HTTP',
        action: action,
        severity: 'critical'
      });
    }

    // Check for password fields on HTTP pages
    if (hasPasswordField && window.location.protocol === 'http:') {
      passwordFieldsOnHttp++;
      issues.push({
        formIndex: index,
        issue: 'Password field on HTTP page',
        severity: 'critical'
      });
    }

    // Check for autocomplete on sensitive fields
    const sensitiveFields = form.querySelectorAll('input[type="password"], input[name*="card"], input[name*="ssn"]');
    sensitiveFields.forEach(field => {
      if (field.autocomplete !== 'off' && field.autocomplete !== 'new-password') {
        issues.push({
          formIndex: index,
          issue: `Sensitive field allows autocomplete: ${field.name || field.type}`,
          severity: 'medium'
        });
      }
    });
  });

  return {
    totalForms: forms.length,
    insecureForms: insecureForms,
    passwordFieldsOnHttp: passwordFieldsOnHttp,
    issues: issues,
    isSecure: issues.filter(i => i.severity === 'critical').length === 0
  };
}

/**
 * Get Third-Party Resources
 * Identifies resources loaded from external domains
 */
function getThirdPartyResources() {
  const currentDomain = window.location.hostname;
  const resources = performance.getEntriesByType('resource');
  const thirdParty = [];
  const domains = new Set();

  resources.forEach(resource => {
    try {
      const url = new URL(resource.name);
      if (url.hostname !== currentDomain) {
        thirdParty.push({
          url: resource.name,
          domain: url.hostname,
          type: resource.initiatorType,
          size: resource.transferSize
        });
        domains.add(url.hostname);
      }
    } catch (e) {
      // Invalid URL, skip
    }
  });

  return {
    count: thirdParty.length,
    uniqueDomains: domains.size,
    domains: Array.from(domains),
    resources: thirdParty
  };
}

/**
 * Detect Fingerprinting Attempts
 * Looks for common fingerprinting techniques
 */
function detectFingerprinting() {
  const indicators = [];

  // Check for canvas fingerprinting
  const canvasElements = document.querySelectorAll('canvas');
  if (canvasElements.length > 0) {
    indicators.push({
      type: 'canvas',
      description: 'Canvas elements detected (potential fingerprinting)',
      count: canvasElements.length
    });
  }

  // Check for WebGL usage
  const webglCanvas = Array.from(canvasElements).find(canvas => {
    return canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
  });
  if (webglCanvas) {
    indicators.push({
      type: 'webgl',
      description: 'WebGL context detected (potential fingerprinting)'
    });
  }

  // Check for font detection scripts
  const scripts = Array.from(document.querySelectorAll('script[src]'));
  const fontDetectionScripts = scripts.filter(s =>
    s.src.includes('font') || s.src.includes('detect')
  );
  if (fontDetectionScripts.length > 0) {
    indicators.push({
      type: 'font-detection',
      description: 'Font detection scripts found',
      count: fontDetectionScripts.length
    });
  }

  // Check for AudioContext (audio fingerprinting)
  if (window.AudioContext || window.webkitAudioContext) {
    indicators.push({
      type: 'audio',
      description: 'AudioContext API available (potential audio fingerprinting)'
    });
  }

  return {
    detected: indicators.length > 0,
    count: indicators.length,
    indicators: indicators,
    riskLevel: indicators.length >= 3 ? 'high' : indicators.length >= 1 ? 'medium' : 'low'
  };
}

/**
 * Check Iframe Security
 * Analyzes iframe embeddings for security issues
 */
function checkIframeSecurity() {
  const iframes = document.querySelectorAll('iframe');
  const issues = [];
  let insecureIframes = 0;

  iframes.forEach((iframe, index) => {
    const src = iframe.src;
    const sandbox = iframe.sandbox;

    // Check for HTTP iframes on HTTPS page
    if (window.location.protocol === 'https:' && src.startsWith('http:')) {
      insecureIframes++;
      issues.push({
        index: index,
        issue: 'HTTP iframe on HTTPS page (mixed content)',
        src: src,
        severity: 'high'
      });
    }

    // Check for missing sandbox attribute
    if (!sandbox || sandbox.length === 0) {
      issues.push({
        index: index,
        issue: 'Iframe missing sandbox attribute',
        src: src,
        severity: 'medium'
      });
    }

    // Check for overly permissive sandbox
    if (sandbox && sandbox.contains('allow-scripts') && sandbox.contains('allow-same-origin')) {
      issues.push({
        index: index,
        issue: 'Iframe has dangerous sandbox combination (allow-scripts + allow-same-origin)',
        src: src,
        severity: 'high'
      });
    }
  });

  return {
    totalIframes: iframes.length,
    insecureIframes: insecureIframes,
    issues: issues,
    isSecure: issues.filter(i => i.severity === 'high').length === 0
  };
}

/**
 * Detect Dangerous JavaScript Patterns
 * Analyzes scripts for security risks and malicious patterns
 */
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

  // 1. Detect Inline Scripts (unsafe-inline)
  const inlineScripts = document.querySelectorAll('script:not([src])');
  patterns.inlineScripts = inlineScripts.length;

  if (inlineScripts.length > 0) {
    issues.push({
      type: 'inline-scripts',
      severity: inlineScripts.length > 10 ? 'high' : 'medium',
      count: inlineScripts.length,
      description: `${inlineScripts.length} inline script(s) detected (CSP unsafe-inline risk)`
    });
  }

  // 2. Detect Inline Event Handlers
  const inlineHandlers = document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover], [onfocus]');
  patterns.inlineHandlers = inlineHandlers.length;

  if (inlineHandlers.length > 0) {
    issues.push({
      type: 'inline-handlers',
      severity: 'medium',
      count: inlineHandlers.length,
      description: `${inlineHandlers.length} inline event handler(s) found`
    });
  }

  // 3. Analyze Script Content for Dangerous Patterns
  const allScripts = document.querySelectorAll('script');
  allScripts.forEach((script, index) => {
    const scriptContent = script.textContent || script.innerText || '';

    if (scriptContent.length === 0) return;

    // Detect eval() usage
    if (/\beval\s*\(/.test(scriptContent)) {
      patterns.evalUsage++;
      issues.push({
        type: 'eval-usage',
        severity: 'high',
        scriptIndex: index,
        description: 'eval() function detected (code injection risk)'
      });
    }

    // Detect Function constructor
    if (/new\s+Function\s*\(/.test(scriptContent)) {
      patterns.evalUsage++;
      issues.push({
        type: 'function-constructor',
        severity: 'high',
        scriptIndex: index,
        description: 'Function() constructor detected (similar to eval)'
      });
    }

    // Detect setTimeout/setInterval with string arguments
    if (/setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/.test(scriptContent)) {
      patterns.evalUsage++;
      issues.push({
        type: 'string-timeout',
        severity: 'medium',
        scriptIndex: index,
        description: 'setTimeout/setInterval with string argument (eval-like behavior)'
      });
    }

    // Detect document.write()
    if (/document\.write(ln)?\s*\(/.test(scriptContent)) {
      patterns.documentWrite++;
      issues.push({
        type: 'document-write',
        severity: 'medium',
        scriptIndex: index,
        description: 'document.write() detected (can break page rendering)'
      });
    }

    // Detect Obfuscated Code
    const obfuscationScore = detectObfuscation(scriptContent);
    if (obfuscationScore > 3) {
      patterns.obfuscated++;
      issues.push({
        type: 'obfuscated-code',
        severity: obfuscationScore > 5 ? 'high' : 'medium',
        scriptIndex: index,
        score: obfuscationScore,
        description: `Highly obfuscated code detected (score: ${obfuscationScore}/10)`
      });
    }

    // Detect Crypto-Mining Signatures
    const miningIndicators = detectCryptoMining(scriptContent);
    if (miningIndicators.detected) {
      patterns.cryptoMining++;
      issues.push({
        type: 'crypto-mining',
        severity: 'critical',
        scriptIndex: index,
        indicators: miningIndicators.patterns,
        description: `Potential crypto-mining detected: ${miningIndicators.patterns.join(', ')}`
      });
    }
  });

  // Calculate risk level
  const criticalCount = issues.filter(i => i.severity === 'critical').length;
  const highCount = issues.filter(i => i.severity === 'high').length;
  const mediumCount = issues.filter(i => i.severity === 'medium').length;

  let riskLevel = 'low';
  if (criticalCount > 0) riskLevel = 'critical';
  else if (highCount > 2) riskLevel = 'high';
  else if (highCount > 0 || mediumCount > 5) riskLevel = 'medium';

  return {
    detected: issues.length > 0,
    riskLevel: riskLevel,
    totalIssues: issues.length,
    patterns: patterns,
    issues: issues,
    summary: {
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: issues.filter(i => i.severity === 'low').length
    }
  };
}

/**
 * Detect Code Obfuscation
 * Returns a score from 0-10 indicating obfuscation level
 */
function detectObfuscation(code) {
  let score = 0;

  // High entropy (random-looking variable names)
  const varNames = code.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\b/g) || [];
  const shortVarRatio = varNames.filter(v => v.length <= 2).length / Math.max(varNames.length, 1);
  if (shortVarRatio > 0.5) score += 2;

  // Excessive escape sequences
  const escapeCount = (code.match(/\\x[0-9a-fA-F]{2}/g) || []).length;
  const unicodeCount = (code.match(/\\u[0-9a-fA-F]{4}/g) || []).length;
  if (escapeCount + unicodeCount > 20) score += 2;

  // Hex encoded strings
  if (/0x[0-9a-fA-F]{2,}/g.test(code)) score += 1;

  // Base64 patterns
  const base64Matches = code.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || [];
  if (base64Matches.length > 3) score += 2;

  // String concatenation patterns (obfuscation technique)
  const concatCount = (code.match(/['"][^'"]{1,3}['"]\s*\+\s*['"][^'"]{1,3}['"]/g) || []).length;
  if (concatCount > 10) score += 1;

  // Array-based string construction
  if (/\[[^\]]{50,}\]\.join\s*\(/.test(code)) score += 2;

  // Excessive use of String.fromCharCode
  if ((code.match(/String\.fromCharCode/g) || []).length > 5) score += 2;

  return Math.min(score, 10);
}

/**
 * Detect Crypto-Mining Signatures
 * Checks for known mining libraries and patterns
 */
function detectCryptoMining(code) {
  const patterns = [];

  // Known mining library names
  const miningLibs = [
    'coinhive', 'cryptoloot', 'coin-hive', 'jsecoin', 'minero',
    'crypto-loot', 'webminer', 'cryptonight', 'monero'
  ];

  for (const lib of miningLibs) {
    if (new RegExp(lib, 'i').test(code)) {
      patterns.push(`Mining library: ${lib}`);
    }
  }

  // Mining pool domains
  const miningDomains = [
    'coinhive.com', 'coin-hive.com', 'crypto-loot.com', 'jsecoin.com',
    'webminepool.com', 'minero.cc', 'cryptoloot.pro'
  ];

  for (const domain of miningDomains) {
    if (code.includes(domain)) {
      patterns.push(`Mining pool: ${domain}`);
    }
  }

  // WebAssembly with suspicious patterns
  if (/WebAssembly\.instantiate|\.wasm/.test(code)) {
    if (/worker|thread|hash|mine/i.test(code)) {
      patterns.push('Suspicious WebAssembly usage');
    }
  }

  // Worker threads with mining indicators
  if (/new\s+Worker/.test(code)) {
    if (/hash|nonce|difficulty|target/i.test(code)) {
      patterns.push('Worker thread with mining indicators');
    }
  }

  // Cryptographic hash functions (common in mining)
  if (/SHA256|keccak|blake2b|cryptonight/i.test(code)) {
    if (/loop|while|setInterval/.test(code)) {
      patterns.push('Hash function in loop (mining pattern)');
    }
  }

  return {
    detected: patterns.length > 0,
    patterns: patterns
  };
}

console.log('Website Security Scanner v2.0 content script loaded');