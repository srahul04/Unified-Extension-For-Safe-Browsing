chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzePage") {
        const analysisResults = {
            hasMixedContent: false,
            hasCSP: false, // For meta tag CSP
            hasXFrameOptions: false, // For meta tag X-Frame-Options
            cookies: [],
            sensitiveAutocomplete: false,
            passwordInputTypeError: false,
            // New fields for malware/traffic
            suspiciousExternalScripts: false,
            formCrossOriginAction: false,
            hasObfuscatedJS: false,
            totalRequests: 0,
            externalRequests: 0,
            hasLargeResources: false
        };

        // 1. Check for Mixed Content
        const currentProtocol = window.location.protocol;
        if (currentProtocol === 'https:') {
            const insecureResources = document.querySelectorAll(
                'img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]'
            );
            if (insecureResources.length > 0) {
                analysisResults.hasMixedContent = true;
            }
        }

        // 2. Check for Content Security Policy (CSP) meta tag
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        if (cspMeta) {
            analysisResults.hasCSP = true;
        }

        // 3. Check for X-Frame-Options meta tag (less common, usually a header)
        const xFrameOptionsMeta = document.querySelector('meta[http-equiv="X-Frame-Options"]');
        if (xFrameOptionsMeta) {
            analysisResults.hasXFrameOptions = true;
        }

        // 4. Analyze Cookies (limited by document.cookie string)
        const cookiesString = document.cookie;
        if (cookiesString) {
            cookiesString.split(';').forEach(cookiePair => {
                const parts = cookiePair.trim().split('=');
                const name = parts[0];
                const value = parts.slice(1).join('=');
                const cookieInfo = {
                    name: name,
                    value: value,
                    secure: cookiePair.includes('Secure'),
                    httpOnlyDetected: false // If accessible via JS, it's not HttpOnly
                };
                analysisResults.cookies.push(cookieInfo);
            });
        }

        // 7. Form Security Checks
        const sensitiveInputTypes = ['password', 'current-password', 'new-password', 'cc-number', 'cc-csc', 'cc-exp'];
        document.querySelectorAll('input').forEach(input => {
            if (sensitiveInputTypes.includes(input.autocomplete) && input.autocomplete !== 'off') {
                analysisResults.sensitiveAutocomplete = true;
            }
        });
        document.querySelectorAll('input[id*="pass"], input[name*="pass"]').forEach(input => {
            if (input.type !== 'password' && input.type !== 'hidden') {
                analysisResults.passwordInputTypeError = true;
            }
        });

        // --- New Features: Malware Attack Possibilities ---

        // 8. Suspicious External Scripts
        const currentHost = window.location.hostname;
        document.querySelectorAll('script[src]').forEach(script => {
            try {
                const scriptUrl = new URL(script.src);
                if (scriptUrl.hostname !== currentHost && !scriptUrl.hostname.includes('google') && !scriptUrl.hostname.includes('gstatic') && !scriptUrl.hostname.includes('jsdelivr') && !scriptUrl.hostname.includes('cloudflare')) {
                    // Basic heuristic: flag scripts from domains not current host and not common CDNs/Google services
                    analysisResults.suspiciousExternalScripts = true;
                }
            } catch (e) {
                // Handle invalid URLs
            }
        });

        // 9. Form Cross-Origin Action
        document.querySelectorAll('form').forEach(form => {
            const actionUrl = form.action;
            if (actionUrl) {
                try {
                    const actionHost = new URL(actionUrl).hostname;
                    if (actionHost !== currentHost) {
                        analysisResults.formCrossOriginAction = true;
                    }
                } catch (e) {
                    // Handle invalid URLs
                }
            }
        });

        // 10. Basic Obfuscated JavaScript Detection
        // This is a very simple heuristic and can have false positives/negatives.
        // More robust detection requires AST analysis.
        document.querySelectorAll('script:not([src])').forEach(inlineScript => {
            const scriptContent = inlineScript.textContent;
            // Look for common obfuscation patterns:
            // - Very long lines without spaces (minified is okay, but extreme length can be suspicious)
            // - High density of non-alphanumeric characters
            // - Presence of eval, unescape, atob, String.fromCharCode in unusual contexts
            const lineLengthThreshold = 200; // Arbitrary threshold for long lines
            const nonAlphaNumRatioThreshold = 0.5; // Arbitrary threshold for non-alphanumeric characters

            const lines = scriptContent.split('\n');
            for (const line of lines) {
                if (line.length > lineLengthThreshold && !line.includes(' ')) {
                    analysisResults.hasObfuscatedJS = true;
                    break;
                }
                const nonAlphaNumMatch = line.match(/[^a-zA-Z0-9\s\.\(\)\{\}\[\]\=\-\+\*\/;,:_'"!@#$%^&`~]/g);
                if (nonAlphaNumMatch && (nonAlphaNumMatch.length / line.length) > nonAlphaNumRatioThreshold) {
                    analysisResults.hasObfuscatedJS = true;
                    break;
                }
            }
            if (scriptContent.includes('eval(') || scriptContent.includes('unescape(') || scriptContent.includes('atob(') || scriptContent.includes('String.fromCharCode(')) {
                // Further check for suspicious usage, but for basic detection, presence is enough
                analysisResults.hasObfuscatedJS = true;
            }
        });


        // --- New Features: Traffic Analysis (Client-Side) ---

        // 11. Total and External Network Requests (from performance API)
        // This gives a snapshot of resources loaded during page load.
        // For ongoing requests, background.js webRequest API is better.
        const resources = performance.getEntriesByType("resource");
        analysisResults.totalRequests = resources.length;

        resources.forEach(resource => {
            try {
                const resourceUrl = new URL(resource.name);
                if (resourceUrl.hostname !== currentHost) {
                    analysisResults.externalRequests++;
                }
            } catch (e) {
                // Ignore invalid resource URLs
            }

            // 12. Large Resource Detection (e.g., > 1MB)
            const ONE_MB = 1024 * 1024;
            if (resource.decodedBodySize && resource.decodedBodySize > ONE_MB) {
                analysisResults.hasLargeResources = true;
            } else if (resource.transferSize && resource.transferSize > ONE_MB) { // Fallback for transfer size
                 analysisResults.hasLargeResources = true;
            }
        });

        sendResponse(analysisResults);
    }
});