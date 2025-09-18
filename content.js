chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyzePage") {
        try {
            const analysisResults = {
                hasMixedContent: false,
                hasCSP: false, // For meta tag CSP
                hasXFrameOptions: false, // For meta tag X-Frame-Options
                cookies: [],
                sensitiveAutocomplete: false,
                passwordInputTypeError: false,
            // Enhanced malware detection fields
            suspiciousExternalScripts: false,
            suspiciousDomains: [],
            malwareReputationIssues: [],
            cryptoMiningDetected: false,
            formCrossOriginAction: false,
            hasObfuscatedJS: false,
            totalRequests: 0,
            externalRequests: 0,
            hasLargeResources: false,
                // Real-time monitoring support
                monitoringActive: false,
                lastUpdated: new Date().toISOString()
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

            // 8. Enhanced Malware Detection
            const currentHost = window.location.hostname;
            let missingSRIExternalScripts = 0;
            const suspiciousDomains = [];
            const malwareReputationIssues = [];
            
            // Known malicious/suspicious domain patterns
            const suspiciousPatterns = [
                /bitcoin|crypto|mining|coin/i,
                /malware|virus|trojan/i,
                /phishing|scam|fraud/i,
                /tracker|analytics.*suspicious/i,
                /ads.*malicious/i
            ];
            
            // Known crypto mining domains (basic list)
            const cryptoMiningDomains = [
                'coinhive.com', 'cryptonight.com', 'miner.com',
                'webmine.pro', 'coinimp.com', 'cryptoloot.pro'
            ];
            
            document.querySelectorAll('script[src]').forEach(script => {
                try {
                    const scriptUrl = new URL(script.src);
                    const domain = scriptUrl.hostname;
                    
                    if (domain !== currentHost) {
                        // SRI check
                        const hasIntegrity = !!script.getAttribute('integrity');
                        if (!hasIntegrity) {
                            missingSRIExternalScripts++;
                        }
                        
                        // Check for suspicious patterns
                        const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(domain));
                        const isCryptoMining = cryptoMiningDomains.some(cryptoDomain => domain.includes(cryptoDomain));
                        
                        if (isSuspicious || isCryptoMining) {
                            analysisResults.suspiciousExternalScripts = true;
                            suspiciousDomains.push(domain);
                            
                            if (isCryptoMining) {
                                analysisResults.cryptoMiningDetected = true;
                                malwareReputationIssues.push(`Crypto mining domain: ${domain}`);
                            } else if (isSuspicious) {
                                malwareReputationIssues.push(`Suspicious domain pattern: ${domain}`);
                            }
                        }
                        
                        // Check for domains with suspicious TLDs
                        const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.click', '.download'];
                        if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
                            suspiciousDomains.push(domain);
                            malwareReputationIssues.push(`Suspicious TLD: ${domain}`);
                        }
                    }
                } catch (e) {
                    // Handle invalid URLs
                }
            });
            
            // Check for crypto mining scripts in inline code
            document.querySelectorAll('script:not([src])').forEach(inlineScript => {
                const scriptContent = inlineScript.textContent.toLowerCase();
                if (scriptContent.includes('coinhive') || scriptContent.includes('cryptonight') || 
                    scriptContent.includes('webgl') && scriptContent.includes('mining')) {
                    analysisResults.cryptoMiningDetected = true;
                    malwareReputationIssues.push('Crypto mining script detected in inline code');
                }
            });
            
            analysisResults.suspiciousDomains = suspiciousDomains;
            analysisResults.malwareReputationIssues = malwareReputationIssues;

            // Stylesheet SRI checks
            let missingSRIExternalStyles = 0;
            document.querySelectorAll('link[rel="stylesheet"][href]').forEach(link => {
                try {
                    const hrefUrl = new URL(link.href);
                    if (hrefUrl.hostname !== currentHost) {
                        const hasIntegrity = !!link.getAttribute('integrity');
                        if (!hasIntegrity) {
                            missingSRIExternalStyles++;
                        }
                    }
                } catch (e) {
                    // Ignore invalid URLs
                }
            });
            analysisResults.missingSRIExternalScripts = missingSRIExternalScripts;
            analysisResults.missingSRIExternalStyles = missingSRIExternalStyles;

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
        } catch (error) {
            console.error("Error in content script analysis:", error);
            sendResponse({
                error: true,
                errorMessage: error.message,
                url: window.location.href,
                timestamp: new Date().toISOString()
            });
        }
    }
    return true; // Keep the message channel open for async responses
});