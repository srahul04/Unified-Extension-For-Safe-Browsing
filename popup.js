document.addEventListener('DOMContentLoaded', async () => {
    const loadingSpinner = document.getElementById('loading');
    const resultsDiv = document.getElementById('results');
    const llmOutputDiv = document.getElementById('llm-output');
    const llmOutputLoading = document.getElementById('llm-output-loading');
    const pdfLoadingText = document.getElementById('pdf-loading-text');
    const scanningUi = document.getElementById('scanning-ui');
    const scanningProgress = document.getElementById('scanning-progress');

    let currentAnalysisData = {}; // Store the latest analysis data
    let currentLlmSummary = ""; // Store the latest LLM summary
    let currentLlmExplanations = ""; // Store the latest LLM explanations
    let currentLlmOverallSecurityAssessment = ""; // Store the LLM's overall security assessment

    // Show initial scanning UI
    loadingSpinner.classList.add('hidden'); // Hide initial spinner
    resultsDiv.classList.add('hidden'); // Hide results initially
    scanningUi.classList.remove('hidden'); // Show scanning UI

    // Helper function to render a result item
    function renderResult(elementId, iconClass, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<span class="icon ${iconClass}">${getIcon(iconClass)}</span> <span>${text}</span>`;
        }
    }

    // Helper to get actual icon character
    function getIcon(iconClass) {
        if (iconClass.includes('success-icon')) return '&#x2714;'; // Checkmark
        if (iconClass.includes('warning-icon')) return '&#x26A0;'; // Warning sign
        if (iconClass.includes('error-icon')) return '&#x2716;'; // X mark
        if (iconClass.includes('info-icon')) return '&#x2139;'; // Info sign
        return '';
    }

    // Function to call Gemini API
    async function callGeminiAPI(prompt) {
        llmOutputDiv.classList.add('hidden');
        llmOutputLoading.classList.remove('hidden');

        try {
            let chatHistory = [];
            chatHistory.push({ role: "user", parts: [{ text: prompt }] });
            const payload = { contents: chatHistory };
            const apiKey = ""; // Canvas will provide this at runtime
            const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (result.candidates && result.candidates.length > 0 &&
                result.candidates[0].content && result.candidates[0].content.parts &&
                result.candidates[0].content.parts.length > 0) {
                return result.candidates[0].content.parts[0].text;
            } else {
                console.error("Gemini API response structure unexpected:", result);
                return "Error: Could not get a valid response from the AI. Please try again.";
            }
        } catch (error) {
            console.error("Error calling Gemini API:", error);
            return `Error: Failed to connect to AI. ${error.message}`;
        } finally {
            llmOutputLoading.classList.add('hidden');
            llmOutputDiv.classList.remove('hidden');
        }
    }

    // Automated analysis and report generation flow
    async function runAnalysisAndReport() {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tabs.length === 0) {
            console.error("No active tab found.");
            scanningUi.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
            renderResult('https-check', 'error-icon', 'Could not get active tab URL.');
            return;
        }

        const activeTab = tabs[0];
        const url = activeTab.url;

        // Step 1: Request header data from background script
        scanningProgress.innerText = "Collecting HTTP headers...";
        const headerResponse = await new Promise(resolve => {
            chrome.runtime.sendMessage({ action: "getHeaders", tabId: activeTab.id }, resolve);
        });
        if (chrome.runtime.lastError) {
            console.error("Error getting headers from background script:", chrome.runtime.lastError.message);
        }

        // Step 2: Execute content script for DOM analysis
        scanningProgress.innerText = "Analyzing page DOM...";
        await chrome.scripting.executeScript({
            target: { tabId: activeTab.id },
            files: ['content.js']
        });
        if (chrome.runtime.lastError) {
            console.error("Script injection failed: ", chrome.runtime.lastError.message);
            scanningUi.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
            renderResult('https-check', 'error-icon', 'Failed to inject content script. Ensure permissions are granted.');
            return;
        }

        // Step 3: Send message to content script to request DOM analysis
        scanningProgress.innerText = "Processing client-side data...";
        const domResponse = await new Promise(resolve => {
            chrome.tabs.sendMessage(activeTab.id, { action: "analyzePage" }, resolve);
        });
        if (chrome.runtime.lastError) {
            console.error("Error sending message or no response from content script:", chrome.runtime.lastError.message);
            scanningUi.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
            renderResult('https-check', 'error-icon', 'Failed to get DOM analysis results. Try refreshing the page.');
            return;
        }
        if (!domResponse) {
            console.error("No response received from content script.");
            scanningUi.classList.add('hidden');
            resultsDiv.classList.remove('hidden');
            renderResult('https-check', 'error-icon', 'No DOM analysis response received.');
            return;
        }

        currentAnalysisData = { domData: domResponse, headerData: headerResponse, url: url };
        displayResults(domResponse, headerResponse, url);

        // Step 4: Generate Security Summary with LLM
        scanningProgress.innerText = "Generating AI Security Summary...";
        const summaryPrompt = `Analyze the following website security findings and provide a concise summary of its client-side security posture, highlighting key strengths and weaknesses. Conclude with an **Overall Client-Side Security Status** (e.g., 'Secure', 'Moderate', 'Not Secure'), and provide a brief justification for your rating. Focus on HTTP headers, client-side practices, potential malware indicators, and traffic patterns.
        
        Website URL: ${currentAnalysisData.url}
        
        DOM Analysis: ${JSON.stringify(currentAnalysisData.domData, null, 2)}
        
        HTTP Headers: ${JSON.stringify(currentAnalysisData.headerData, null, 2)}
        
        Provide the summary in a clear, easy-to-understand format. Ensure the "Overall Client-Side Security Status" is clearly stated at the end.`;
        currentLlmSummary = await callGeminiAPI(summaryPrompt);
        llmOutputDiv.innerText = currentLlmSummary;
        const overallMatch = currentLlmSummary.match(/Overall Client-Side Security Posture: (.+)/);
        if (overallMatch && overallMatch[1]) {
            currentLlmOverallSecurityAssessment = overallMatch[1].trim();
        } else {
            currentLlmOverallSecurityAssessment = "Not explicitly rated by AI in summary.";
        }

        // Step 5: Generate Explanations and Fixes with LLM
        scanningProgress.innerText = "Generating AI Explanations and Fixes...";
        let problematicFindings = [];
        if (!currentAnalysisData.url.startsWith('https://')) problematicFindings.push("Missing HTTPS");
        if (currentAnalysisData.domData.hasMixedContent) problematicFindings.push("Mixed Content");
        if (!currentAnalysisData.domData.hasCSP && (!currentAnalysisData.headerData || !currentAnalysisData.headerData['content-security-policy'])) problematicFindings.push("Missing Content Security Policy (CSP)");
        if (!currentAnalysisData.domData.hasXFrameOptions && (!currentAnalysisData.headerData || !currentAnalysisData.headerData['x-frame-options'])) problematicFindings.push("Missing X-Frame-Options");
        if (!currentAnalysisData.headerData || !currentAnalysisData.headerData['strict-transport-security']) problematicFindings.push("Missing Strict-Transport-Security (HSTS)");
        if (!currentAnalysisData.headerData || currentAnalysisData.headerData['x-content-type-options'] !== 'nosniff') problematicFindings.push("Missing or incorrect X-Content-Type-Options (should be nosniff)");
        if (currentAnalysisData.domData.cookies && currentAnalysisData.domData.cookies.some(c => !c.secure || !c.httpOnlyDetected)) problematicFindings.push("Insecure Cookies (missing Secure/HttpOnly)");
        if (currentAnalysisData.domData.sensitiveAutocomplete) problematicFindings.push("Sensitive Autocomplete enabled on input fields");
        if (currentAnalysisData.domData.passwordInputTypeError) problematicFindings.push("Password input fields not using type='password'");
        if (!currentAnalysisData.headerData || !currentAnalysisData.headerData['referrer-policy']) problematicFindings.push("Missing Referrer-Policy");
        if (!currentAnalysisData.headerData || !currentAnalysisData.headerData['permissions-policy']) problematicFindings.push("Missing Permissions-Policy");
        if (!currentAnalysisData.headerData || !currentAnalysisData.headerData['cross-origin-opener-policy']) problematicFindings.push("Missing Cross-Origin-Opener-Policy (COOP)");
        if (!currentAnalysisData.headerData || !currentAnalysisData.headerData['cross-origin-resource-policy']) problematicFindings.push("Missing Cross-Origin-Resource-Policy (CORP)");
        if (currentAnalysisData.domData.suspiciousExternalScripts) problematicFindings.push("Suspicious External Scripts detected");
        if (currentAnalysisData.domData.formCrossOriginAction) problematicFindings.push("Form submitting to a different origin");
        if (currentAnalysisData.domData.hasObfuscatedJS) problematicFindings.push("Obfuscated JavaScript detected (basic heuristic)");
        if (currentAnalysisData.domData.externalRequests > 5) problematicFindings.push(`High number of external requests (${currentAnalysisData.domData.externalRequests})`);
        if (currentAnalysisData.domData.hasLargeResources) problematicFindings.push("Large resources detected");

        if (problematicFindings.length === 0) {
            currentLlmExplanations = "No major security issues detected that require specific AI-powered explanations. Great job!";
        } else {
            const explanationsPrompt = `For a web application, explain the security risks of the following issues and provide actionable, specific remediation steps.
            
            Issues detected:
            ${problematicFindings.map((issue, index) => `${index + 1}. ${issue}`).join('\n')}
            
            Provide explanations and remediation steps for each issue in a clear, concise, and practical manner.`;
            currentLlmExplanations = await callGeminiAPI(explanationsPrompt);
        }
        llmOutputDiv.innerText += `\n\n--- Explanations and Fixes ---\n${currentLlmExplanations}`; // Append explanations
        
        // Step 6: Generate PDF Report
        scanningProgress.innerText = "Generating PDF Report...";
        await generatePdfReport();

        scanningProgress.innerText = "Scan Complete!";
        // Keep scanning UI visible for a moment, then transition to results
        setTimeout(() => {
            scanningUi.classList.add('hidden'); // Hide scanning UI
            resultsDiv.classList.remove('hidden'); // Show results
        }, 1500); // Show "Scan Complete!" for 1.5 seconds
    }

    // Function to generate PDF Report
    async function generatePdfReport() {
        pdfLoadingText.classList.remove('hidden');

        try {
            if (typeof window.jspdf === 'undefined' || typeof window.jspdf.jsPDF === 'undefined') {
                throw new Error("jsPDF library not loaded. Please ensure internet connectivity and try again.");
            }

            const jsPDF = window.jspdf.jsPDF;
            const doc = new jsPDF();
            let y = 10;
            const lineHeight = 7;
            const margin = 10;
            const maxWidth = 190;

            doc.setFontSize(18);
            doc.text("Web Security Analysis Report", margin, y);
            y += lineHeight * 2;

            doc.setFontSize(12);
            doc.text(`URL: ${currentAnalysisData.url}`, margin, y);
            y += lineHeight;
            doc.text(`Date: ${new Date().toLocaleString()}`, margin, y);
            y += lineHeight * 2;

            const addSection = (title, content) => {
                if (y + lineHeight * 2 > doc.internal.pageSize.height - margin) {
                    doc.addPage();
                    y = margin;
                }
                doc.setFontSize(14);
                doc.text(title, margin, y);
                y += lineHeight;
                doc.setFontSize(10);
                const splitText = doc.splitTextToSize(content, maxWidth);
                doc.text(splitText, margin, y);
                y += splitText.length * lineHeight + lineHeight;
            };

            if (currentLlmOverallSecurityAssessment) {
                addSection("Overall Client-Side Security Posture", currentLlmOverallSecurityAssessment);
            } else {
                addSection("Overall Client-Side Security Posture", "Please generate the AI Security Summary first to get an overall assessment.");
            }

            let generalChecksContent = `HTTPS: ${currentAnalysisData.url.startsWith('https://') ? 'Enabled' : 'Disabled'} (Note: This checks protocol, not certificate validity)\n`;
            generalChecksContent += `Mixed Content: ${currentAnalysisData.domData.hasMixedContent ? 'Detected' : 'None'}\n`;
            generalChecksContent += `Content Security Policy (CSP): ${currentAnalysisData.domData.hasCSP || (currentAnalysisData.headerData && currentAnalysisData.headerData['content-security-policy']) ? 'Detected' : 'Missing'}\n`;
            generalChecksContent += `X-Frame-Options: ${currentAnalysisData.domData.hasXFrameOptions || (currentAnalysisData.headerData && currentAnalysisData.headerData['x-frame-options']) ? 'Detected' : 'Missing'}\n`;
            generalChecksContent += `Strict-Transport-Security (HSTS): ${currentAnalysisData.headerData && currentAnalysisData.headerData['strict-transport-security'] ? 'Detected' : 'Missing'}\n`;
            generalChecksContent += `X-Content-Type-Options: ${currentAnalysisData.headerData && currentAnalysisData.headerData['x-content-type-options'] === 'nosniff' ? 'nosniff' : 'Missing or Incorrect'}\n`;
            generalChecksContent += `X-XSS-Protection: ${currentAnalysisData.headerData && currentAnalysisData.headerData['x-xss-protection'] && currentAnalysisData.headerData['x-xss-protection'].startsWith('1') ? 'Enabled' : 'Not Enabled or Deprecated'}\n`;
            generalChecksContent += `Referrer-Policy: ${currentAnalysisData.headerData && currentAnalysisData.headerData['referrer-policy'] ? currentAnalysisData.headerData['referrer-policy'] : 'Missing'}\n`;
            generalChecksContent += `Permissions-Policy: ${currentAnalysisData.headerData && currentAnalysisData.headerData['permissions-policy'] ? 'Detected' : 'Missing'}\n`;
            generalChecksContent += `Cross-Origin-Opener-Policy (COOP): ${currentAnalysisData.headerData && currentAnalysisData.headerData['cross-origin-opener-policy'] ? 'Detected' : 'Missing'}\n`;
            generalChecksContent += `Cross-Origin-Resource-Policy (CORP): ${currentAnalysisData.headerData && currentAnalysisData.headerData['cross-origin-resource-policy'] ? 'Detected' : 'Missing'}\n`;
            addSection("General Security Checks", generalChecksContent);

            let cookieContent = "";
            if (currentAnalysisData.domData.cookies && currentAnalysisData.domData.cookies.length > 0) {
                currentAnalysisData.domData.cookies.forEach(cookie => {
                    let status = [];
                    if (!cookie.secure) status.push('Not Secure');
                    if (!cookie.httpOnlyDetected) status.push('Not HttpOnly (Accessible by JS)');
                    if (status.length === 0) status.push('Secure & HttpOnly');
                    cookieContent += `${cookie.name}: ${status.join(', ')}\n`;
                });
            } else {
                cookieContent = "No cookies found or accessible via JavaScript.\n";
            }
            addSection("Cookie Security", cookieContent);

            let formContent = `Sensitive Autocomplete: ${currentAnalysisData.domData.sensitiveAutocomplete ? 'Detected' : 'None'}\n`;
            formContent += `Password Input Type: ${currentAnalysisData.domData.passwordInputTypeError ? 'Incorrect Type' : 'Correct Type'}\n`;
            formContent += `Password Encryption (Client-Side Note): This extension cannot verify server-side password encryption or hashing. Ensure strong hashing algorithms are used server-side.\n`;
            addSection("Form Security", formContent);

            let malwareContent = `Suspicious External Scripts: ${currentAnalysisData.domData.suspiciousExternalScripts ? 'Detected' : 'None'}\n`;
            malwareContent += `Form Cross-Origin Action: ${currentAnalysisData.domData.formCrossOriginAction ? 'Detected' : 'None'}\n`;
            malwareContent += `Obfuscated JavaScript (Basic Heuristic): ${currentAnalysisData.domData.hasObfuscatedJS ? 'Detected' : 'None'}\n`;
            addSection("Potential Malware Indicators", malwareContent);

            let trafficContent = `Total Network Requests: ${currentAnalysisData.domData.totalRequests}\n`;
            trafficContent += `External Network Requests: ${currentAnalysisData.domData.externalRequests}\n`;
            trafficContent += `Large Resources (>1MB): ${currentAnalysisData.domData.hasLargeResources ? 'Detected' : 'None'}\n`;
            addSection("Traffic Analysis", trafficContent);

            if (currentLlmSummary) {
                addSection("AI-Powered Security Summary", currentLlmSummary);
            }
            if (currentLlmExplanations) {
                addSection("AI-Powered Explanations & Fixes", currentLlmExplanations);
            }

            doc.save(`security_report_${new Date().toISOString().slice(0,10)}.pdf`);
            pdfLoadingText.innerText = "PDF generated successfully!";

        } catch (error) {
            console.error("Error generating PDF:", error);
            pdfLoadingText.innerText = `Error generating PDF: ${error.message}`;
        } finally {
            setTimeout(() => { pdfLoadingText.classList.add('hidden'); }, 5000); // Hide message after 5 seconds
        }
    }

    // Start the automated process when the popup is opened
    runAnalysisAndReport();
});