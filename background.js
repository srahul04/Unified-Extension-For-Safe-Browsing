const headerDataStore = {}; // Store header data keyed by tabId
// Store security history for real-time monitoring
let securityHistory = {};

chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        // Only process the main document request for the current tab
        if (details.type === "main_frame") {
            const headers = {};
            details.responseHeaders.forEach(header => {
                headers[header.name.toLowerCase()] = header.value;
            });
            headerDataStore[details.tabId] = headers;
            
            // Store timestamp for this security check
            if (!securityHistory[details.url]) {
                securityHistory[details.url] = [];
            }
            
            // Limit history to last 10 entries per URL
            if (securityHistory[details.url].length >= 10) {
                securityHistory[details.url].shift(); // Remove oldest entry
            }
            
            // Add new entry with timestamp
            securityHistory[details.url].push({
                timestamp: new Date().toISOString(),
                headers: headers
            });
        }
    },
    { urls: ["<all_urls>"], types: ["main_frame"] },
    ["responseHeaders", "extraHeaders"] // Ensure access to all headers in MV3
);

// Listen for messages from popup.js to provide header data
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getHeaders") {
        const tabId = request.tabId;
        const headers = headerDataStore[tabId] || {};
        sendResponse(headers);
        // Clear the stored headers after sending, as they are for a specific page load
        delete headerDataStore[tabId];
    } else if (request.action === "getSecurityHistory") {
        sendResponse(securityHistory[request.url] || []);
    } else if (request.action === "startMonitoring") {
        // Acknowledge receipt of the message
        sendResponse({status: "monitoring_acknowledged"});
    } else if (request.action === "stopMonitoring") {
        // Acknowledge receipt of the message
        sendResponse({status: "monitoring_stopped"});
    }
    return true; // Keep the message channel open for async responses
});

// Clear data when a tab is closed or navigated away from
chrome.tabs.onRemoved.addListener((tabId) => {
    delete headerDataStore[tabId];
});

chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0) { // Main frame navigation
        delete headerDataStore[details.tabId];
    }
});

// Cleanup old history entries (older than 7 days)
setInterval(() => {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    Object.keys(securityHistory).forEach(url => {
        securityHistory[url] = securityHistory[url].filter(entry => {
            return new Date(entry.timestamp) > sevenDaysAgo;
        });
        
        // Remove empty history arrays
        if (securityHistory[url].length === 0) {
            delete securityHistory[url];
        }
    });
}, 86400000); // Run once per day (24 hours in milliseconds)

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
    // Open the extension popup when notification is clicked
    chrome.action.openPopup();
});

// Function to compare security headers and detect changes
const detectSecurityChanges = (oldHeaders, newHeaders) => {
    const securityHeaders = [
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy'
    ];
    
    const changes = [];
    
    // Check for removed or changed security headers
    securityHeaders.forEach(header => {
        if (oldHeaders[header] && !newHeaders[header]) {
            changes.push(`${header} header was removed`);
        } else if (oldHeaders[header] && newHeaders[header] && oldHeaders[header] !== newHeaders[header]) {
            changes.push(`${header} header was changed`);
        }
    });
    
    // Check for added security headers
    securityHeaders.forEach(header => {
        if (!oldHeaders[header] && newHeaders[header]) {
            changes.push(`${header} header was added`);
        }
    });
    
    return changes;
};

// Setup periodic security checks for monitored tabs
let monitoredTabs = {};

// Register a tab for monitoring
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "registerTabForMonitoring") {
        monitoredTabs[message.tabId] = {
            url: message.url,
            lastChecked: new Date().toISOString()
        };
        sendResponse({status: "tab_registered"});
    } else if (message.action === "unregisterTabFromMonitoring") {
        if (monitoredTabs[message.tabId]) {
            delete monitoredTabs[message.tabId];
        }
        sendResponse({status: "tab_unregistered"});
    } else if (message.action === "performSecurityCheck") {
        performSecurityCheck(message.tabId, message.url, sendResponse);
        return true; // Keep the message channel open for the async response
    } else if (message.action === "getSecurityHistory") {
        // Return security history for the specified URL
        const history = securityHistory[message.url] || [];
        sendResponse(history);
    }
    return true;
});

// Function to perform a security check and detect changes
async function performSecurityCheck(tabId, url, sendResponse) {
    try {
        // Skip for browser UI pages and empty tabs
        if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || 
            url.startsWith("about:") || url.startsWith("chrome-extension://")) {
            sendResponse({securityChanged: false});
            return;
        }
        
        // Get current headers
        const headers = headerDataStore[tabId] || {};
        
        // Execute content script to get DOM security data
        let domResponse = null;
        try {
            await chrome.scripting.executeScript({
                target: {tabId: tabId},
                files: ['content.js']
            });
            
            domResponse = await new Promise((resolve) => {
                chrome.tabs.sendMessage(tabId, {action: "analyzePage"}, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error("Error analyzing page:", chrome.runtime.lastError);
                        resolve(null);
                    } else {
                        resolve(response);
                    }
                });
            });
        } catch (error) {
            console.error("Error executing content script:", error);
        }
        
        // Get previous security history for this URL
        const history = securityHistory[url] || [];
        
        let securityChanged = false;
        let changes = [];
        
        if (history.length > 0) {
            // Compare with most recent entry
            const lastEntry = history[history.length - 1];
            
            // Compare headers
            changes = detectSecurityChanges(lastEntry.headers, headers);
            
            // Compare DOM security data if available
            if (domResponse && lastEntry.domData) {
                // Check for changes in key security indicators
                if (domResponse.mixedContent !== lastEntry.domData.mixedContent ||
                    domResponse.cspPresent !== lastEntry.domData.cspPresent ||
                    domResponse.xFrameOptions !== lastEntry.domData.xFrameOptions ||
                    JSON.stringify(domResponse.cookieIssues) !== JSON.stringify(lastEntry.domData.cookieIssues) ||
                    JSON.stringify(domResponse.formIssues) !== JSON.stringify(lastEntry.domData.formIssues) ||
                    JSON.stringify(domResponse.malwareIndicators) !== JSON.stringify(lastEntry.domData.malwareIndicators)) {
                    
                    securityChanged = true;
                    changes.push("DOM security posture changed");
                }
            }
            
            securityChanged = changes.length > 0;
        }
        
        // Update security history with current data
        if (domResponse) {
            addToSecurityHistory(url, headers, domResponse);
        }
        
        // Update last checked timestamp
        if (monitoredTabs[tabId]) {
            monitoredTabs[tabId].lastChecked = new Date().toISOString();
        }
        
        // Send response back to popup
        sendResponse({
            securityChanged: securityChanged,
            changes: changes,
            analysisData: {
                domData: domResponse,
                headerData: headers,
                url: url,
                timestamp: new Date().toISOString()
            }
        });
        
        // If security changed, create notification
        if (securityChanged) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon2.png',
                title: 'Security Changes Detected',
                message: `${changes.length} security changes detected on ${url}. Click for details.`,
                priority: 2
            });
        }
    } catch (error) {
        console.error("Error performing security check:", error);
        sendResponse({securityChanged: false, error: error.message});
    }
}

// Check for tab updates that might affect security
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // If this is a monitored tab and the URL changed, update our records
    if (monitoredTabs[tabId] && changeInfo.url) {
        monitoredTabs[tabId].url = changeInfo.url;
        monitoredTabs[tabId].lastChecked = new Date().toISOString();
        
        // Trigger a security check for the new URL
        setTimeout(() => {
            checkTabSecurity(tabId, changeInfo.url);
        }, 2000); // Wait for page to load
    }
});

// Function to check tab security
const checkTabSecurity = async (tabId, url) => {
    try {
        // Skip for browser UI pages and empty tabs
        if (!url || url.startsWith("chrome://") || url.startsWith("edge://") || 
            url.startsWith("about:") || url.startsWith("chrome-extension://")) {
            return;
        }
        
        // Get current headers
        const headers = headerDataStore[tabId] || {};
        
        // Get previous security history for this URL
        const history = securityHistory[url] || [];
        
        if (history.length > 0) {
            // Compare with most recent entry
            const lastEntry = history[history.length - 1];
            const changes = detectSecurityChanges(lastEntry.headers, headers);
            
            if (changes.length > 0) {
                // Create notification for security changes
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon2.png',
                    title: 'Security Changes Detected',
                    message: `${changes.length} security header changes detected on ${url}. Click for details.`,
                    priority: 2
                });
            }
        }
        
        // Update last checked timestamp
        if (monitoredTabs[tabId]) {
            monitoredTabs[tabId].lastChecked = new Date().toISOString();
        }
    } catch (error) {
        console.error("Error checking tab security:", error);
    }
};