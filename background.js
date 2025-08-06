const headerDataStore = {}; // Store header data keyed by tabId

chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        // Only process the main document request for the current tab
        if (details.type === "main_frame") {
            const headers = {};
            details.responseHeaders.forEach(header => {
                headers[header.name.toLowerCase()] = header.value;
            });
            headerDataStore[details.tabId] = headers;
        }
    },
    { urls: ["<all_urls>"], types: ["main_frame"] },
    ["responseHeaders"] // Request access to response headers
);

// Listen for messages from popup.js to provide header data
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getHeaders") {
        const tabId = request.tabId;
        const headers = headerDataStore[tabId] || {};
        sendResponse(headers);
        // Clear the stored headers after sending, as they are for a specific page load
        delete headerDataStore[tabId];
    }
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