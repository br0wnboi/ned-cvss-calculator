chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.target === 'offscreen') {
        setupOffscreenDocument('offscreen.html').then(() => {
            chrome.runtime.sendMessage(message).then(sendResponse);
        });
        return true; // Indicates we will send response asynchronously
    }
});

let creating;
async function setupOffscreenDocument(path) {
    const offscreenUrl = chrome.runtime.getURL(path);
    const existingContexts = await chrome.runtime.getContexts({
        contextTypes: ['OFFSCREEN_DOCUMENT'],
        documentUrls: [offscreenUrl]
    });

    if (existingContexts.length > 0) {
        console.log(`[Background] Offscreen document already exists. Reusing it.`);
        return;
    }

    if (creating) {
        await creating;
    } else {
        console.log(`[Background] Creating new Offscreen document at ${new Date().toISOString()}`);
        console.time("Create Offscreen Doc");
        creating = chrome.offscreen.createDocument({
            url: path,
            reasons: ['WORKERS'], // Web Workers
            justification: 'Run local machine learning models using Transformers.js in a Web Worker.',
        });
        await creating;
        console.timeEnd("Create Offscreen Doc");
        creating = null;
    }
}

// Track when offscreen document dies
chrome.runtime.onConnect.addListener((port) => {
    // We could listen for connections from the offscreen doc if we wanted strictly.
});
