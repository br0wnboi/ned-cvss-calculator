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
        return;
    }

    if (creating) {
        await creating;
    } else {
        creating = chrome.offscreen.createDocument({
            url: path,
            reasons: ['WORKERS'], // Web Workers
            justification: 'Run local machine learning models using Transformers.js in a Web Worker.',
        });
        await creating;
        creating = null;
    }
}
