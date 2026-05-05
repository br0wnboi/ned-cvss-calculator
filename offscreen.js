// Ensure we can access the transformers library
const { pipeline, env } = window; // or however it's exported in the UMD build

// Note: For testing, we are allowing remote models. 
// For production, we will bundle the models locally to be 100% offline.
if (env) {
    env.allowLocalModels = false;
    env.allowRemoteModels = true;
}

let embedder = null;

// Mock database for testing semantic search
const testCweDB = [
    { id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)', desc: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.' },
    { id: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)', desc: 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.' },
    { id: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)', desc: 'The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.' },
    { id: 'CWE-200', name: 'Exposure of Sensitive Information to an Unauthorized Actor', desc: 'The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.' }
];

let embeddedCweDB = [];

function cosineSimilarity(vecA, vecB) {
    let dotProduct = 0, normA = 0, normB = 0;
    for (let i = 0; i < vecA.length; i++) {
        dotProduct += vecA[i] * vecB[i];
        normA += vecA[i] * vecA[i];
        normB += vecB[i] * vecB[i];
    }
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

async function initEmbedder() {
    if (!embedder) {
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Loading ML Model (~25MB)...' });
        // We use the transformers library from the global scope (since we loaded via script tag)
        const transformers = window.transformers || window; // Fallbacks
        const pipe = transformers.pipeline;
        embedder = await pipe('feature-extraction', 'Xenova/all-MiniLM-L6-v2', {
            quantized: true,
        });

        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Embedding test DB...' });
        // Compute embeddings for our small test DB
        embeddedCweDB = [];
        for (const cwe of testCweDB) {
            const output = await embedder(cwe.name + " " + cwe.desc, { pooling: 'mean', normalize: true });
            embeddedCweDB.push({
                ...cwe,
                vector: Array.from(output.data)
            });
        }
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Ready' });
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'SEMANTIC_SEARCH') {
        (async () => {
            try {
                await initEmbedder();
                const output = await embedder(message.query, { pooling: 'mean', normalize: true });
                const queryVector = Array.from(output.data);
                
                const results = embeddedCweDB.map(cwe => ({
                    id: cwe.id,
                    name: cwe.name,
                    score: cosineSimilarity(queryVector, cwe.vector)
                })).sort((a, b) => b.score - a.score);
                
                sendResponse({ success: true, results });
            } catch (error) {
                console.error("Semantic search error:", error);
                sendResponse({ success: false, error: error.toString() });
            }
        })();
        return true; // Keep channel open
    }
});
