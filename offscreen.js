import { pipeline, env } from './lib/transformers/transformers.min.js';

// Note: For testing, we are allowing remote models. 
// For production, we will bundle the models locally to be 100% offline.
if (env) {
    env.allowLocalModels = false;
    env.allowRemoteModels = true;
    env.backends.onnx.wasm.numThreads = 1;
}

let embedder = null;

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
    if (embeddedCweDB.length === 0) {
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Loading CWE database...' });
        const res = await fetch(chrome.runtime.getURL('data/cwe-embeddings.json'));
        embeddedCweDB = await res.json();
    }

    if (!embedder) {
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Loading ML Model (~25MB)...' });
        embedder = await pipeline('feature-extraction', 'Xenova/bge-small-en-v1.5', {
            quantized: true,
        });
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Ready' });
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'SEMANTIC_SEARCH') {
        (async () => {
            try {
                await initEmbedder();
                
                // BGE-small requires queries to be prefixed for retrieval tasks
                const queryStr = "Represent this sentence for searching relevant passages: " + message.query;
                const output = await embedder(queryStr, { pooling: 'mean', normalize: true });
                const queryVector = Array.from(output.data);
                
                const scoresMap = new Map();
                const namesMap = new Map();

                // Because cwe-embeddings.json now has multiple vectors per ID, keep the max score
                for (const item of embeddedCweDB) {
                    const score = cosineSimilarity(queryVector, item.vector);
                    if (!scoresMap.has(item.id) || score > scoresMap.get(item.id)) {
                        scoresMap.set(item.id, score);
                        namesMap.set(item.id, item.name);
                    }
                }
                
                const results = Array.from(scoresMap.entries()).map(([id, score]) => ({
                    id: id,
                    name: namesMap.get(id),
                    score: score
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
