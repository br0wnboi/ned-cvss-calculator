import { pipeline, env } from './lib/transformers/transformers.min.js';

// Note: For testing, we are allowing remote models. 
// For production, we will bundle the models locally to be 100% offline.
if (env) {
    env.allowLocalModels = false;
    env.allowRemoteModels = true;
    env.backends.onnx.wasm.numThreads = 1;
    env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('lib/transformers/');
}

let embedder = null;
let embeddedCweMeta = [];
let embeddedCweVectors = null;

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
    if (embeddedCweMeta.length === 0) {
        console.time("Load Binary DB & Meta");
        
        const metaRes = await fetch(chrome.runtime.getURL('data/cwe-embeddings-meta.json'));
        embeddedCweMeta = await metaRes.json();
        
        const binRes = await fetch(chrome.runtime.getURL('data/cwe-embeddings.bin'));
        const arrayBuffer = await binRes.arrayBuffer();
        embeddedCweVectors = new Float32Array(arrayBuffer);
        
        console.timeEnd("Load Binary DB & Meta");
    }

    if (!embedder) {
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Loading ML Model (~25MB)...' });
        console.time("Load Embedder (Pipeline + WASM init)");
        embedder = await pipeline('feature-extraction', 'Snowflake/snowflake-arctic-embed-xs', {
            quantized: true,
        });
        console.timeEnd("Load Embedder (Pipeline + WASM init)");
        chrome.runtime.sendMessage({ type: 'SEMANTIC_STATUS', status: 'Ready' });
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'SEMANTIC_SEARCH') {
        (async () => {
            try {
                console.time("Total Search Request");
                await initEmbedder();
                
                // BGE-small requires queries to be prefixed for retrieval tasks
                const queryStr = "Represent this sentence for searching relevant passages: " + message.query;
                
                console.time("Model Inference");
                const output = await embedder(queryStr, { pooling: 'mean', normalize: true });
                const queryVector = Array.from(output.data);
                console.timeEnd("Model Inference");
                
                console.time("Cosine Similarity Sweep");
                const scoresMap = new Map();
                const namesMap = new Map();

                const vecLength = queryVector.length;

                for (let i = 0; i < embeddedCweMeta.length; i++) {
                    const meta = embeddedCweMeta[i];
                    const offset = i * vecLength;
                    const chunkVector = embeddedCweVectors.subarray(offset, offset + vecLength);
                    
                    const score = cosineSimilarity(queryVector, chunkVector);
                    
                    if (!scoresMap.has(meta.id) || score > scoresMap.get(meta.id)) {
                        scoresMap.set(meta.id, score);
                        namesMap.set(meta.id, meta.name);
                    }
                }
                
                const results = Array.from(scoresMap.entries()).map(([id, score]) => ({
                    id: id,
                    name: namesMap.get(id),
                    score: score
                })).sort((a, b) => b.score - a.score);
                
                console.timeEnd("Cosine Similarity Sweep");
                console.timeEnd("Total Search Request");
                sendResponse({ success: true, results });
            } catch (error) {
                console.error("Semantic search error:", error);
                sendResponse({ success: false, error: error.toString() });
            }
        })();
        return true; // Keep channel open
    }
});
