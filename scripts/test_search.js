import fs from 'fs';
import { pipeline } from '@xenova/transformers';

function cosineSimilarity(vecA, vecB) {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < vecA.length; i++) {
        dotProduct += vecA[i] * vecB[i];
        normA += vecA[i] * vecA[i];
        normB += vecB[i] * vecB[i];
    }
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

async function main() {
    const db = JSON.parse(fs.readFileSync('../data/cwe-embeddings.json', 'utf8'));
    const embedder = await pipeline('feature-extraction', 'Xenova/bge-small-en-v1.5', { quantized: true });
    
    const query = "bypassed login with special characters";
    const queryStr = "Represent this sentence for searching relevant passages: " + query;
    const output = await embedder(queryStr, { pooling: 'mean', normalize: true });
    const queryVector = Array.from(output.data);
    
    const scoresMap = new Map();
    for (const item of db) {
        const score = cosineSimilarity(queryVector, item.vector);
        if (!scoresMap.has(item.id) || score > scoresMap.get(item.id)) {
            scoresMap.set(item.id, score);
        }
    }
    
    const results = Array.from(scoresMap.entries())
        .map(([id, score]) => ({ id, score }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 5);
        
    console.log(results);
}
main();
