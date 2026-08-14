import fs from 'fs';
import path from 'path';
import { pipeline, env } from '@xenova/transformers';

// Path configuration
const DATA_DIR = path.resolve('../data');
const CWE_DATA_PATH = path.join(DATA_DIR, 'cwe-data.json');
const OUTPUT_PATH = path.join(DATA_DIR, 'cwe-embeddings.json');

// Configuration for local caching
env.localModelPath = './models';
env.cacheDir = './models';

async function generateEmbeddings() {
    console.log("Loading CWE database...");
    const rawData = fs.readFileSync(CWE_DATA_PATH, 'utf8');
    const parsed = JSON.parse(rawData);
    
    // Support either an array directly or { entries: [...] }
    const cweData = Array.isArray(parsed) ? parsed : (parsed.entries || []);
    
    if (cweData.length === 0) {
        console.error("No CWE data found!");
        process.exit(1);
    }
    console.log(`Found ${cweData.length} weaknesses.`);

    console.log("Loading Xenova/bge-small-en-v1.5 model...");
    // Initialize the feature extraction pipeline
    const embedder = await pipeline('feature-extraction', 'Xenova/bge-small-en-v1.5', {
        quantized: true
    });
    
    console.log("Generating embeddings. This may take a minute...");
    const embeddedCweDB = [];
    
    for (let i = 0; i < cweData.length; i++) {
        const cwe = cweData[i];
        const chunks = [];
        
        // Chunk 1: Core definition
        chunks.push(`${cwe.name}: ${cwe.description || ''}`);
        
        // Chunk 2+ : Extended descriptions split by paragraphs
        if (cwe.extended_description) {
            // Split by double newlines or similar paragraph breaks
            const paragraphs = cwe.extended_description.split(/\n\s*\n/).filter(p => p.trim().length > 20);
            paragraphs.forEach(p => chunks.push(p.trim()));
        }

        // Chunk N : Alternate terms
        if (cwe.alternate_terms) {
            chunks.push(`Also known as: ${cwe.alternate_terms}`);
        }
        
        for (const textToEmbed of chunks) {
            // Compute the embedding
            const output = await embedder(textToEmbed, { pooling: 'mean', normalize: true });
            
            // Truncate to 5 decimal places to save massive amounts of space
            const vector = Array.from(output.data).map(v => Number(v.toFixed(5)));

            embeddedCweDB.push({
                id: cwe.id,
                name: cwe.name,
                vector: vector
            });
        }

        if ((i + 1) % 50 === 0) {
            console.log(`Progress: ${i + 1} / ${cweData.length}`);
        }
    }
    
    console.log(`Done processing ${embeddedCweDB.length} items. Saving to JSON...`);
    fs.writeFileSync(OUTPUT_PATH, JSON.stringify(embeddedCweDB));
    
    console.log(`Successfully saved to: ${OUTPUT_PATH}`);
}

generateEmbeddings().catch(err => {
    console.error("Error during embedding generation:", err);
    process.exit(1);
});
