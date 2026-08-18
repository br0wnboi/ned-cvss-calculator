import fs from 'fs';
import path from 'path';
import { pipeline, env } from '@huggingface/transformers';

// Path configuration
const DATA_DIR = path.resolve('../data');
const CWE_DATA_PATH = path.join(DATA_DIR, 'cwe-data.json');
const OUTPUT_PATH = path.join(DATA_DIR, 'cwe-embeddings.json');

// Configuration for local caching
env.localModelPath = './models';
env.allowLocalModels = true;
env.allowRemoteModels = false;

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
    console.log("Loading Snowflake/snowflake-arctic-embed-xs model...");
    // Initialize the feature extraction pipeline
    const embedder = await pipeline('feature-extraction', 'Snowflake/snowflake-arctic-embed-xs', {
        quantized: true
    });
    
    console.log("Generating embeddings. This may take a minute...");
    
    const metadata = [];
    const allVectors = [];
    
    for (let i = 0; i < cweData.length; i++) {
        const cwe = cweData[i];
        const chunks = [];
        
        chunks.push(`${cwe.name}: ${cwe.description || ''}`);
        
        if (cwe.extended_description) {
            const paragraphs = cwe.extended_description.split(/\n\s*\n/).filter(p => p.trim().length > 20);
            paragraphs.forEach(p => chunks.push(p.trim()));
        }

        if (cwe.alternate_terms) {
            chunks.push(`Also known as: ${cwe.alternate_terms}`);
        }
        
        for (const textToEmbed of chunks) {
            // Snowflake arctic-embed-xs requires prefix for queries, but NOT documents!
            const output = await embedder(textToEmbed, { pooling: 'mean', normalize: true });
            
            // output.data is a Float32Array
            allVectors.push(output.data);
            
            metadata.push({
                id: cwe.id,
                name: cwe.name
            });
        }

        if ((i + 1) % 50 === 0) {
            console.log(`Progress: ${i + 1} / ${cweData.length}`);
        }
    }
    
    console.log(`Done processing ${allVectors.length} items. Saving to Binary and JSON Meta...`);
    
    // Save Metadata
    fs.writeFileSync('../data/cwe-embeddings-meta.json', JSON.stringify(metadata, null, 0));
    
    // Save Binary Float32Array
    // Since all vectors have 384 dimensions
    const totalLength = allVectors.length * 384;
    const floatBuffer = new Float32Array(totalLength);
    
    let offset = 0;
    for (const vec of allVectors) {
        floatBuffer.set(vec, offset);
        offset += vec.length;
    }
    
    fs.writeFileSync('../data/cwe-embeddings.bin', Buffer.from(floatBuffer.buffer));
    console.log("Successfully saved binary embeddings and metadata.");
}

generateEmbeddings().catch(err => {
    console.error("Error during embedding generation:", err);
    process.exit(1);
});
