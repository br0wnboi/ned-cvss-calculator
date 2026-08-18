import fs from 'fs';
const db = JSON.parse(fs.readFileSync('../data/cwe-embeddings.json', 'utf8'));
const cwe79 = db.filter(item => item.id === 'CWE-79' || item.id === '79');
console.log(`Found ${cwe79.length} chunks for CWE-79.`);
