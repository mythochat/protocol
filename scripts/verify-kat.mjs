#!/usr/bin/env node
/**
 * Verify all vectors in ../vectors/*.json conform to the JSON schema
 * defined in docs/kat-vectors-format.md. Sanity check, not cryptographic
 * re-derivation (use generate-kat.mjs for that).
 */
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '../vectors');

const REQUIRED_FIELDS = ['schema', 'wire_version', 'primitive', 'spec_ref', 'generator', 'cases'];
let errors = 0;

for (const file of readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json'))) {
  const v = JSON.parse(readFileSync(resolve(VECTORS_DIR, file), 'utf8'));
  for (const field of REQUIRED_FIELDS) {
    if (!(field in v)) {
      console.error(`✗ ${file}: missing field "${field}"`);
      errors++;
    }
  }
  if (v.schema !== 'mytho.chat/kat/v1') {
    console.error(`✗ ${file}: schema is "${v.schema}", expected "mytho.chat/kat/v1"`);
    errors++;
  }
  if (!Array.isArray(v.cases) || v.cases.length === 0) {
    console.error(`✗ ${file}: cases must be a non-empty array`);
    errors++;
  }
  for (const [i, c] of (v.cases || []).entries()) {
    if (!c.label || !c.inputs || !c.outputs) {
      console.error(`✗ ${file} case[${i}]: missing label/inputs/outputs`);
      errors++;
    }
  }
  if (errors === 0) console.log(`✓ ${file} (${v.cases.length} cases)`);
}

if (errors > 0) {
  console.error(`\n${errors} schema error(s).`);
  process.exit(1);
}
console.log('\nAll vectors conform to mytho.chat/kat/v1 schema.');
