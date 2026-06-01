#!/usr/bin/env node
/**
 * Verify all vectors in ../vectors/*.json conform to the JSON schema defined in
 * docs/kat-vectors-format.md. This is a structural + encoding sanity check, not
 * a cryptographic re-derivation (use generate-kat.mjs for byte-exact re-pinning).
 *
 * Checks per file:
 *   - all REQUIRED_FIELDS present
 *   - schema === "mytho.chat/kat/v1", wire_version === 1
 *   - generator.seed present (hex)
 *   - cases is a non-empty array; each case has label/inputs/outputs
 *   - every "*_hex" / "*_hex_first_32" / "*_hex_last_32" value is lowercase hex
 *   - every "<prefix>_length" equals (len of "<prefix>_hex") / 2 when the
 *     same-object full-hex sibling exists
 *
 * Exit code is non-zero if ANY file has ANY error.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, '../vectors');

const REQUIRED_FIELDS = ['schema', 'wire_version', 'primitive', 'spec_ref', 'generator', 'cases'];
const HEX_RE = /^[0-9a-f]*$/;
const isHexKey = (k) => k.endsWith('_hex') || k.endsWith('_hex_first_32') || k.endsWith('_hex_last_32');

let totalErrors = 0;

/**
 * Recursively validate hex strings and `<prefix>_hex` ↔ `<prefix>_length`
 * agreement within each object. `path` is a breadcrumb for error messages.
 * Returns the number of errors found; pushes messages onto `errs`.
 */
function validateNode(node, path, errs) {
  if (Array.isArray(node)) {
    node.forEach((item, i) => validateNode(item, `${path}[${i}]`, errs));
    return;
  }
  if (!node || typeof node !== 'object') return;

  for (const [k, val] of Object.entries(node)) {
    const here = `${path}.${k}`;
    if (isHexKey(k)) {
      if (typeof val !== 'string') {
        errs.push(`${here}: hex field must be a string, got ${typeof val}`);
      } else if (!HEX_RE.test(val)) {
        errs.push(`${here}: not lowercase hex ("${val.slice(0, 24)}${val.length > 24 ? '…' : ''}")`);
      }
    }
    if (k.endsWith('_length')) {
      const prefix = k.slice(0, -'_length'.length);
      const hexSibling = node[`${prefix}_hex`];
      if (typeof hexSibling === 'string' && HEX_RE.test(hexSibling)) {
        const expected = hexSibling.length / 2;
        if (val !== expected) {
          errs.push(`${here}: ${val} != ${prefix}_hex length/2 (${expected})`);
        }
      }
    }
    if (val && typeof val === 'object') validateNode(val, here, errs);
  }
}

const files = readdirSync(VECTORS_DIR).filter((f) => f.endsWith('.json')).sort();
if (files.length === 0) {
  console.error('✗ no vector files found in vectors/');
  process.exit(1);
}

for (const file of files) {
  const errs = []; // per-file error context (CANON: each file reports independently)
  let v;
  try {
    v = JSON.parse(readFileSync(resolve(VECTORS_DIR, file), 'utf8'));
  } catch (e) {
    console.error(`✗ ${file}: invalid JSON — ${e.message}`);
    totalErrors++;
    continue;
  }

  for (const field of REQUIRED_FIELDS) {
    if (!(field in v)) errs.push(`missing field "${field}"`);
  }
  if (v.schema !== 'mytho.chat/kat/v1') {
    errs.push(`schema is "${v.schema}", expected "mytho.chat/kat/v1"`);
  }
  if (v.wire_version !== 1) {
    errs.push(`wire_version is ${JSON.stringify(v.wire_version)}, expected 1`);
  }
  if (!v.generator || typeof v.generator.seed !== 'string' || v.generator.seed.length === 0) {
    errs.push('generator.seed missing or not a non-empty string');
  } else if (!HEX_RE.test(v.generator.seed)) {
    errs.push(`generator.seed is not lowercase hex ("${v.generator.seed.slice(0, 24)}…")`);
  }
  if (!Array.isArray(v.cases) || v.cases.length === 0) {
    errs.push('cases must be a non-empty array');
  } else {
    v.cases.forEach((c, i) => {
      if (!c.label || !c.inputs || !c.outputs) {
        errs.push(`case[${i}]: missing label/inputs/outputs`);
        return;
      }
      validateNode(c.inputs, `case[${i}].inputs`, errs);
      validateNode(c.outputs, `case[${i}].outputs`, errs);
    });
  }

  if (errs.length === 0) {
    console.log(`✓ ${file} (${v.cases.length} cases)`);
  } else {
    for (const e of errs) console.error(`✗ ${file}: ${e}`);
    totalErrors += errs.length;
  }
}

if (totalErrors > 0) {
  console.error(`\n${totalErrors} error(s) across ${files.length} file(s).`);
  process.exit(1);
}
console.log(`\nAll ${files.length} vectors conform to mytho.chat/kat/v1 schema.`);
