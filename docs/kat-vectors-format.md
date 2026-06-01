# KAT Vectors — JSON Schema

> Part of the mytho.chat protocol specification (v1.0). Defines the JSON schema for normative Known-Answer Test vectors in `vectors/*.json`. Vectors are deterministic, regeneratable from the source script (`scripts/generate-kat.mjs`), and pin byte-exact encodings.

---

## 1. File naming

Each KAT JSON file is named after the operation it pins:

- `vectors/peerid-derivation.json`
- `vectors/aad-encoding.json`
- `vectors/padding-7816.json`
- `vectors/aead-nonce-derivation.json`
- `vectors/delivery-token.json`
- `vectors/hkdf-chain-step.json`
- `vectors/handshake-x3dh-pq.json`

## 2. Common schema

```json
{
  "schema": "mytho.chat/kat/v1",
  "wire_version": 1,
  "primitive": "string identifying the operation (e.g. 'peerid-derivation')",
  "spec_ref": "docs/wire-format.md §2",
  "generator": {
    "script": "scripts/generate-kat.mjs",
    "noble_versions": {
      "@noble/post-quantum": "x.y.z",
      "@noble/hashes": "x.y.z",
      "@noble/ciphers": "x.y.z"
    },
    "seed": "deterministic seed used (hex)",
    "generated_at": "RFC 3339 timestamp at generation"
  },
  "cases": [
    {
      "label": "human-readable description",
      "inputs": { "field": "hex or base64url or literal as per primitive" },
      "outputs": { "field": "expected hex or base64url" },
      "notes": "optional"
    }
  ]
}
```

## 3. Encoding conventions

- **Binary fields**: lowercase hex without `0x` prefix unless noted. Example: `"aabbccdd"`.
- **Integers in inputs**: JSON numbers when ≤ 2^53; otherwise decimal string with `"_int"` suffix on the field name.
- **Big-endian** for all integer-to-bytes operations in `inputs`/`outputs`.
- **All ASCII labels** (HKDF `info`, etc.) appear as JSON strings; the test harness MUST encode them as UTF-8 bytes byte-for-byte.

## 4. Conformance

A conforming implementation MUST pass **all** cases in each KAT file for the targeted `wire_version`. Failure on a single case is a non-conformance.

## 5. Regeneration

```bash
cd mythochat-protocol
node scripts/generate-kat.mjs
```

The script is **deterministic** given the pinned `seed`. Output diffs between runs indicate either (a) a primitive library update (intentional — re-pin), or (b) a non-determinism bug (regression).

---

*v1.0*
