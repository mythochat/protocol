# Security Review — mytho.chat Protocol v1.0

> **What this is.** A structured, adversarial **AI-assisted security review** of the
> mytho.chat protocol specification and its Known-Answer-Test (KAT) tooling,
> conducted on 2026-06-01. Six independent review dimensions were each analyzed
> by a separate adversarial reviewer, findings were remediated, and every
> dimension was re-reviewed against the corrected text until no blocking finding
> remained. All cryptographic test vectors were independently re-derived from
> their pinned inputs.
>
> **What this is NOT.** This is **not** a formal cryptographic audit by an
> accredited third-party security firm. It carries **no legal warranty or
> liability**. It was produced by an automated language-model review process,
> which can err. Before relying on this protocol for high-assurance or
> safety-critical deployments, commission an **independent human-expert
> cryptographic audit** (see `SECURITY.md` §16). Treat the security properties in
> `README.md` §11 as **design targets**, not certified guarantees.

---

## 1. Scope

**In scope (this open-source repository):**

- The protocol specification: `README.md`, `docs/wire-format.md`,
  `docs/ratchet-state-machine.md`, `docs/hkdf-labels.md`,
  `docs/kat-vectors-format.md`, `SECURITY.md`, `CONTRIBUTING.md`.
- The deterministic KAT tooling and vectors: `scripts/generate-kat.mjs`,
  `scripts/verify-kat.mjs`, `vectors/*.json`.

**Out of scope:** any production deployment, relay server, or client
implementation. Those are not part of this repository; this review makes no
claim about them.

## 2. Methodology

The review was run as a fan-out / remediate / re-verify loop:

1. **Six independent dimensions**, each examined by a separate adversarial
   reviewer with no shared state:
   1. Cryptographic correctness & primitive usage
   2. Wire-format precision (byte-exact, zero inter-implementer ambiguity)
   3. Ratchet & handshake security (FS / PCS / deniability)
   4. Threat model (completeness, honesty, conformance language)
   5. KAT tooling code (determinism, correctness, vector completeness)
   6. Internal consistency & references
2. **Remediation** of every blocking finding, applied to the specification.
3. **Adversarial re-review** of each dimension against the corrected text.
4. **Independent KAT re-derivation**: all 12 vectors recomputed from their
   pinned inputs using the pinned `@noble` library versions and compared
   byte-for-byte.

## 3. Dimensions and scores

| # | Dimension | Initial | Final |
|---|---|---|---|
| 1 | Cryptographic correctness & primitives | 9/10 | **10/10** |
| 2 | Wire-format precision | 6/10 | **10/10** |
| 3 | Ratchet & handshake security | 7/10 | **10/10** |
| 4 | Threat model | 8/10 | **10/10** |
| 5 | KAT tooling code | 6/10 | **10/10** |
| 6 | Internal consistency & references | 6/10 | **10/10** |

## 4. Findings and resolutions

All findings below were **resolved** and confirmed on adversarial re-review.

### Dimension 1 — Cryptographic correctness
- **HKDF terminology vs. vectors.** The prose described several derivations as
  `HKDF-Expand(MK, …)`, but the vectors (correctly) compute full HKDF
  (Extract-then-Expand, RFC 5869, empty salt = 32 zero bytes). Prose aligned to
  the vectors across `wire-format.md` §5.1, `ratchet-state-machine.md` §3–§4,
  `README.md` §11a, `hkdf-labels.md` §1a/§3, and the vector `notes`. Primitive
  sizes (ML-KEM-768 ct = 1088 B, ML-DSA-65 pk = 1952 B / sig = 3309 B), the
  dual-input handshake KDF, the 38-byte AAD, and ISO/IEC 7816-4 padding were all
  verified correct.

### Dimension 2 — Wire-format precision
- **`delivery_token` sizes/endianness** pinned in §4: `nonce` = 16 B,
  `exp` = `u64_be` (8 B), `data` = 88 B, `mac` = 32 B (no truncation), matching
  `vectors/delivery-token.json`.
- **Conditional length fields** pinned in §5: `kem_ct_len` (0 or 1088 by
  `ratchet_flags.bit0`) and `sender_sig_len` (0 in deniable mode, else the
  ML-DSA-65 signature length) are always serialized, with `MALFORMED` on
  mismatch.
- **`padding_bin` field width** corrected from `u16` to `u32` in the §3 struct
  (the maximum media bin 262144 does not fit in `u16`).
- **Text/media bin disambiguation** in §7: the relay validates membership in the
  union set and caps `sealed_payload_len`; it does not discriminate content type.

### Dimension 3 — Ratchet & handshake security
- **Post-compromise-security trigger made normative (MUST):** the first message
  of every new sending chain MUST carry a fresh `kem_ciphertext` with
  `ratchet_flags.bit0 = 1`; a receiver observing a direction change without it
  MUST reject. This closes a silent-PCS-failure path.
- **KEM-step KDF corrected** to `PRK = HKDF-Extract(salt=RK_n, IKM=kem_ss)` then
  `HKDF-Expand(PRK, "mytho/rk/v1", 64)` (split), removing a malformed
  `HKDF-Expand(salt=…)` pseudocode.
- **Domain separation clarified:** `CK_0` is the second half of the
  `mytho/rk/v1` output; `mytho/ck/v1` is used only in the symmetric step.
- **Anti-reuse rule corrected** to the full `(salt, IKM, info)` triple.
- **Explicit `Failed` state** added to the state machine (fail-closed on
  signature/decapsulation failure, ratchet error, replay, or flag-policy
  rejection).

### Dimension 4 — Threat model
- **Malicious/compromised issuer** added: can forge session tokens but holds no
  message keys — E2E confidentiality and integrity survive.
- **Relay availability (DoS)** added as a partial non-goal (rate-limit / quota /
  PoW mitigations stated).
- **Downgrade / replay** adversary stated (fatal `BAD_VERSION`, single-use
  delivery-token nonce, message-key erasure).
- **Sealed-sender scope clarified honestly**: the relay knows the authenticated
  *session* peer; sealed-sender removes the sender from the routing envelope and
  from persistence, and the no-correlation-persistence MUST is the guarantee.

### Dimension 5 — KAT tooling
- Vector `notes` aligned to Extract-then-Expand; empty salt documented in inputs.
- `@noble` versions pinned exactly; resolved versions recorded per vector.
- `verify-kat.mjs` hardened (hex/length/`wire_version`/schema validation,
  per-file error isolation, non-zero exit on failure).
- Dead `randomBytes` import removed.
- **Five new vectors added** for completeness: AEAD encrypt+decrypt roundtrip,
  multi-step symmetric ratchet, out-of-order skipped keys, ML-DSA-65
  sign/verify (with tampered-message rejection), and ML-KEM-768
  encapsulate/decapsulate shared-secret equality.

### Dimension 6 — Consistency & references
- Residual "draft/roadmap" framing removed (`wire-format.md` §10 now states
  `wire_version = 0x01` is stable for v1.x).
- `peerId` corrected throughout to "SHA-256 (32 B) **of** the 1952-byte ML-DSA-65
  public key".
- Orphan HKDF labels reconciled (`mytho/delivery-token/v1` and
  `mytho/sealed-sender/v1` marked RESERVED / OPTIONAL; `mytho/mk/v1` documented
  in the §4 graph).
- ES256 reference corrected (RFC 7518 for the algorithm; RFC 7515 is JWS).
- KAT vector index (12 files) consistent across `wire-format.md` §11 and
  `kat-vectors-format.md` §1; all pinned constants consistent cross-document.

## 5. Cryptographic verification summary

All 12 KAT vectors were independently re-derived from their pinned inputs and
matched byte-for-byte, including:

- `peerId = SHA-256(pk)` for two ML-DSA-65 keypairs.
- The 38-byte AAD encoding for three field combinations.
- ISO/IEC 7816-4 padding (empty / partial-fit / exact-fit + extra block).
- Deterministic AEAD nonce via `HKDF(salt="", IKM=MK, "mytho/nonce/v1", 24)`.
- The delivery-token HMAC over the 88-byte `data` layout.
- KEM-step (`RK' ‖ CK_0`) and symmetric chain steps.
- The PQ-only X3DH-PQ handshake → `SK`.
- AEAD roundtrip (decryption recovers the plaintext; tampered AAD is rejected).
- ML-DSA-65 sign/verify (and tampered-message rejection).
- ML-KEM-768 decapsulation equals the encapsulated shared secret.

`scripts/verify-kat.mjs` validates the schema of all 12 vectors and regeneration
is byte-deterministic.

## 6. Disclaimer & limitations

- This is an **AI-assisted review**, not an accredited third-party audit. It
  has no legal weight and no warranty.
- The security properties hold only under the assumptions in `README.md` §11:
  a correct client implementation, sound underlying primitives (ML-KEM-768,
  ML-DSA-65, XChaCha20-Poly1305, HKDF-SHA-256), and an uncompromised endpoint
  device.
- The review covers the **specification and its test vectors**, not any
  implementation. Specification correctness does not imply implementation
  correctness; implementers remain responsible for constant-time execution,
  zeroization, RNG sourcing, and the other hardening items in `SECURITY.md`.
- Out-of-scope threats remain out of scope (endpoint compromise, network
  timing/volume analysis, recovery of expired messages, simultaneous compromise
  of relay and issuer).
- A formal independent cryptographic audit remains **recommended and not yet
  performed** (`SECURITY.md` §16).

## 7. Conclusion

After remediation, all six review dimensions reached the maximum internal score,
with every blocking finding resolved and confirmed on adversarial re-review, and
all 12 KAT vectors independently re-derived. The v1.0 specification is internally
consistent, byte-precise, and faithful to its stated cryptographic constructions.

This raises confidence in the **specification's design**. It does not replace an
independent human-expert audit of a deployed implementation, which remains the
appropriate next step before high-assurance reliance.

---

*Review date: 2026-06-01 · Method: multi-dimension adversarial AI-assisted review
with independent KAT re-derivation · Target: mytho.chat protocol specification
v1.0 (this repository).*
