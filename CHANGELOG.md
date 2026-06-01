# Changelog

All notable changes to the mytho.chat protocol specification.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The spec uses an internal `wire_version` byte tracked separately from this CHANGELOG (current: `0x01`).

## [1.0.1] — 2026-06-01

Documentation-hardening pass over the v1.0 specification. No wire-format or cryptographic-construction changes: `wire_version` stays `0x01` and all v1.0 KAT vectors remain valid. The fixes reconcile prose with the KATs and pin previously under-specified details.

### Fixed
- **HKDF terminology** aligned between prose and KATs: every derivation is now stated as full HKDF (RFC 5869, **Extract-then-Expand**, empty salt = 32 zero bytes); removed the malformed `HKDF-Expand(MK, …)` / concatenated-`info` phrasing in `docs/hkdf-labels.md` §3 and `README.md` §11a.
- **HKDF labels reconciled** (`docs/hkdf-labels.md`): `mytho/delivery-token/v1` and `mytho/sealed-sender/v1` marked RESERVED / OPTIONAL (allocated-but-not-active, not forbidden); anti-reuse rule restated over the full `(salt, IKM, info)` triple so distinct labels are recognized as the correct domain-separation mechanism.
- **`delivery_token`** `nonce` (16 bytes) and `exp` (`u64_be`, 8 bytes) sizes/endianness pinned; HMAC-SHA-256 output is the full 32 bytes (no truncation).
- **`SealedPayload`** conditional-length rules pinned: `kem_ct_len` (0 or 1088 by `ratchet_flags.bit0`) and `sender_sig_len` (0 in deniable mode, else the ML-DSA-65 signature length) are always present and MUST be rejected on mismatch (`MALFORMED`).
- **PCS trigger** made a MUST (first message of every new sending chain carries a fresh `kem_ciphertext` with `ratchet_flags.bit0 = 1`); added an explicit fail-closed `Failed` state to the ratchet state machine.
- **`peerId`** description corrected: `peerId` = SHA-256 (32 bytes) **of** the raw 1952-byte ML-DSA-65 public key (the key is the hash input, not the peerId itself).
- **Threat model** expanded (`README.md` §3) with malicious/compromised issuer, relay DoS (partial non-goal), and downgrade/replay adversaries; sealed-sender scope clarified (relay knows the authenticated **session** peer; the envelope/persistence omission plus no-correlation persistence is the guarantee).
- **Padding-bin** text/media disambiguation: the relay validates membership in the union set and caps `sealed_payload_len`, but does not discriminate content type (no routing-envelope content-type field).
- **ES256 reference** fixed: ES256 is RFC 7518 (JWA); RFC 7515 is JWS.
- **KATs:** five new vector files added (AEAD roundtrip, multi-step ratchet, skipped-keys, ML-DSA sign/verify, ML-KEM decapsulate); `notes` aligned with the Extract-then-Expand wording; `verify-kat` hardened; noble dependency versions pinned.

## [1.0.0] — 2026-06-01

First stable specification release. The protocol is in production. The
`wire_version` byte is fixed at `0x01` for the entire v1.x line; breaking
changes will bump both the spec major version and `wire_version` together.



### Added
- Conformance & Construction Rationale section in `README.md` §11a with explicit MUST/MUST NOT/SHOULD/MAY clauses for the relay and the client.
- `docs/hkdf-labels.md` — canonical normative table of all HKDF `info` labels (domain separation).
- `docs/kat-vectors-format.md` — JSON schema for normative Known-Answer Test vectors.
- `vectors/` directory with seven KAT files (peerId derivation, AAD encoding, ISO 7816-4 padding, AEAD nonce derivation, delivery token, HKDF chain step, X3DH-PQ handshake).
- `scripts/generate-kat.mjs` — deterministic KAT vector generator.
- `wire-format.md` §11 — KAT vectors index.
- `ratchet-state-machine.md` §7 — formal deniability note (relay cannot forge; no third party can prove authorship).
- Conformance note in `README.md` Status block: the binary wire-format §3–§7 (`delivery_token`, `padding_bin` enforcement, `wire_version` validation, sealed-sender envelope) is the conformance target for v1.0 implementations.

### Changed
- `README.md` §5 (Cryptographic suite): pinned NIST Security Category 3 for ML-KEM-768 and ML-DSA-65; pinned `draft-irtf-cfrg-xchacha-03` for XChaCha20-Poly1305; added NIST SP 800-56C Rev. 2 as dual-input KDF normative reference; added PQXDH and X-Wing comparison; **clarified construction is PQ-only** (no classical leg) with rationale.
- `wire-format.md` §2 (Identifiers and constants): pinned `MAX_SKIP=2000`, `TTL_HARD_LIMIT=604800s (7d)`, `DELIVERY_TOKEN_LIFETIME=300s`, `MAX_MESSAGE_TEXT=16MiB`, `MAX_MESSAGE_MEDIA=64MiB`. Pinned `peerId` = SHA-256 (32 bytes) of the raw 1952-byte ML-DSA-65 public key (the 1952-byte key is the SHA-256 input, not the peerId itself), per FIPS 204 §7.
- `wire-format.md` §3: `chat_type ∈ {1, 2}` (group/room) marked RESERVED for a future revision; v1.0 receivers MUST reject with `MALFORMED`. Receivers MUST reject envelopes where `reserved != 0x00`.
- `wire-format.md` §4 (delivery_token): pinned `sender_peer_id` source as the authenticated WebSocket session (`AUTH` msg); pinned token lifetime ≤ 300s; HMAC output 32 bytes (no truncation); `server_pepper` ≥ 32 bytes from CSPRNG.
- `wire-format.md` §5 (SealedPayload): split into §5.1 (deterministic AEAD nonce via `HKDF(salt="", IKM=MK, info="mytho/nonce/v1", L=24)` — NOT on wire); §5.2 (byte-exact 38-byte AAD encoding); §5.3 (ISO/IEC 7816-4 plaintext padding); §5.4 (OTPK exhaustion explicit via `ratchet_flags.bit1`).
- `ratchet-state-machine.md` §3: cited NIST SP 800-56C for dual-input KDF; cited PQXDH for structural comparison (PQ-only departure from); cross-referenced wire-format §5.4 for OTPK signaling.
- `ratchet-state-machine.md` §4: cross-reference to `docs/hkdf-labels.md` as canonical normative source.
- `ratchet-state-machine.md` §6: `MAX_SKIP=2000` pinned (was `e.g.`).
- `README.md` §13 (Roadmap): KAT vectors checked off; "Hybrid double-ratchet" renamed to "Post-quantum double-ratchet" (no classical leg).
- `README.md` §14 (References): expanded with direct URLs to NIST FIPS, Signal PQXDH, X-Wing IETF draft, NIST SP 800-56C, and Double Ratchet spec.

### Fixed
- **Contradiction** between `README.md` §5 calling the construction "hybrid" and `ratchet-state-machine.md` §1 stating "rather than classical DH". Resolved: PQ-only is the design choice, explicitly documented in §5.
- **Ambiguity** in AEAD nonce — was unspecified, now deterministically derived from `MK`, eliminating nonce-reuse risk.
- **Ambiguity** in AAD encoding — was string concatenation without lengths, now byte-exact 38-byte encoding with KAT.
- **Ambiguity** in pre-AEAD padding — algorithm was unspecified, now pinned as ISO/IEC 7816-4.
- **Silent degradation** of OTPK exhaustion — now explicitly signaled via `ratchet_flags.bit1`; receivers MAY reject.

## [0.1.0] — 2026-05-30

Initial public draft. Sealed-sender relay over PQ-KEM + PQ-DSA + AEAD + Double Ratchet, with ephemeral TTL and external identity issuer.
