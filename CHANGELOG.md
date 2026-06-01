# Changelog

All notable changes to the mytho.chat protocol specification.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The spec uses an internal `wire_version` byte tracked separately from this CHANGELOG (current: `0x01`).

## [0.2.0] — 2026-06-01

### Added
- Conformance & Construction Rationale section in `README.md` §11a with explicit MUST/MUST NOT/SHOULD/MAY clauses for the relay and the client.
- `docs/hkdf-labels.md` — canonical normative table of all HKDF `info` labels (domain separation).
- `docs/kat-vectors-format.md` — JSON schema for normative Known-Answer Test vectors.
- `vectors/` directory with seven KAT files (peerId derivation, AAD encoding, ISO 7816-4 padding, AEAD nonce derivation, delivery token, HKDF chain step, X3DH-PQ handshake).
- `scripts/generate-kat.mjs` — deterministic KAT vector generator.
- `wire-format.md` §11 — KAT vectors index.
- `ratchet-state-machine.md` §7 — formal deniability note (relay cannot forge; no third party can prove authorship).
- Implementation status banner in `README.md` Status block: declares the binary wire-format §3–§7 as planned for v1.0; current reference deployment uses a simplified JSON envelope.

### Changed
- `README.md` §5 (Cryptographic suite): pinned NIST Security Category 3 for ML-KEM-768 and ML-DSA-65; pinned `draft-irtf-cfrg-xchacha-03` for XChaCha20-Poly1305; added NIST SP 800-56C Rev. 2 as dual-input KDF normative reference; added PQXDH and X-Wing comparison; **clarified construction is PQ-only** (no classical leg) with rationale.
- `wire-format.md` §2 (Identifiers and constants): pinned `MAX_SKIP=2000`, `TTL_HARD_LIMIT=604800s (7d)`, `DELIVERY_TOKEN_LIFETIME=300s`, `MAX_MESSAGE_TEXT=16MiB`, `MAX_MESSAGE_MEDIA=64MiB`. Pinned `peerId` representation as raw 1952-byte ML-DSA-65 public key per FIPS 204 §7.
- `wire-format.md` §3: `chat_type ∈ {1, 2}` (group/room) marked RESERVED for v1.0; v0.2 receivers MUST reject with `MALFORMED`. Receivers MUST reject envelopes where `reserved != 0x00`.
- `wire-format.md` §4 (delivery_token): pinned `sender_peer_id` source as the authenticated WebSocket session (`AUTH` msg); pinned token lifetime ≤ 300s; HMAC output 32 bytes (no truncation); `server_pepper` ≥ 32 bytes from CSPRNG.
- `wire-format.md` §5 (SealedPayload): split into §5.1 (deterministic AEAD nonce via `HKDF-Expand(MK, "mytho/nonce/v1", 24)` — NOT on wire); §5.2 (byte-exact 38-byte AAD encoding); §5.3 (ISO/IEC 7816-4 plaintext padding); §5.4 (OTPK exhaustion explicit via `ratchet_flags.bit1`).
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
