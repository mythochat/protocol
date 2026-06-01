# HKDF Domain-Separation Labels

> Part of the mytho.chat protocol specification (Draft v0.2). Canonical normative reference for **all** HKDF `info` labels used in the protocol. Implementations MUST use these byte-exact ASCII strings; mismatch breaks interoperability silently.

---

## 1. Why a single table

`HKDF(salt, ikm, info, length)` produces independent outputs for the same `(salt, ikm)` when `info` differs. Reusing the same `info` for two different derivations is a key-confusion vulnerability. This document lists every `info` label authorized in the protocol — anything not here MUST NOT be used.

All labels are **ASCII**, no trailing newline, no padding. The encoding is the literal UTF-8 byte sequence of the string.

---

## 2. Canonical labels

| Context | `info` label (ASCII) | Length (bytes) | Output size | Defined in |
| --- | --- | --- | --- | --- |
| Handshake master secret | `mytho/handshake/v1` | 18 | 32 (RK_0) | `docs/ratchet-state-machine.md` §3 |
| Root key advance | `mytho/rk/v1` | 11 | 32 (RK_n+1) | `docs/ratchet-state-machine.md` §4 |
| Chain key advance | `mytho/ck/v1` | 11 | 32 (CK_n+1) | `docs/ratchet-state-machine.md` §4 |
| Message key derivation | `mytho/mk/v1` | 11 | 32 (MK_n) | `docs/ratchet-state-machine.md` §4 |
| AEAD nonce derivation | `mytho/nonce/v1` | 14 | 24 (XChaCha20 nonce) | `docs/wire-format.md` §5.1 |
| Delivery-token HMAC key | `mytho/delivery-token/v1` | 23 | 32 (HMAC-SHA-256 key) | `docs/wire-format.md` §4 |
| Sealed-sender peer hint | `mytho/sealed-sender/v1` | 22 | 16 (peer-hint envelope marker) | reserved for v1.0 |

## 3. Implementation example (pseudocode)

```
RK_n+1, CK_0 = HKDF-Extract-and-Expand(
    salt = RK_n,
    ikm  = kem_shared_secret,
    info = "mytho/rk/v1" || "mytho/ck/v1",   // two outputs, see §4
    L    = 32 + 32
)
```

**Two-output expansion**: when a single HKDF call must produce two keys (e.g., new Root Key + new Chain Key at a direction change), the canonical approach is `HKDF-Expand(..., info, 64)` and split the 64-byte output into two 32-byte halves. Implementations MUST NOT call HKDF twice with the same `(salt, ikm)`.

## 4. Forward compatibility

Labels are versioned (`/v1`). A protocol revision that needs to change a derivation MUST allocate a new label (`/v2`); MUST NOT reuse a `/v1` label with new semantics. KAT vectors are tagged with the label version.

## 5. Conformance

Any HKDF call within the protocol that does NOT appear in §2 is **non-conformant**. Reviewers MUST treat unknown labels as a spec violation. New labels require a normative spec PR with explicit purpose, output length, and KAT.

---

*Draft v0.2 — labels are stable for v0.x and v1.x compatibility; new labels added under `/v1` are forward-compatible.*
