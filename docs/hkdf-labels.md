# HKDF Domain-Separation Labels

> Part of the mytho.chat protocol specification (v1.0). Canonical normative reference for **all** HKDF `info` labels used in the protocol. Implementations MUST use these byte-exact ASCII strings; mismatch breaks interoperability silently.

---

## 1. Why a single table

`HKDF(salt, ikm, info, length)` produces independent outputs for the same `(salt, ikm)` when `info` differs. Reusing the same `info` for two different derivations is a key-confusion vulnerability. This document lists every `info` label authorized in the protocol — anything in §2 (including the labels marked RESERVED / OPTIONAL) is allocated; any label **not** listed in §2 MUST NOT be used.

All labels are **ASCII**, no trailing newline, no padding. The encoding is the literal UTF-8 byte sequence of the string.

---

## 1a. HKDF construction

Every key derivation in this protocol uses **full HKDF** per [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869): the **Extract-then-Expand** composition.

```
HKDF(salt, IKM, info, L) = HKDF-Expand( HKDF-Extract(salt, IKM), info, L )
```

`HKDF-Extract(salt, IKM)` returns a pseudorandom key (`PRK`); `HKDF-Expand(PRK, info, L)` stretches it to `L` octets under the domain-separation label `info`. The hash is SHA-256 throughout (`HashLen = 32`).

When a derivation has **no natural salt**, the salt is the **empty string**. Per RFC 5869 §2.2 an absent salt is treated as `HashLen` zero bytes — i.e. **32 zero bytes** for SHA-256. The only derivation in this protocol with a natural (non-empty) salt is the KEM root step (§3), whose salt is the current Root Key `RK_n`.

This document therefore never writes `HKDF-Expand(MK, …)` as if a key were the `PRK`; a key is always the `IKM` of a full HKDF call, e.g. `HKDF(salt="", IKM=MK, info="mytho/nonce/v1", L=24)`.

---

## 2. Canonical labels

| Context | `info` label (ASCII) | Length (bytes) | Output size | Defined in |
| --- | --- | --- | --- | --- |
| Handshake master secret | `mytho/handshake/v1` | 18 | 32 (RK_0) | `docs/ratchet-state-machine.md` §3 |
| Root key advance | `mytho/rk/v1` | 11 | 32 (RK_n+1) | `docs/ratchet-state-machine.md` §4 |
| Chain key advance | `mytho/ck/v1` | 11 | 32 (CK_n+1) | `docs/ratchet-state-machine.md` §4 |
| Message key derivation | `mytho/mk/v1` | 11 | 32 (MK_n) | `docs/ratchet-state-machine.md` §4 |
| AEAD nonce derivation | `mytho/nonce/v1` | 14 | 24 (XChaCha20 nonce) | `docs/wire-format.md` §5.1 |
| Delivery-token HMAC key | `mytho/delivery-token/v1` | 23 | 32 (HMAC-SHA-256 key) | RESERVED / OPTIONAL — the reference construction uses `server_pepper` directly as the HMAC key; deployments MAY derive it via this label. Not used by the reference KATs. |
| Sealed-sender peer hint | `mytho/sealed-sender/v1` | 22 | 16 (peer-hint envelope marker) | RESERVED for a future revision |

## 3. Implementation example (pseudocode)

**KEM root step** — the only derivation with a natural (non-empty) salt: the salt is the current Root Key `RK_n`, the IKM is the KEM shared secret, and a single 64-byte expansion under `mytho/rk/v1` is split into the new Root Key and the seed chain key:

```
PRK          = HKDF-Extract(salt=RK_n, IKM=kem_shared_secret)
RK' || CK_0  = HKDF-Expand(PRK, info="mytho/rk/v1", L=64)   // split 32 || 32
```

Only `mytho/rk/v1` participates here. `CK_0` is **not** derived with `mytho/ck/v1` — it is simply the second 32-byte half of this `mytho/rk/v1`-labelled output. The `mytho/ck/v1` label is used **only** in the symmetric chain step below.

**Two-output expansion**: when a single HKDF call must produce two keys (the root step above is the canonical case), expand to `L = 64` under one `info` and split the output into two 32-byte halves. Do not issue two separate HKDF calls that share the same `(salt, IKM, info)` triple.

**Symmetric chain step** — no natural salt, so `salt = ""` (32 zero bytes, §1a). The advanced chain key and the per-message key are derived from the **same** current chain key `CK` under **different** `info` labels:

```
CK' = HKDF(salt="", IKM=CK, info="mytho/ck/v1", L=32)   // next chain key
MK  = HKDF(salt="", IKM=CK, info="mytho/mk/v1", L=32)   // this message key
```

Sharing `(salt, IKM) = ("", CK)` across these two calls is correct: the distinct `info` labels provide the domain separation (see §4 anti-reuse rule).

## 4. Anti-reuse rule & forward compatibility

**Anti-reuse.** An implementation MUST NOT invoke HKDF twice with the same `(salt, IKM, info)` triple expecting independent outputs; distinct `info` labels are precisely how independent keys are produced (e.g. the chain step in §3 derives `CK'` and `MK` from the same `CK` using different `info`).

**Forward compatibility.** Labels are versioned (`/v1`). A protocol revision that needs to change a derivation MUST allocate a new label (`/v2`); MUST NOT reuse a `/v1` label with new semantics. KAT vectors are tagged with the label version.

## 5. Conformance

Any HKDF call within the protocol that uses a label **not listed in §2** is **non-conformant**; reviewers MUST treat unknown labels as a spec violation. The labels marked **RESERVED / OPTIONAL** in §2 are *allocated but not used by the reference KATs* — "reserved" means allocated-but-not-yet-active, not forbidden: `mytho/delivery-token/v1` MAY be used by a deployment to derive the delivery-token HMAC key, and `mytho/sealed-sender/v1` is held for a future revision. New labels require a normative spec PR with explicit purpose, output length, and KAT.

---

*v1.0 — labels are stable within the v1.x line; new labels added under `/v1` are forward-compatible.*
