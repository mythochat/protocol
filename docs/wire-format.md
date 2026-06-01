# Fragment Wire Format

> Part of the mytho.chat protocol specification (Draft v0.1). Companion to [`README.md`](../README.md) §4 (architecture) and §7 (message model). This document specifies the **byte layout** of what travels between client and relay, and what the relay is permitted to read.
>
> **Design rule:** the relay parses **only** the routing envelope. Everything inside the sealed payload is opaque to it. If a field is not in the routing envelope, the relay never sees it in cleartext.

---

## 1. Layering

```
+-----------------------------------------------------------+
| Transport frame (WebSocket message / JSON)                |  <- relay reads this
|  +-----------------------------------------------------+  |
|  | Routing Envelope (cleartext to relay)               |  |  <- relay routes on this
|  |   recipientPeerId, fragmentMeta, ttl, deliveryToken |  |
|  +-----------------------------------------------------+  |
|  +-----------------------------------------------------+  |
|  | Sealed Payload (opaque to relay)                    |  |  <- relay NEVER decrypts
|  |   ratchet header + AEAD ciphertext + sender seal    |  |
|  +-----------------------------------------------------+  |
+-----------------------------------------------------------+
```

Two encodings are defined and MUST be equivalent in content:

- **Canonical binary** (this document, §3–§5) — for the reference implementation and KAT vectors.
- **JSON transport** (§7) — base64url of the binary fields, used over the WebSocket control channel.

All multi-byte integers are **big-endian, unsigned**. All variable-length fields are length-prefixed (`u16` or `u32` as noted). There is no implicit padding between fields.

---

## 2. Identifiers and constants

| Name | Type | Definition |
| --- | --- | --- |
| `peerId` | 32 bytes | `SHA-256(IK_pub_dilithium)` — a peer's public identifier |
| `messageId` | 16 bytes | client-generated random; unique per logical message |
| `fragmentIndex` | u8 | 0-based index within a message |
| `totalFragments` | u8 | total fragments for this `messageId` (1–256) |
| `ttlSeconds` | u32 | requested lifetime; relay MUST clamp to `TTL_HARD_LIMIT` |
| `WIRE_VERSION` | u8 | currently `0x01` (this document) |
| `MAX_FRAGMENT_TEXT` | const | 65536 bytes (post-padding) |
| `MAX_FRAGMENT_MEDIA` | const | 262144 bytes (post-padding) |
| `MAX_MESSAGE_TEXT` | const | 16 MiB total across fragments (post-padding) |
| `MAX_MESSAGE_MEDIA` | const | 64 MiB total across fragments (post-padding) |
| `MAX_SKIP` | const | **2000** message keys (receiver SHOULD allow higher) |
| `TTL_HARD_LIMIT` | const | **604800 seconds (7 days)** RECOMMENDED; MUST NOT exceed 2592000 (30 days) |
| `DELIVERY_TOKEN_LIFETIME` | const | **300 seconds (5 min)** — token `exp - now()` MUST NOT exceed this |
| `padding_bin_text` | enum | {1024, 4096, 16384, 65536} |
| `padding_bin_media` | enum | {16384, 65536, 262144} |

`peerId` derivation is fixed at SHA-256 of the DER-free raw ML-DSA-65 public key bytes. Implementations MUST agree byte-for-byte (KAT vectors will pin this).

**`peerId` representation.** `IK_pub_dilithium` is the **raw byte serialization** of the ML-DSA-65 public key as specified in FIPS 204 §7 (ρ || t1), **no DER, no ASN.1, no length prefix**. The full public-key length is exactly 1952 bytes. The KAT vector `vectors/peerid-derivation.json` (see `docs/kat-vectors-format.md`) pins this byte-for-byte.

---

## 3. Routing Envelope (cleartext — the only thing the relay parses)

```
struct RoutingEnvelope {
    u8      wire_version;          // 0x01
    u8      msg_type;              // see §6
    u8      chat_type;             // 0=private; 1=group, 2=room are RESERVED for v1.0 — v0.1/v0.2 receivers MUST reject with MALFORMED
    u8      reserved;              // 0x00, MUST be zero in v0.1
    bytes32 recipient_peer_id;     // routing target
    bytes16 message_id;
    u8      fragment_index;
    u8      total_fragments;
    u16     padding_bin;           // declared bin (see §5); relay validates membership
    u32     ttl_seconds;           // relay clamps
    u16     delivery_token_len;
    bytes   delivery_token;        // HMAC sealed-sender token (see §4)
    u32     sealed_payload_len;
    bytes   sealed_payload;        // OPAQUE — relay does not parse beyond length
}
```

What the relay is **allowed** to do with this:

- Route to `recipient_peer_id`.
- Enforce `ttl_seconds` (clamped), `padding_bin` membership, fragment count sanity, quota.
- Verify `delivery_token` (HMAC) — see §4.
- Store/forward `sealed_payload` as opaque bytes.

What the relay **MUST NOT** do:

- Parse, log, or persist the contents of `sealed_payload`.
- Derive or infer the sender identity from anything other than the (verified) delivery token, which does not reveal sender identity to the relay (see §4).

What the relay **MUST** also do:

- Reject envelopes where `reserved != 0x00` with `MALFORMED` (forward-compatibility safeguard).

**Group/room reserved (v0.1/v0.2).** `chat_type ∈ {1, 2}` is structurally allocated but **not specified** in this version — multi-party ratcheting is out of scope for v0.1 (see `docs/ratchet-state-machine.md` §8). Receivers MUST reject envelopes with `chat_type != 0` with `MALFORMED`. Group semantics will be specified in v1.0.

Note the **absence** of a `sender_peer_id` field. Sender identity lives **inside** the sealed payload (§5), not in the envelope. This is the sealed-sender property.

---

## 4. Delivery token (sealed-sender authorization)

To send to `recipient_peer_id`, the sender first obtains a short-lived token from the issuer/relay boundary:

```
delivery_token = HMAC-SHA-256(
    key  = server_pepper,                 // server-side secret, never exposed
    data = sender_peer_id || recipient_peer_id || nonce || exp
)  // the tuple (nonce, exp) is carried alongside; sender_peer_id is NOT carried in cleartext
```

- The relay obtains `sender_peer_id` from the **authenticated session** bound to the WebSocket (`AUTH` msg, §6) — it is **never** read from the wire frame. This is what gives the sealed-sender property: the routing envelope reveals only the recipient.
- The relay verifies the HMAC (using a `server_pepper` known only to the relay) and `exp`, and enforces **single use** via a `seen` set keyed by `nonce` (TTL = token lifetime).
- The token authorizes "*some authenticated peer* may deliver to `recipient`," **without revealing which peer** to the routing layer.
- Binds to `recipient_peer_id`: a token minted for B MUST be rejected for delivery to C.
- Replay of the same `(nonce)` is rejected for the token lifetime.
- **Token lifetime**: `exp - now()` MUST NOT exceed `DELIVERY_TOKEN_LIFETIME` (§2 = 300s). Tokens beyond that window MUST be rejected.
- **HMAC output**: 32 bytes (full SHA-256 output, no truncation).
- **`server_pepper` size**: 32 bytes minimum, from a CSPRNG, never logged, rotated on operator policy.

This complements, and is independent from, the cryptographic sender authentication inside the payload (§5).

---

## 5. Sealed Payload (opaque to relay)

Decrypted and verified **only** by the recipient client:

```
struct SealedPayload {
    u8       payload_version;          // 0x01
    // --- ratchet header (authenticated, needed to derive the message key) ---
    u8       ratchet_flags;            // bit0: contains_new_kem_pub (direction change)
                                       // bit1: handshake_otpk_used (1=OTPK bound; 0=signed-prekey only, PFS-degraded)
                                       // bits2-7: reserved, MUST be zero in v0.1
    u16      kem_ct_len;
    bytes    kem_ciphertext;           // ML-KEM-768 encapsulation (1088 bytes), present iff bit0 set
    u32      prev_chain_len;           // PN: messages in previous sending chain
    u32      message_number;           // N: index in current chain
    // --- sender seal (who sent this; hidden from relay) ---
    bytes32  sender_peer_id;           // revealed only after decryption
    u16      sender_sig_len;           // 0 iff deniable=1
    bytes    sender_sig;               // ML-DSA-65 over (header || aead_ct), unless deniable
    u8       deniable;                 // 0=signed, 1=deniable (MAC-only, no sender_sig)
    // --- content ---
    u8       destruct_policy;          // app-layer, relay-agnostic
    u32      aead_ct_len;
    bytes    aead_ct;                  // XChaCha20-Poly1305(nonce, plaintext_padded, AAD); tag 16B appended
}
```

### 5.1 AEAD nonce (deterministic, NOT on wire)

```
aead_nonce = HKDF-Expand(MK, info = "mytho/nonce/v1", length = 24 bytes)
```

The nonce is **derived** from the per-message key `MK`, not transmitted. Since `MK` is single-use (§ratchet 5), nonce-reuse with the same key is by construction impossible. Implementations MUST NOT random-sample the AEAD nonce.

### 5.2 AAD (Additional Authenticated Data) — byte-exact encoding

```
AAD = u8(payload_version)
    || u8(ratchet_flags)
    || u32_be(message_number)
    || bytes32(recipient_peer_id)
```

**Total length: exactly 38 bytes.** All multi-byte integers are big-endian. Implementations MUST emit and verify the AAD byte-for-byte; a KAT vector pins this in `vectors/aad-encoding.json`.

`sender_peer_id` is intentionally **NOT** included in AAD: in signed mode, sender integrity comes from the ML-DSA signature over (header || aead_ct); in deniable mode, sender_peer_id is unauthenticated by design (the deniability property).

### 5.3 Plaintext padding (pre-AEAD)

The plaintext is padded to the declared `padding_bin` **before** AEAD encryption, using **ISO/IEC 7816-4 padding**:

```
padded = plaintext || 0x80 || (0x00 repeated until len(padded) == padding_bin)
```

If `len(plaintext) == padding_bin`, a full extra padding block (one byte `0x80` followed by `padding_bin - 1` zero bytes, totaling another `padding_bin` bytes) is appended (the padding is **always present and always unambiguous** — there is no plaintext for which decoding is ambiguous).

A KAT vector `vectors/padding-7816.json` pins three cases: empty plaintext, exact-fit plaintext, partial-fit plaintext.

### 5.4 OTPK exhaustion signaling

If the initiator's handshake claim returned **no one-time prekey** (pool exhausted at the relay), the initiator MUST set `ratchet_flags.bit1 = 0` (`handshake_otpk_used = false`). The responder MAY reject such handshakes by policy (deployments requiring strict forward-secrecy-for-first-message SHOULD reject). The exhaustion is **explicit on wire**, not silent.

---

## 6. Message types (`msg_type`)

| Value | Name | Direction | Notes |
| --- | --- | --- | --- |
| `0x01` | `RELAY` | client→relay | deliver a fragment |
| `0x02` | `DELIVER` | relay→client | fragment delivered to recipient |
| `0x03` | `ACK` | client→relay | recipient confirms; relay discards fragment |
| `0x04` | `PENDING_FETCH` | client→relay | request queued fragments after reconnect |
| `0x05` | `REVOKE` | client→relay | request propagation of a revoke (app layer) |
| `0x10` | `REGISTER_PEER` | client→relay | publish peer + prekeys (PoW-gated) |
| `0x11` | `CLAIM_PREKEYS` | client→relay | fetch a peer's prekey bundle |
| `0x12` | `AUTH` | client→relay | present ES256 session token |
| `0x7F` | `ERROR` | relay→client | structured error (see §8) |

Only `RELAY`, `DELIVER`, `ACK`, `PENDING_FETCH` carry a `SealedPayload`. Control types (`AUTH`, `REGISTER_PEER`, `CLAIM_PREKEYS`) carry their own small cleartext structs (keys are public; tokens are signed, not secret).

---

## 7. JSON transport mapping

Over the WebSocket channel, the same envelope is expressed as JSON with binary fields base64url-encoded (no padding):

```json
{
  "v": 1,
  "type": "RELAY",
  "chatType": "private",
  "recipientPeerId": "b64url(32 bytes)",
  "messageId": "b64url(16 bytes)",
  "fragmentIndex": 0,
  "totalFragments": 1,
  "paddingBin": 4096,
  "ttlSeconds": 172800,
  "deliveryToken": { "mac": "b64url", "nonce": "b64url", "exp": 1750000000 },
  "sealedPayload": "b64url(opaque bytes)"
}
```

The relay validates: `v == 1`, `type` known, `recipientPeerId` is 32 bytes, `paddingBin ∈ {1024,4096,16384,65536}` (text) or `{16384,65536,262144}` (media), `ttlSeconds` within hard-limit, `deliveryToken` HMAC valid + unused, `sealedPayload` length within `MAX_FRAGMENT`. Any failure → `ERROR` (fail-closed), connection may be dropped after repeated violations.

---

## 8. Error model

```json
{ "type": "ERROR", "code": "STRING_CODE", "fatal": true|false }
```

| Code | Meaning | Fatal |
| --- | --- | --- |
| `BAD_VERSION` | unsupported `wire_version` | yes |
| `MALFORMED` | envelope failed structural validation | per-message |
| `INVALID_DELIVERY_TOKEN` | HMAC/exp/replay failure | per-message |
| `BAD_PADDING_BIN` | declared bin not in allowed set / size mismatch | per-message |
| `QUOTA_EXCEEDED` | recipient pending quota full | per-message |
| `TTL_REJECTED` | requested TTL outside bounds after clamp logic | per-message |
| `RATE_LIMITED` | per-IP / per-peer limiter tripped | per-message |
| `AUTH_REQUIRED` | no valid ES256 session | yes |

Error codes never leak payload content. The relay does not explain *why* a sealed payload would fail to decrypt — it cannot, since it never decrypts.

---

## 9. What the relay stores (and for how long)

| Item | Storage | Lifetime |
| --- | --- | --- |
| Pending fragment (recipient offline) | ephemeral queue (RAM) | until ACK or `ttl_seconds` (clamped), then erased |
| `seen` nonce (delivery token) | ephemeral set | token lifetime |
| `seen` (messageId, fragmentIndex) replay guard | ephemeral set | fragment TTL |
| peerId → public keys + prekeys | ephemeral registry | bounded TTL, renewable |
| Online presence | ephemeral | short heartbeat TTL |

No plaintext. No message archive. No sender↔recipient correlation persisted. See `README.md` §3 for what remains out of scope (timing/volume analysis).

---

## 10. Versioning

`wire_version = 0x01` is a **draft**. Breaking changes before v1.0 are expected and will bump this byte. Implementations MUST reject versions they do not understand (`BAD_VERSION`, fatal). KAT vectors (roadmap) will be tagged to a specific `wire_version`.

---

## 11. Known-Answer Test (KAT) vectors

Normative KAT vectors live in `vectors/*.json`, each tagged to a specific `wire_version`. They pin byte-exact encodings for:

- `peerid-derivation.json` — given `IK_pub_dilithium` (hex), the derived `peerId`.
- `aad-encoding.json` — the 38-byte AAD for sample envelopes.
- `padding-7816.json` — ISO/IEC 7816-4 padding cases (empty / exact-fit / partial-fit).
- `aead-nonce-derivation.json` — `HKDF-Expand(MK, "mytho/nonce/v1", 24)` for sample `MK` values.
- `delivery-token.json` — `HMAC-SHA-256(server_pepper, sender || recipient || nonce || exp_be64)` cases.

See `docs/kat-vectors-format.md` for the JSON schema and `scripts/generate-kat.mjs` for the deterministic generator.

---

*Draft v0.2 — byte layouts may change before stable v1.0. Report ambiguities via `security@mytho.chat` or repository issues. This document intentionally omits any deployment secret, key, or infrastructure detail.*
