# Security Policy

mytho.chat is, in this repository, a **protocol specification** (v1.0). This policy covers both the specification here and the reference deployment at `mytho.chat`.

## Reporting a vulnerability

**Please report privately first.** Do not open a public issue for a suspected cryptographic weakness, protocol flaw, or deployment vulnerability.

- **Email:** `security@mytho.chat`
- **Encryption:** a PGP key for encrypted reports is published at `mytho.chat/pgp.asc` *(placeholder until the reference deployment is live)*.
- **Acknowledgement target:** within 5 business days.
- **Coordinated disclosure:** we ask for a 90-day window before public disclosure, or sooner by mutual agreement once a fix or mitigation is in place.

We welcome reports about:

- Weaknesses in the **protocol design** (handshake, ratchet, wire format, sealed-sender token).
- Incorrect or unsafe **use of primitives** (ML-KEM-768, ML-DSA-65, XChaCha20-Poly1305, HKDF, Double Ratchet).
- **Metadata leakage** beyond what is already declared out-of-scope (see [`README.md`](./README.md) §3).
- Errors in the specification documents that could lead implementers to build something insecure.

## What is in and out of scope

**In scope:**
- The specification in this repository.
- The reference relay and clients operated under `mytho.chat` (once live).

**Out of scope** (already documented as non-goals — see README §3):
- Compromise of an endpoint **device** (a hostile endpoint defeats any E2E system).
- Network-level **traffic analysis** by packet timing/volume (only size-bin padding is claimed).
- Recovery of **already-expired** ephemeral messages.
- Correlation by an adversary who **simultaneously** compromises both the relay **and** the external identity issuer.

Reporting an out-of-scope item is still welcome as discussion, but it is not treated as a vulnerability.

## Cryptographic assumptions

The protocol's claims hold only while the underlying assumptions hold:

- ML-KEM-768 and ML-DSA-65 remain secure as currently believed by the cryptographic community (NIST FIPS 203 / 204).
- HKDF-SHA-256 and XChaCha20-Poly1305 remain secure.
- The Double Ratchet composition (Perrin/Marlinspike) is used as specified.

If a break is found in any of these primitives, the corresponding property in README §11 is invalidated. We will publish migration guidance if a primitive is deprecated.

## Audit status

**No formal third-party audit has been completed at the time of writing.** A formal audit of the production cryptographic core is planned; results will be published here and at `mytho.chat/transparency`. Until then, treat all security properties as **claimed design targets**, not certified guarantees.

## Implementation hardening (for anyone building from this spec)

The specification is necessary but not sufficient for a secure implementation. Implementers are responsible for:

- **Constant-time** operations on secret-dependent paths.
- **Zeroization** of message keys, chain keys, and the master key after use.
- A **cryptographically secure RNG** for nonces, KEM randomness, and PoW.
- Enforcing the **bounded skipped-key store** (`MAX_SKIP`) to prevent memory-exhaustion DoS.
- **Fail-closed** behavior on any validation error.
- Not logging plaintext, keys, tokens, or full peerIds in production.

## Safe harbor

We will not pursue legal action against good-faith security research that:

- Respects user privacy and data,
- Does not degrade or disrupt the service for others,
- Does not access or modify data beyond what is necessary to demonstrate the issue,
- Gives us reasonable time to remediate before public disclosure.
