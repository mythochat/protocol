# Contributing

Thank you for taking the time to review the mytho.chat protocol.

This repository is a **specification**, not the production codebase. Contributions are therefore mostly about **the design and its documentation** — clarity, correctness, and security of the protocol as described.

## What we're looking for

**High value:**
- Corrections to cryptographic reasoning or primitive usage.
- Ambiguities in the wire format ([`docs/wire-format.md`](./docs/wire-format.md)) or ratchet ([`docs/ratchet-state-machine.md`](./docs/ratchet-state-machine.md)) that two implementers could read differently.
- Identified gaps between the stated threat model ([`README.md`](./README.md) §3) and what the protocol actually defends.
- Proposed **Known-Answer Test (KAT)** vectors for the cryptographic suite (roadmap item).
- Editorial fixes that improve precision (we prefer precise over persuasive).

**Out of scope for pull requests:**
- The production implementation (not in this repo, not accepted here).
- Feature requests for the consumer product (chat UX, app features) — those belong to the product, not the protocol.
- Security vulnerabilities — **do not** open a public PR/issue; use the process in [`SECURITY.md`](./SECURITY.md).

## How to propose a change

1. **For discussion or questions** about the design → open an **issue**.
2. **For concrete spec edits** → open a **pull request** against `main` with a clear description of *what* changes and *why* it is more correct or clearer.
3. **For anything security-sensitive** → email `security@mytho.chat` first (see [`SECURITY.md`](./SECURITY.md)). Do not disclose publicly until coordinated.

## Conventions

- **Language:** specification text is in English.
- **Primitives:** we use only standardized, audited primitives. Proposals that introduce non-standard or home-grown cryptography will not be accepted, regardless of cleverness. (See README §2 — *conservative composition*.)
- **Normative keywords:** MUST / MUST NOT / SHOULD / MAY follow RFC 2119 sense.
- **Diagrams:** Mermaid, inline in Markdown, so they render on GitHub and stay diffable.
- **No secrets:** never include keys, tokens, infrastructure details, or anything from the private production system in a contribution.

## Versioning of the spec

The protocol is **Draft v0.1**. Breaking changes are expected before a stable **v1.0** marking. The `wire_version` byte and document headers track this. Don't assume stability until v1.0 is declared.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the repository's **Apache License 2.0**. Don't submit material you don't have the right to license under those terms.

## Tone

This is a security project. We value:

- **Precision over enthusiasm** — "this is ambiguous between X and Y" beats "this looks great".
- **Adversarial thinking** — tell us how it breaks.
- **Honesty about limits** — if something only *partially* mitigates a threat, say so, and we'll document it as such.

We'd rather ship a smaller spec that is **true** than a larger one that over-promises.
