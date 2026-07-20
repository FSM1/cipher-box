# Security Policy

## Supported Versions

CipherBox releases as a single product version (`vX.Y.Z`). The repo is
mid-rewrite: **no supported release currently exists**. v1 is frozen on the
`v1` branch (tag `v1-freeze`), was staging-only, and receives no fixes; v2 is
being built on `main` and starts releasing at `v2.0.0`. From then on, only
the latest release receives security fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Private Vulnerability Reporting](https://github.com/FSM1/cipher-box/security/advisories/new)
to submit a report confidentially.

Include as much of the following as is available:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (even partial)
- Affected component(s) and version(s)
- Any suggested mitigations

**Response expectations** (best-effort targets, not contractual commitments):

- Acknowledgement within 5 business days
- Initial triage and severity assessment within 10 business days
- Coordinated disclosure after a fix is available or 90 days from report, whichever comes first

## Security Model and Scope

CipherBox is an end-to-end encrypted storage system. A brief summary of the v2 threat model:

- **Client-side encryption only.** Files and metadata are encrypted on the client before leaving
  the device. The server stores and relays only ciphertext.
- **Zero-knowledge server.** The API never receives plaintext file contents, file names, or
  unencrypted keys, and never serves IPNS records — clients resolve and verify records against
  the network.
- **One crypto implementation.** All cryptography lives in `crates/core`: XChaCha20-Poly1305
  sealing, BLAKE3 tree KDF, X25519 + HPKE key wrapping, Ed25519/secp256k1 signing. Key
  derivation is restricted to a frozen KDF catalog.
- **Fail-closed verification.** Every resolved record must pass the adoption gate (signature,
  epoch, and structure checks); a failure is treated as a trust violation, never as staleness.
- **Keyless republishing.** IPNS records are re-published by a keyless module inside the API
  from client-signed records — the server never holds signing keys.

For the full design, see [`blueprint/core.md`](blueprint/core.md) (primitives, wire formats)
and [`blueprint/engine.md`](blueprint/engine.md) (trust model).

### In scope

- Vulnerabilities that could expose plaintext user data or private keys
- Authentication or authorization bypasses in the API
- Cryptographic weaknesses in key derivation, wrapping, sealing, or signing
- Adoption-gate bypasses (accepting a record that should fail verification)
- Vulnerabilities in the desktop app (FUSE layer, IPC, OAuth redirect handling)

### Out of scope

- Denial-of-service attacks against public infrastructure
- Social engineering of maintainers
- Vulnerabilities in third-party dependencies (report those upstream; mention them here if they affect CipherBox directly)
- The frozen v1 branch
- Issues in deferred features (billing, mobile apps) that are not implemented
