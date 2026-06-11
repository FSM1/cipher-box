<!-- generated-by: gsd-doc-writer -->

# Security Policy

## Supported Versions

CipherBox follows independent per-package versioning managed by Release Please.
The table below lists the **current released versions** derived from `.release-please-manifest.json`.
Only the latest release of each component receives security fixes.

| Component             | Current Version | Supported |
| --------------------- | --------------- | --------- |
| cipher-box (root)     | 0.38.6          | Yes       |
| apps/api              | 0.37.1          | Yes       |
| apps/web              | 0.41.0          | Yes       |
| apps/desktop          | 0.41.0          | Yes       |
| apps/tee-worker       | 0.31.1          | Yes       |
| packages/crypto       | 0.31.0          | Yes       |
| packages/core         | 0.30.0          | Yes       |
| All previous releases | —               | No        |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Private Vulnerability Reporting](https://github.com/FSM1/cipher-box/security/advisories/new)
to submit a report confidentially. <!-- VERIFY: private vulnerability reporting is enabled for this repository -->

Include as much of the following as is available:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (even partial)
- Affected component(s) and version(s)
- Any suggested mitigations

<!-- VERIFY: response SLA — the following timeline is a best-effort target, not a contractual commitment -->

**Response expectations:**

- Acknowledgement within 5 business days
- Initial triage and severity assessment within 10 business days
- Coordinated disclosure after a fix is available or 90 days from report, whichever comes first

## Security Model and Scope

CipherBox is an end-to-end encrypted storage system. A brief summary of the threat model:

- **Client-side encryption only.** Files and metadata are encrypted in the browser or desktop app
  before leaving the device. The server stores and relays only ciphertext.
- **Zero-knowledge server.** The API never receives plaintext file contents, file names, or unencrypted
  keys. It cannot decrypt user data.
- **TEE republishing.** IPNS record republishing is performed inside a Trusted Execution Environment
  (TEE). The TEE decrypts the IPNS private key in hardware for the duration of a single signing
  operation and immediately discards it.
- **Key wrapping.** All sensitive keys are wrapped with ECIES before leaving the client. Content is
  encrypted with AES-256-GCM.

For the full architecture, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### In scope

- Vulnerabilities that could expose plaintext user data or private keys
- Authentication or authorization bypasses in the API
- Cryptographic weaknesses in key derivation, wrapping, or content encryption
- TEE isolation failures that could allow key extraction
- Vulnerabilities in the Tauri desktop app (FUSE layer, IPC, OAuth redirect handling)

### Out of scope

- Denial-of-service attacks against public infrastructure
- Social engineering of maintainers
- Vulnerabilities in third-party dependencies (report those upstream; mention them here if they affect CipherBox directly)
- Issues in deferred features (billing, mobile apps) that are not yet implemented
