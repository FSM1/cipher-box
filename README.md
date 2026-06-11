<!-- generated-by: gsd-doc-writer -->

<p align="center">
  <img src="./cipherbox logo.png" alt="CipherBox Logo" width="450"/>
</p>

<h3 align="center">Privacy-first encrypted cloud storage with decentralized persistence</h3>

---

## What is CipherBox

CipherBox is a privacy-first encrypted cloud storage system. All encryption happens
client-side — the server never sees plaintext data, file names, or encryption keys. Files are stored
on IPFS for decentralized persistence, keys are derived deterministically via Web3Auth so the same
user always gets the same vault regardless of login method, and data can be exported for independent
recovery without CipherBox.

## Acknowledgements

This project is inspired by discussions and planning while working on
[ChainSafe Files](https://github.com/chainsafe/ui-monorepo). A massive shout-out to all the
colleagues who worked on the original ChainSafe Files project.

## Features

- **Authentication** — Web3Auth MPC Core Kit: email OTP, Google OAuth, magic link, external wallet
  (SIWE). MFA via device factor with BIP39 recovery phrase.
- **Encryption** — Client-side AES-256-GCM for files and metadata. ECIES secp256k1 key wrapping
  (per-file, per-folder random keys). AES-256-CTR streaming for large media files. Web Worker
  offloading for batch encryption.
- **File Management** — Upload, download, rename, move, delete. Batch upload pipeline with concurrent
  encryption and pinning. Nested folders up to 20 levels. Drag-and-drop. File versioning with
  point-in-time restore (up to 10 versions per file).
- **Sharing** — User-to-user sharing with ECIES re-wrapping (read-only and read-write). Invite-link
  sharing with time-limited access tokens. Multi-recipient sharing. Lazy key rotation on revoke.
- **Recycle Bin** — 30-day soft-delete with restore and permanent delete.
- **Search** — Client-side encrypted search index across file and folder names. Fuzzy matching with
  Cmd/Ctrl+K shortcut.
- **Media Preview** — Image, PDF, video (streaming CTR decryption), and audio preview.
- **Sync** — Multi-device via IPNS polling (~30s). Conflict detection and resolution
  (sequence-number based).
- **Desktop** — macOS, Linux, and Windows via Tauri v2 + FUSE-T/libfuse3/WinFsp virtual filesystem
  mount. Background sync with system tray. SMB backend on macOS.
- **TEE Republishing** — Automatic IPNS record refresh every 6 hours via Phala Cloud. Zero-knowledge:
  keys decrypted only inside hardware enclaves.
- **Data Portability** — Full vault export (JSON + encrypted blobs). Standalone recovery with
  `privateKey` — no CipherBox required.
- **Observability** — Structured logging (web), Prometheus metrics endpoint (API), Grafana Faro
  integration, load testing infrastructure.
- **BYO IPFS** — Bring-your-own IPFS node support via server-relay flow. Dual-pin mode with
  automatic migration.

## Architecture Overview

```text
┌───────────────┐     ┌──────────────┐     ┌───────────────┐
│ Web / Desktop │────>│ CipherBox API│────>│  PostgreSQL   │
│   (Client)   │     │  (NestJS)    │     │  (Metadata)   │
└──────┬────────┘     └──────┬───────┘     └───────────────┘
       │                     │
       │ Encrypted blobs      │ Relay
       v                     v
┌──────────────┐     ┌───────────────┐
│    IPFS      │     │  TEE Worker   │
│  (Storage)   │     │ (IPNS Refresh)│
└──────────────┘     └───────────────┘
```

The client encrypts everything locally. The API is a zero-knowledge relay — it stores encrypted
keys and routes IPFS/IPNS operations but never accesses plaintext. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for cryptographic details.

## Tech Stack

| Component          | Technology                                                      |
| :----------------- | :-------------------------------------------------------------- |
| **Frontend**       | React 18 + TypeScript + Tailwind CSS                            |
| **Backend**        | Node.js + NestJS + TypeScript                                   |
| **Database**       | PostgreSQL 16                                                   |
| **Job Queue**      | BullMQ + Redis 7                                                |
| **Key Derivation** | Web3Auth MPC Core Kit                                           |
| **Storage**        | IPFS via Kubo                                                   |
| **Desktop**        | Tauri v2 + FUSE-T (macOS) / libfuse3 (Linux) / WinFsp (Windows) |
| **TEE**            | Phala Cloud (IPNS republishing)                                 |
| **Crypto**         | Web Crypto API (AES-256-GCM/CTR) + eciesjs (ECIES secp256k1)    |
| **Observability**  | Grafana Faro (web), Prometheus (API)                            |

## Project Structure

```text
cipher-box/
├── apps/
│   ├── api/              # NestJS backend (@cipherbox/api)
│   ├── web/              # React frontend (@cipherbox/web)
│   ├── desktop/          # Tauri v2 desktop app (@cipherbox/desktop)
│   └── tee-worker/       # Phala Cloud TEE worker (cipherbox-tee-worker)
├── packages/
│   ├── core/             # Shared TypeScript types and metadata schemas
│   ├── crypto/           # Shared encryption library (AES, ECIES, key derivation)
│   ├── sdk-core/         # Stateless SDK operations (encrypt, pin, folder ops)
│   ├── sdk/              # Stateful SDK client (CipherBoxClient)
│   └── api-client/       # Generated OpenAPI typed client
├── crates/
│   ├── core/             # Shared Rust types
│   ├── crypto/           # Rust encryption library
│   ├── sdk/              # Rust SDK (stateful orchestration, sync daemon)
│   ├── fuse/             # FUSE filesystem implementation
│   └── api-client/       # Rust API client
├── tests/
│   ├── web-e2e/          # Playwright web E2E tests
│   ├── sdk-e2e/          # SDK integration tests
│   ├── desktop-e2e/      # Desktop E2E tests
│   ├── load/             # Load and performance tests
│   └── vectors/          # Crypto test vectors
└── docs/                 # Architecture, development, and specification docs
```

## Getting Started

### Prerequisites

- Node.js 20+
- pnpm 10+
- Docker (for PostgreSQL, IPFS, Redis)
- Rust toolchain (desktop app only)

### Quick Start

```bash
# 1. Start infrastructure services
docker compose -f docker/docker-compose.yml up -d

# 2. Install dependencies
pnpm install

# 3. Copy environment files
cp apps/api/.env.example apps/api/.env
cp apps/web/.env.example apps/web/.env

# 4. Start API and web app
pnpm dev
```

- API: <http://localhost:3000>
- Web: <http://localhost:5173>

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for full setup including the desktop app, testing,
and environment configuration.

## Documentation

| Document                                                                   | Description                                        |
| :------------------------------------------------------------------------- | :------------------------------------------------- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                               | Encryption hierarchy, key derivation, threat model |
| [docs/AUTHENTICATION_ARCHITECTURE.md](docs/AUTHENTICATION_ARCHITECTURE.md) | Auth flow, Web3Auth integration                    |
| [docs/FILESYSTEM_SPECIFICATION.md](docs/FILESYSTEM_SPECIFICATION.md)       | Filesystem rules, naming, and constraints          |
| [docs/METADATA_SCHEMAS.md](docs/METADATA_SCHEMAS.md)                       | All metadata object schemas                        |
| [docs/METADATA_EVOLUTION_PROTOCOL.md](docs/METADATA_EVOLUTION_PROTOCOL.md) | Metadata versioning and migration                  |
| [docs/DATABASE_EVOLUTION_PROTOCOL.md](docs/DATABASE_EVOLUTION_PROTOCOL.md) | Migration discipline, TypeORM rules                |
| [docs/CAPACITY.md](docs/CAPACITY.md)                                       | Storage quotas and limits                          |
| [docs/VAULT_EXPORT_FORMAT.md](docs/VAULT_EXPORT_FORMAT.md)                 | Export/recovery data format                        |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)                                 | Local dev setup, environment, workflow             |
| [tests/TESTING_STRATEGY.md](tests/TESTING_STRATEGY.md)                     | SDK E2E and load testing architecture              |

## Security

CipherBox is zero-knowledge by design:

- The server never holds plaintext data, file names, or unencrypted keys.
- `privateKey` is never stored in localStorage, sessionStorage, or sent to the server.
- All key wrapping uses ECIES secp256k1; all content encryption uses AES-256-GCM.
- IPNS private keys are encrypted with the TEE `publicKey` before transmission and are decrypted
  only inside hardware enclaves (`keyEpoch`-scoped, rotated every 4 weeks).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full threat model.

## License

[MIT](LICENSE)
