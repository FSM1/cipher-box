<p align="center">
  <img src="./cipherbox logo.png" alt="CipherBox Logo" width="450"/>
</p>

<h3 align="center">Privacy-first encrypted cloud storage with decentralized persistence</h3>

---

## What is CipherBox

CipherBox is a **technology demonstrator** for privacy-first cloud storage. All encryption happens client-side — the server never sees plaintext data, file names, or encryption keys. Files are stored on IPFS for decentralized persistence, keys are derived deterministically via Web3Auth so the same user always gets the same vault regardless of login method, and data can be exported for independent recovery without CipherBox.

## Acknowledgements

This project is inspired by discussions and planning while working on [ChainSafe Files](https://github.com/chainsafe/ui-monorepo). A massive shout-out to all the colleagues I got to work with on the original ChainSafe Files project, who unknowingly contributed to this phoenix rising out of the ashes.

## Features

- **Authentication** — Web3Auth MPC Core Kit: email OTP, Google OAuth, magic link, external wallet. MFA via device factor. Same user identity = same vault.
- **Encryption** — Client-side AES-256-GCM for files and metadata. ECIES secp256k1 key wrapping (per-file, per-folder random keys). Streaming AES-256-CTR for large media files.
- **File Management** — Upload, download, rename, move, delete. Nested folders up to 20 levels. Drag-and-drop.
- **Sync** — Multi-device via IPNS polling (~30s). Conflict detection and resolution.
- **Desktop** — macOS via Tauri v2 + FUSE-T virtual filesystem mount. Background sync with system tray.
- **TEE Republishing** — Automatic IPNS record refresh every 6 hours via Phala Cloud. Zero-knowledge: keys decrypted only inside hardware enclaves.
- **Data Portability** — Full vault export (JSON + encrypted blobs). Standalone recovery with private key — no CipherBox required.

- **Sharing** — User-to-user sharing with ECIES re-wrapping. Invite-link sharing with time-limited access tokens.
- **Recycle Bin** — 30-day soft-delete with restore.

### Planned (v1.1+)

- **Search** — Client-side encrypted search index across file and folder names.
- **Versioning** — File history with point-in-time restore.
- **Desktop (Windows & Linux)** — WinFSP / libfuse support.

## Architecture Overview

```text
┌──────────────┐     ┌──────────────┐     ┌───────────────┐
│  Web / Desktop│────▶│  CipherBox   │────▶│  PostgreSQL   │
│   (Client)   │     │    API       │     │  (Metadata)   │
└──────┬───────┘     └──────┬───────┘     └───────────────┘
       │                    │
       │ Encrypted          │ Relay
       │ blobs              │
       ▼                    ▼
┌──────────────┐     ┌───────────────┐
│    IPFS      │     │  TEE Worker   │
│  (Storage)   │     │ (IPNS Refresh)│
└──────────────┘     └───────────────┘
```

The client encrypts everything locally. The API is a zero-knowledge relay — it stores encrypted keys and routes IPFS/IPNS operations but never accesses plaintext. For full cryptographic details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tech Stack

| Component          | Technology                                    |
| :----------------- | :-------------------------------------------- |
| **Frontend**       | React 18 + TypeScript + Tailwind CSS          |
| **Backend**        | Node.js + NestJS + TypeScript                 |
| **Database**       | PostgreSQL 16                                 |
| **Job Queue**      | BullMQ + Redis                                |
| **Key Derivation** | Web3Auth MPC Core Kit                         |
| **Storage**        | IPFS via Kubo                                 |
| **Desktop**        | Tauri v2 + FUSE-T / WinFSP                    |
| **TEE**            | Phala Cloud (IPNS republishing)               |
| **Crypto**         | Web Crypto API (AES-256-GCM, ECIES secp256k1) |

## Project Structure

```text
cipher-box/
├── apps/
│   ├── api/              # NestJS backend
│   ├── web/              # React frontend
│   └── desktop/          # Tauri v2 desktop app
├── packages/
│   ├── crypto/           # Shared encryption library
│   └── api-client/       # OpenAPI spec; generated typed client lives in apps/web/src/api/
├── tee-worker/           # Phala Cloud TEE worker
├── tests/
│   ├── e2e/              # Playwright E2E tests
│   └── desktop-e2e/      # Desktop E2E tests
└── docker/               # Docker Compose (PostgreSQL, IPFS, Redis)
```

## Getting Started

```bash
docker compose -f docker/docker-compose.yml up -d
pnpm install
pnpm dev   # starts API (:3000) + web (:5173)
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for full setup instructions including desktop app, testing, and environment configuration.

## Documentation

| Document                                                                   | Description                                                  |
| :------------------------------------------------------------------------- | :----------------------------------------------------------- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                               | Encryption hierarchy, key derivation, threat model           |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)                                 | Local setup, running, testing                                |
| [docs/AUTHENTICATION_ARCHITECTURE.md](docs/AUTHENTICATION_ARCHITECTURE.md) | Auth flow details                                            |
| [docs/METADATA_SCHEMAS.md](docs/METADATA_SCHEMAS.md)                       | All metadata object schemas                                  |
| [docs/VAULT_EXPORT_FORMAT.md](docs/VAULT_EXPORT_FORMAT.md)                 | Export/recovery data format                                  |
| [docs/DATABASE_EVOLUTION_PROTOCOL.md](docs/DATABASE_EVOLUTION_PROTOCOL.md) | Migration discipline                                         |
| [00-Preliminary-R&D/Documentation/](00-Preliminary-R&D/Documentation/)     | Frozen v1 specifications (PRD, API, Data Flows, Client Spec) |

## License

[MIT](LICENSE)
