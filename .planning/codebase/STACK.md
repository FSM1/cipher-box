# Technology Stack

**Analysis Date:** 2026-03-06

## Project Status

CipherBox is a **technology demonstrator** with a working implementation. The web app (`apps/web/`), backend API (`apps/api/`), desktop app (`apps/desktop/`), shared crypto library (`packages/crypto/`), TEE worker (`tee-worker/`), and E2E test suites (`tests/e2e/`, `tests/desktop-e2e/`) are all implemented. The original PoC console harness remains in `00-Preliminary-R&D/poc/` for historical reference only.

## Languages

**Primary:**

- TypeScript 5.7+ - All application code (web, API, desktop frontend, crypto, TEE worker)

**Secondary:**

- Rust - Desktop FUSE filesystem (`apps/desktop/src-tauri/`)
- SQL - PostgreSQL migrations (`apps/api/src/migrations/`)
- JavaScript (ES2022) - Compilation target

## Runtime

**Environment:**

- Node.js 20+ - Backend API and build tooling
- Browser (Chrome/Firefox/Safari) - Web app
- Tauri v2 (WebView + Rust) - Desktop app (macOS, Windows)

**Package Manager:**

- pnpm 9+ - Workspace-based monorepo management
- Lockfile: `pnpm-lock.yaml` at workspace root

## Frameworks

**Web App (`apps/web/`):**

- React 18 - Frontend framework
- Tailwind CSS - Styling
- Vite - Build tooling and dev server
- Zustand - State management

**Backend (`apps/api/`):**

- NestJS - Backend framework
- TypeORM - Database ORM with migrations
- BullMQ + Redis - Job queue for background tasks
- Passport - Authentication strategies

**Desktop (`apps/desktop/`):**

- Tauri v2 - Desktop shell (Rust + WebView)
- FUSE-T (SMB backend) - Virtual filesystem mount (macOS)
- WinFSP - Virtual filesystem (Windows)
- Vendored fuser crate - FUSE bindings with socket-read patch

**Build/Dev:**

- TypeScript 5.7+ - Type checking and compilation
- ESLint 9 - Linting (flat config)
- Vitest - Unit testing (web, crypto)
- Jest - Unit testing (API)
- Playwright - E2E testing

## Key Dependencies

**Cryptography:**

- `eciesjs` ^0.4.16 - ECIES encryption (secp256k1 key wrapping)
- `@noble/secp256k1` - Public key derivation
- `@noble/ed25519` - Ed25519 IPNS record signing
- Web Crypto API - AES-256-GCM/CTR encryption, HKDF-SHA256 key derivation

**Authentication:**

- `@web3auth/mpc-core-kit` ^3.5.0 - MPC-based auth and deterministic keypair derivation
- `jose` - JWT verification (backend JWKS validation)
- `@simplewebauthn/*` - WebAuthn/passkey support

**IPFS/IPNS:**

- Kubo HTTP API - File storage and pinning (via `apps/api/src/ipfs/providers/local.provider.ts`)
- Self-hosted Someguy (staging) / delegated-ipfs.dev (production fallback) - IPNS record publishing and resolution

**Desktop (Rust):**

- `fuser` (vendored) - FUSE bindings with FUSE-T socket-read patch
- `winfsp` - Windows filesystem in userspace
- `reqwest` - HTTP client for API calls
- `keyring` - OS keychain for token storage
- `tauri` v2 - Desktop app framework

## Configuration

**Environment:**

- `.env` files for local configuration (see `apps/api/.env.example`, `apps/web/.env.example`)
- GitHub Actions secrets/vars for CI/CD
- Docker Compose `.env` for staging

**TypeScript:**

- Target: ES2022
- Module: ES2022 / ESNext (varies by workspace)
- ModuleResolution: Bundler
- Strict mode enabled across all workspaces

**Build Commands:**

- `pnpm dev` - Start all dev servers
- `pnpm --filter api dev` - API dev server (<http://localhost:3000>)
- `pnpm --filter web dev` - Web dev server (<http://localhost:5173>)
- `pnpm --filter desktop tauri dev` - Desktop dev
- `pnpm test` - Run unit tests (all workspaces)
- `pnpm typecheck` - TypeScript type checking
- `pnpm api:generate` - Regenerate API client from OpenAPI spec

## Cryptography Stack

**Symmetric Encryption:**

- AES-256-GCM - File and metadata encryption (Web Crypto API)
- AES-256-CTR - Streaming encryption for large files and media playback (Web Crypto API)

**Asymmetric Encryption:**

- ECIES (secp256k1) - Key wrapping via `eciesjs`
- ECDSA (secp256k1) - Keypair from Web3Auth MPC Core Kit
- Ed25519 - IPNS record signing via `@noble/ed25519`

**Key Derivation:**

- HKDF-SHA256 - Deterministic IPNS keypair derivation from user's private key (Web Crypto API)
- Random generation - Content encryption keys (file keys, folder keys) via `crypto.getRandomValues()`

## Platform Requirements

**Development:**

- Node.js 20+
- pnpm 9+
- PostgreSQL 16 (Docker or local)
- Redis (Docker or local)
- IPFS Kubo node with HTTP API enabled

**Staging/Production:**

- Docker Compose for orchestration
- PostgreSQL database
- Redis instance
- IPFS Kubo node
- Web3Auth project (auth)
- Phala Cloud TEE worker (IPNS republishing)

---

Stack analysis: 2026-03-06
