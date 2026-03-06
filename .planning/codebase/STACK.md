# Technology Stack

**Analysis Date:** 2026-01-20

## Project Status

CipherBox is a **technology demonstrator** with a working implementation. The web app (`apps/web/`), backend API (`apps/api/`), desktop app (`apps/desktop/`), shared crypto library (`packages/crypto/`), TEE worker (`tee-worker/`), and E2E test suites (`tests/e2e/`, `tests/e2e-desktop/`) are all implemented. The original PoC console harness remains in `/00-Preliminary-R&D/poc/` for reference.

## Languages

**Primary:**

- TypeScript 5.7+ - All application code (web, desktop, backend, crypto, PoC)

**Secondary:**

- JavaScript (ES2022) - Compilation target
- SQL - PostgreSQL database schema and migrations
- Rust - TEE worker (Phala Cloud) and desktop FUSE filesystem

## Runtime

**Environment:**

- Node.js 20+ - Backend API and build tooling
- Browser (Chrome/Firefox/Safari) - Web app
- Tauri v2 - Desktop app (macOS)

**Package Manager:**

- pnpm 9+ - Workspace-based monorepo management
- Lockfile: `pnpm-lock.yaml` at workspace root

## Frameworks

**Web App:**

- React 18 - Frontend framework
- Tailwind CSS - Styling
- Vite - Build tooling

**Backend:**

- NestJS - Backend framework (Node.js)
- TypeORM - Database ORM
- BullMQ + Redis - Job queue

**Desktop:**

- Tauri v2 - Desktop shell
- FUSE-T (SMB backend) - Virtual filesystem mount (macOS)

**Build/Dev:**

- TypeScript 5.7+ - Type checking and compilation
- ESLint 9 - Linting
- Vitest - Unit testing (web, crypto)
- Jest - Unit testing (API)
- Playwright - E2E testing

## Key Dependencies

**PoC Critical (from `00-Preliminary-R&D/poc/package.json`):**

- `ipfs-http-client` 60.0.1 - IPFS node communication
- `eciesjs` 0.4.7 - ECIES encryption (secp256k1)
- `@noble/secp256k1` 2.1.0 - Public key derivation
- `dotenv` 16.4.5 - Environment configuration

**PoC Dev Dependencies:**

- `@types/node` 20.19.30 - Node.js type definitions
- `typescript` 5.4.2 - TypeScript compiler
- `tsx` 4.7.1 - TypeScript execution
- `eslint` 8.57.0 - Linting

**Planned Production:**

- `@web3auth/modal` - Auth and key derivation
- `jose` - JWT verification (backend)
- PostgreSQL client - Database access (backend)
- `winston` - Structured logging framework (backend)
- `nest-winston` - NestJS Winston integration (backend)
- Datadog/Splunk transport - Log aggregation for dev/prod environments

## Configuration

**Environment:**

- `.env` file for local configuration
- Environment variables for sensitive data
- Key configs from `00-Preliminary-R&D/poc/.env.example`:
  - `ECDSA_PRIVATE_KEY` - Required, 32-byte hex
  - `IPFS_API_URL` - IPFS daemon endpoint (default: <http://127.0.0.1:5001>)
  - `IPFS_GATEWAY_URL` - IPFS gateway for reads
  - `IPFS_LOCAL_API_URL`, `IPFS_LOCAL_GATEWAY_URL` - Kubo node endpoints
  - `POC_STATE_DIR` - Local state persistence
  - `IPNS_POLL_INTERVAL_MS`, `IPNS_POLL_TIMEOUT_MS` - Polling config

**TypeScript (from `00-Preliminary-R&D/poc/tsconfig.json`):**

- Target: ES2022
- Module: ES2022
- ModuleResolution: Bundler
- Strict mode enabled
- Output: `dist/`

**Build:**

- `npm start` or `yarn start` - Run PoC via tsx
- `npm run build` - Compile TypeScript
- `npm run lint` - Run ESLint

## Cryptography Stack

**Symmetric Encryption:**

- AES-256-GCM - File and metadata encryption (via Node.js `crypto`)
- AES-256-CTR - Planned for streaming (v1.1+)

**Asymmetric Encryption:**

- ECIES (secp256k1) - Key wrapping via `eciesjs`
- ECDSA (secp256k1) - Key derivation via Web3Auth (planned)
- Ed25519 - IPNS record signing (planned, via `libsodium.js`)

**Key Derivation:**

- HKDF-SHA256 - Key derivation (planned)
- SHA-256 - Hashing

## Platform Requirements

**Development:**

- Node.js 20+
- Local IPFS daemon (Kubo) with HTTP API enabled
- npm or yarn

**Production (Planned):**

- PostgreSQL database
- IPFS Kubo node (pinning and storage)
- Web3Auth project (auth)
- TEE provider (Phala Cloud primary, AWS Nitro fallback)

---

Stack analysis: 2026-01-20
