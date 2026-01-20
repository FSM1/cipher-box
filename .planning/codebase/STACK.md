# Technology Stack

**Analysis Date:** 2026-01-20

## Project Status

CipherBox is a **technology demonstrator** in early development. Currently, only a **Proof of Concept (PoC) console harness** exists in `/00-Preliminary-R&D/poc/`. The full production system (web app, desktop app, backend) is specified in documentation but not yet implemented.

## Languages

**Primary:**
- TypeScript 5.4.x - All application code (PoC, planned web/desktop/backend)

**Secondary:**
- JavaScript (ES2022) - Compilation target
- SQL - PostgreSQL database schema (planned)
- Rust - TEE/Phala Cloud workloads (planned, referenced in spec)

## Runtime

**Environment:**
- Node.js 20+ - PoC requires Node 20+
- Browser (Chrome/Firefox/Safari) - Web app (planned)
- Tauri/Electron - Desktop app (planned)

**Package Manager:**
- npm/yarn - `yarn.lock` present in PoC
- Lockfile: present at `00-Preliminary-R&D/poc/yarn.lock`

## Frameworks

**PoC (Current):**
- No framework - Raw Node.js + TypeScript
- `tsx` 4.7.1 - TypeScript execution

**Planned Web App:**
- React 18 - Frontend framework
- Tailwind CSS - Styling
- Axios - HTTP client

**Planned Backend:**
- NestJS - Backend framework (Node.js)
- jose - JWT verification

**Planned Desktop:**
- Tauri (preferred) or Electron - Desktop shell
- macFUSE/FUSE3/WinFSP - Filesystem mount

**Build/Dev:**
- TypeScript 5.4.2 - Type checking and compilation
- ESLint 8.57.0 - Linting
- tsx 4.7.1 - Dev execution

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
  - `IPFS_API_URL` - IPFS daemon endpoint (default: http://127.0.0.1:5001)
  - `IPFS_GATEWAY_URL` - IPFS gateway for reads
  - `PINATA_ENABLED`, `PINATA_API_KEY`, `PINATA_API_SECRET` - Remote pinning
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
- Pinata API account (IPFS pinning)
- Web3Auth project (auth)
- TEE provider (Phala Cloud primary, AWS Nitro fallback)

---

*Stack analysis: 2026-01-20*
