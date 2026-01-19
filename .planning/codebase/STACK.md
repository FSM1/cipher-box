# Technology Stack

**Analysis Date:** 2026-01-19

## Languages

**Primary:**
- TypeScript 5.4.2 - All application code in `poc/src/`
- Markdown - Documentation in `Documentation/` directory

**Secondary:**
- JSON - Configuration and data formats

## Runtime

**Environment:**
- Node.js (ES2022 target, ES2022 modules)

**Package Manager:**
- Yarn
- Lockfile: `poc/yarn.lock` present

## Frameworks

**Core:**
- None (PoC uses vanilla Node.js)

**Testing:**
- None detected

**Build/Dev:**
- tsx 4.7.1 - TypeScript execution for development
- TypeScript 5.4.2 - Compilation to JavaScript
- ESLint 8.57.0 - Linting

## Key Dependencies

**Critical:**
- `@noble/secp256k1` 2.1.0 - ECDSA keypair operations, public key derivation (secp256k1 curve)
- `eciesjs` 0.4.7 - ECIES encryption for key wrapping (public key encryption)
- `ipfs-http-client` 60.0.1 - IPFS HTTP API client for add/cat/pin operations and IPNS publish/resolve
- `dotenv` 16.4.5 - Environment variable management

**Infrastructure:**
- Node.js `crypto` module - AES-256-GCM encryption/decryption
- Node.js `fs/promises` - File system operations for state persistence

## Configuration

**Environment:**
- Configuration via `.env` file (example at `poc/.env.example`)
- Required: `ECDSA_PRIVATE_KEY` (hex format, no 0x prefix)
- Optional: `IPFS_API_URL`, `IPFS_GATEWAY_URL`, `PINATA_ENABLED`, `PINATA_API_KEY`, `PINATA_API_SECRET`, `POC_STATE_DIR`, `IPNS_POLL_INTERVAL_MS`, `IPNS_POLL_TIMEOUT_MS`, `STRESS_CHILDREN_COUNT`, `STRESS_CHILD_TYPE`

**Build:**
- `poc/tsconfig.json` - TypeScript configuration (strict mode, ES2022, Bundler module resolution)
- `poc/.eslintrc*` - ESLint configuration (not explicitly found but referenced in package.json)

## Platform Requirements

**Development:**
- Node.js runtime
- Local IPFS node (Kubo) at http://127.0.0.1:5001 (configurable)
- Optional: Pinata account for remote pinning

**Production:**
- Planned stack (not yet implemented):
  - Backend: NestJS (Node.js framework)
  - Database: PostgreSQL
  - Frontend: React 18 + TypeScript
  - Desktop: Tauri or Electron
  - Auth: Web3Auth SDK (@web3auth/modal)
  - Styling: Tailwind CSS
  - IPFS Pinning: Pinata API

---

*Stack analysis: 2026-01-19*
