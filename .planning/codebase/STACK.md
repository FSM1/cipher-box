# Technology Stack

**Analysis Date:** 2026-03-29

## Languages

**Primary:**

- TypeScript ^5.9.3 - All frontend, backend, SDK packages, tests, tee-worker, and tooling
- Rust (Edition 2021) - Desktop native backend, all `crates/*` libraries

**Secondary:**

- JavaScript (ESM) - Config files (`eslint.config.js`, `prettier.config.js`, `commitlint.config.js`)
- SQL - Database migrations in `apps/api/src/migrations/`

## Runtime

**Environment:**

- Node.js 22+ (CI uses `node-version: '22'`)
- Rust stable 1.93+ (desktop and crate workspace)
- Browser (Chrome/Firefox/Safari) - Web app
- Tauri v2 (WebView + Rust) - Desktop app (macOS, Windows, Linux)

**Package Manager:**

- pnpm 10+ (CI uses `version: 10`)
- Lockfile: `pnpm-lock.yaml` (present, CI uses `--frozen-lockfile`)
- pnpm (tee-worker uses workspace dependencies since Phase 35 migration to `apps/tee-worker/`)
- Cargo (Rust workspace; `Cargo.lock` present)

## Monorepo Layout

**Workspace definition:** `pnpm-workspace.yaml`

```yaml
packages:
  - 'apps/*'
  - 'packages/*'
  - 'tests/*'
```

**Current version:** 0.30.1 (unified across all packages via Release Please)

### TypeScript SDK Packages (`packages/`)

| Package               | Name                    | Version | Build Tool   | Purpose                                                                  |
| --------------------- | ----------------------- | ------- | ------------ | ------------------------------------------------------------------------ |
| `packages/crypto`     | `@cipherbox/crypto`     | 0.29.0  | tsup         | Cryptographic primitives: AES-GCM, ECIES, Ed25519, HKDF, IPNS            |
| `packages/core`       | `@cipherbox/core`       | 0.29.0  | tsup         | Domain types, metadata schemas, vault blob structures                    |
| `packages/api-client` | `@cipherbox/api-client` | 0.30.0  | tsup + orval | Auto-generated typed HTTP client from OpenAPI spec                       |
| `packages/sdk-core`   | `@cipherbox/sdk-core`   | 0.30.0  | tsup         | Stateful SDK core: vault operations, key management                      |
| `packages/sdk`        | `@cipherbox/sdk`        | 0.30.0  | tsup         | High-level SDK facade re-exporting crypto + core + api-client + sdk-core |

**Dependency chain:** `crypto` <- `core` <- `api-client` <- `sdk-core` <- `sdk`

All SDK packages produce dual CJS/ESM output with TypeScript declarations via tsup:

```typescript
// packages/*/tsup.config.ts
defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
});
```

### Rust Crates (`crates/`)

| Crate               | Name                   | Version | Purpose                                                            |
| ------------------- | ---------------------- | ------- | ------------------------------------------------------------------ |
| `crates/crypto`     | `cipherbox-crypto`     | 0.4.0   | Crypto primitives: AES-GCM, ECIES, Ed25519, HKDF                   |
| `crates/core`       | `cipherbox-core`       | 0.4.0   | Domain types, metadata schemas, IPNS records, vault blob           |
| `crates/api-client` | `cipherbox-api-client` | 0.4.0   | Typed HTTP client for CipherBox API via reqwest                    |
| `crates/fuse`       | `cipherbox-fuse`       | 0.4.0   | FUSE filesystem with platform-specific mount implementations       |
| `crates/sdk`        | `cipherbox-sdk`        | 0.4.0   | Stateful SDK: sync daemon, write queue, key state, device registry |

**Dependency chain:** `crypto` <- `core` <- `api-client` <- `fuse`, `sdk`

**Platform features (conditional compilation):**

- `fuse` feature (default) - macOS/Linux FUSE via vendored `fuser` 0.16
- `winfsp` feature - Windows via `winfsp` 0.12

### Applications (`apps/`)

| App            | Name                 | Framework         | Purpose                     |
| -------------- | -------------------- | ----------------- | --------------------------- |
| `apps/api`     | `@cipherbox/api`     | NestJS 11         | Backend REST API            |
| `apps/web`     | `@cipherbox/web`     | React 18 + Vite 7 | Web frontend SPA            |
| `apps/desktop` | `@cipherbox/desktop` | Tauri 2 + Vite 6  | Desktop app with FUSE mount |

### TEE Worker (`apps/tee-worker/`)

| Component         | Framework | Purpose                                                                                                 |
| ----------------- | --------- | ------------------------------------------------------------------------------------------------------- |
| `apps/tee-worker` | Express 4 | Standalone TEE worker -- IPNS republishing (Docker simulator in staging, Phala Cloud CVM in production) |

The tee-worker is part of the pnpm workspace (since Phase 35 migration to `apps/`). It uses workspace dependencies for shared packages (`@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`) and is deployed as a Docker service (node:20-alpine) — simulator mode on the staging VPS since PR #472; Phala Cloud CVM (`TEE_MODE=cvm`) is the production target.

### Test Suites (`tests/`)

| Suite           | Name                    | Framework        | Purpose                                |
| --------------- | ----------------------- | ---------------- | -------------------------------------- |
| `tests/web-e2e` | `@cipherbox/web-e2e`    | Playwright ^1.48 | Browser E2E tests for web app          |
| `tests/sdk-e2e` | `@cipherbox/sdk-e2e`    | Vitest ^3.0.5    | SDK integration tests against live API |
| `tests/load`    | `@cipherbox/load-tests` | Vitest ^3.0.5    | Load and performance tests             |

### Tools (`tools/`)

| Tool                      | Framework | Purpose                                        |
| ------------------------- | --------- | ---------------------------------------------- |
| `tools/mock-ipns-routing` | Fastify 5 | Mock delegated routing service for E2E testing |

### Cross-Language Test Vectors (`tests/vectors/`)

- `tests/vectors/crypto/` - AES-GCM, ECIES, Ed25519, HKDF, IPNS name vectors
- `tests/vectors/core/` - Bin metadata, folder metadata, IPNS record, vault blob vectors

Used by both TypeScript (`@cipherbox/crypto`) and Rust (`cipherbox-crypto`) to verify cross-language parity. CI runs `scripts/check-vector-parity.sh` in the `vector-parity` job.

## Frameworks

**Core:**

- NestJS ^11.0.0 - Backend API framework (`apps/api`)
- React ^18.3.1 - Web frontend UI (`apps/web`)
- Tauri 2 - Desktop app shell with native Rust backend (`apps/desktop`)
- Express ^4.21.0 - TEE worker HTTP server (`apps/tee-worker`)

**State Management:**

- Zustand ^5.0.10 - Client-side state in web app (`apps/web`)
- React Query / TanStack Query ^5.62.0 - Server state and caching (`apps/web`)

**Routing:**

- React Router DOM ^7.12.0 - Client-side routing (`apps/web`)

**Testing:**

- Vitest ^3.0.5 - Unit tests for all SDK packages, web app, SDK E2E, load tests
- Jest ^29.7.0 - Unit tests for API (`apps/api`)
- Playwright ^1.48.0 - Browser E2E tests (`tests/web-e2e`)
- `@vitest/coverage-v8` ^3.0.0 - Coverage for SDK packages and web app
- `cargo-llvm-cov` - Coverage for Rust crates (CI only)
- Codecov - Coverage reporting service
- `@faker-js/faker` ^9.0.0 - Test data generation (web E2E)
- `@johanneskares/wallet-mock` ^1.4.1 - Wallet mocking in E2E
- `axios-mock-adapter` ^2.1.0 - HTTP mock for api-client tests
- `supertest` ^7.2.2 - HTTP assertion library for API tests

**Build/Dev:**

- Vite ^7.3.0 - Web app dev server and bundler (`apps/web`)
- Vite ^6.0.0 - Desktop webview bundler (`apps/desktop`)
- tsup ^8.5.0 - TypeScript library bundler (all `packages/*`)
- NestJS CLI ^11.0.0 - API build and dev (`apps/api`)
- tsx ^4.21.0 - TypeScript execution for scripts, tee-worker dev, mock-ipns-routing dev
- Cargo / rustc 1.93+ - Rust compilation (all `crates/*`, `apps/desktop/src-tauri`)

**Deployment:**

- phala CLI 1.1.13+ - Phala Cloud CVM deployment and management (`npm install -g phala`; no longer used in CI since PR #472 retired the staging CVM — kept for manual CVM management and future production deploys)

**Code Quality:**

- ESLint ^9.18.0 - Linting via flat config at `eslint.config.js`
- Prettier ^3.4.2 - Formatting via `prettier.config.js`
- typescript-eslint ^8.21.0 - TypeScript-specific lint rules
- Husky ^9.1.7 - Git hooks (`.husky/pre-commit`, `.husky/commit-msg`)
- lint-staged ^15.4.3 - Staged file linting
- commitlint ^20.4.1 - Conventional commit enforcement (`commitlint.config.js`)
- markdownlint-cli ^0.47.0 - Markdown linting

**API Tooling:**

- `@nestjs/swagger` ^11.0.0 - OpenAPI spec generation from decorators (`apps/api`)
- Orval ^7.3.0 - API client generation from OpenAPI spec (`packages/api-client`)

## Key Dependencies

### Backend API (`apps/api/package.json`)

**Database & ORM:**

- `@nestjs/typeorm` ^11.0.0 + `typeorm` ^0.3.28 - ORM and database access
- `pg` ^8.14.1 - PostgreSQL driver

**Job Queue:**

- `ioredis` ^5.9.2 - Redis client
- `@nestjs/bullmq` ^11.0.4 + `bullmq` ^5.67.3 - Background job processing

**Authentication:**

- `@nestjs/jwt` ^11.0.2 + `jose` ^6.1.3 - JWT signing and verification
- `@nestjs/passport` ^11.0.5 + `passport` ^0.7.0 + `passport-jwt` ^4.0.1 - Auth strategies
- `viem` ^2.44.4 - Ethereum signature verification for SIWE auth
- `argon2` ^0.44.0 - Password hashing for device approval tokens

**Infrastructure:**

- `@nestjs/config` ^4.0.0 - Environment configuration
- `@nestjs/throttler` ^6.5.0 - Rate limiting
- `@nestjs/terminus` ^11.0.0 - Health checks
- `prom-client` ^15.1.3 - Prometheus metrics
- `class-validator` ^0.14.3 + `class-transformer` ^0.5.1 - DTO validation
- `@sendgrid/mail` ^8.1.6 - Email OTP delivery
- `cookie-parser` ^1.4.7 - Cookie parsing for refresh tokens

### Web Frontend (`apps/web/package.json`)

**Auth & Wallet:**

- `@web3auth/mpc-core-kit` ^3.5.0 - MPC-TSS key management
- `@web3auth/ethereum-mpc-provider` ^9.7.0 - Ethereum provider for Web3Auth
- `@toruslabs/tss-dkls-lib` ^4.1.0 - TSS-DKLS threshold signing
- `@tkey/common-types` ^15.1.0 - tKey type definitions
- `viem` ^2.44.4 + `wagmi` ^3.3.4 - Ethereum wallet integration

**HTTP & State:**

- `axios` ^1.13.2 - HTTP client (used by api-client)
- `zustand` ^5.0.10 - Client state management
- `@tanstack/react-query` ^5.62.0 - Server state and caching

**UI:**

- `@floating-ui/react` ^0.27.16 - Tooltip/popover positioning
- `react-dropzone` ^14.3.8 - File upload drag-and-drop
- `minisearch` ^7.2.0 - Client-side full-text search indexing
- `pdfjs-dist` ^5.4.624 - PDF preview rendering
- `react-router-dom` ^7.12.0 - Client-side routing

**Polyfills:**

- `buffer` ^6.0.3 - Buffer polyfill for browser
- `process` ^0.11.10 - Process polyfill for browser
- `stream-browserify` ^3.0.0 + `readable-stream` ^4.7.0 - Stream polyfills
- `vite-plugin-node-polyfills` ^0.25.0 - Node.js polyfills for Vite
- `@rollup/plugin-inject` ^5.0.5 + `@rollup/plugin-replace` ^6.0.3 - Build-time polyfill injection

### TypeScript SDK -- Crypto (`packages/crypto/package.json`)

- `eciesjs` ^0.4.16 - ECIES encryption (secp256k1)
- `@noble/ed25519` ^2.2.3 - Ed25519 signing
- `@noble/hashes` ^1.7.1 - SHA-256, HKDF
- `@libp2p/crypto` ^5.1.13 - libp2p key handling
- `@libp2p/peer-id` ^6.0.4 - Peer ID derivation
- `ipns` ^10.1.3 - IPNS record creation/validation
- `multiformats` ^13.4.2 - CID/multicodec encoding

### Rust Workspace (`Cargo.toml`)

**Crypto:**

- `aes-gcm` 0.10 - AES-256-GCM encryption
- `aes` 0.8 + `ctr` 0.9 - AES-256-CTR streaming encryption
- `ecies` 0.2 (pure mode, no default features) - ECIES encryption
- `ed25519-dalek` 2 (rand_core, zeroize) - Ed25519 signing
- `hkdf` 0.12 + `sha2` 0.10 - Key derivation
- `zeroize` 1 - Secure memory wiping

**Encoding:**

- `serde` 1 + `serde_json` 1 - Serialization
- `hex` 0.4 + `base64` 0.22 - Encoding
- `prost` 0.13 - Protocol Buffers
- `ciborium` 0.2 - CBOR encoding

**Async/HTTP:**

- `tokio` 1 (full features) - Async runtime
- `reqwest` 0.12 (json, rustls-tls, multipart) - HTTP client

**Error Handling:**

- `thiserror` 2 - Derive macro for error types
- `log` 0.4 - Logging facade

### Desktop App (`apps/desktop/src-tauri/Cargo.toml`)

**Tauri Plugins:**

- `tauri` 2 (tray-icon, image-png, image-ico) - Desktop app framework
- `tauri-plugin-deep-link` 2 - OAuth deep link handling
- `tauri-plugin-autostart` 2 - Launch at login
- `tauri-plugin-shell` 2 - Shell command execution
- `tauri-plugin-notification` 2 - System notifications
- `tauri-plugin-updater` 2 - Auto-update

**System:**

- `keyring` 3 (apple-native, windows-native, linux-native-sync-persistent) - OS keychain
- `fuser` 0.16 (vendored at `apps/desktop/src-tauri/vendor/fuser/`) - FUSE bindings with socket-read patch
- `winfsp` 0.12 (optional, Windows) - WinFSP bindings
- `dirs` 5 - Standard directory paths
- `clap` 4 (derive) - CLI argument parsing
- `env_logger` 0.11 - Log output configuration

### TEE Worker (`apps/tee-worker/package.json`)

**Shared workspace packages:**

- `@cipherbox/crypto` workspace:\* - Cryptographic primitives (ECIES, Ed25519, HKDF, IPNS)
- `@cipherbox/core` workspace:\* - Domain types, metadata schemas, IPNS record creation
- `@cipherbox/sdk-core` workspace:\* - Stateless orchestration (pinning providers, IPFS operations)

**TEE-specific dependencies:**

- `express` ^4.21.0 - HTTP server
- `@phala/dstack-sdk` ^0.5.7 - Hardware-backed key derivation inside Phala Cloud CVM
- `@noble/secp256k1` ^2.2.3 - secp256k1 key operations (simulator mode fallback)
- `@noble/hashes` ^1.7.0 - HKDF hash functions (simulator mode fallback)
- `prom-client` ^15.1.3 - Prometheus metrics (GET /metrics endpoint)

**Removed (now provided by shared packages):**

- ~~`eciesjs`~~ - replaced by `@cipherbox/crypto` ECIES
- ~~`@noble/ed25519`~~ - replaced by `@cipherbox/crypto` Ed25519
- ~~`ipns`~~ - replaced by `@cipherbox/core` IPNS
- ~~`@libp2p/crypto`~~ - replaced by `@cipherbox/crypto`
- ~~`multiformats`~~ - replaced by `@cipherbox/core`

## Configuration

**TypeScript Base:** `tsconfig.base.json`

- Target: ES2022, Module: ESNext, ModuleResolution: bundler
- Strict mode, strictNullChecks, noUnusedLocals, noUnusedParameters, noImplicitReturns
- All packages extend this base

**API TypeScript:** `apps/api/tsconfig.json`

- Extends base; overrides: CommonJS module, node moduleResolution
- emitDecoratorMetadata + experimentalDecorators enabled (NestJS requirement)

**Web TypeScript:** `apps/web/tsconfig.json`

- Extends base; overrides: ES2020 target, react-jsx, noEmit

**TEE Worker TypeScript:** `apps/tee-worker/tsconfig.json`

- Standalone (does not extend base): ES2022 target, ES2022 module, bundler resolution

**ESLint:** `eslint.config.js` (flat config)

- typescript-eslint recommended rules
- Prettier integration via `eslint-plugin-prettier`
- `@typescript-eslint/no-unused-vars` error (ignoring `^_` prefix)
- `@typescript-eslint/no-explicit-any` warn
- Ignores: dist, node_modules, .planning, .claude, 00-Preliminary-R&D, .learnings, src-tauri/target

**Prettier:** `prettier.config.js`

```javascript
{ semi: true, singleQuote: true, tabWidth: 2, trailingComma: 'es5', printWidth: 100 }
```

**Commitlint:** `commitlint.config.js`

- Extends `@commitlint/config-conventional`
- Custom rule: subject must not contain parenthesized text (breaks Release Please parsing)

**Git Hooks:** `.husky/`

- `pre-commit` - Runs lint-staged (ESLint + Prettier on staged TS/JS/JSON/YAML/MD)
- `commit-msg` - Runs commitlint

**Vite (Web):** `apps/web/vite.config.ts`

- React plugin, buffer/process polyfills
- Dev server port 5173, COOP: same-origin-allow-popups header
- API proxy: `/api` -> `http://localhost:3000`

**Cargo (Rust):** Root `Cargo.toml`

- Workspace with 6 members (5 crates + `apps/desktop/src-tauri`)
- `[patch.crates-io]` for vendored fuser at `apps/desktop/src-tauri/vendor/fuser`
- Workspace dependencies centralized for version consistency

**Environment:**

- `apps/api/.env` - Database, Redis, IPFS, JWT, SendGrid, TEE config (see `.env.example`)
- `apps/web/.env` - Web3Auth client ID, API URL (see `.env.example`)
- `apps/desktop/.env` - Web3Auth client ID, Google OAuth, API URL, environment (see `.env.example`)
- `.env.example` files present for all three apps

## Build Commands

**Development:**

```bash
pnpm dev                              # Concurrent API + Web dev servers
pnpm --filter @cipherbox/api dev      # API only (nest start --watch, port 3000)
pnpm --filter @cipherbox/web dev      # Web only (vite dev, port 5173)
pnpm --filter @cipherbox/desktop dev  # Desktop (tauri dev)
```

**Build (SDK packages must be built in dependency order):**

```bash
pnpm --filter @cipherbox/crypto build     # 1. Crypto primitives
pnpm --filter @cipherbox/core build       # 2. Domain types
pnpm --filter @cipherbox/api-client build # 3. API client
pnpm --filter @cipherbox/sdk-core build   # 4. SDK core
pnpm --filter @cipherbox/sdk build        # 5. SDK facade
pnpm --filter @cipherbox/api build        # 6. API (nest build)
pnpm --filter @cipherbox/web build        # 7. Web (tsc + vite build + SW build)
pnpm build                                # Build all (no guaranteed order)
cargo check --workspace                   # Check all Rust crates
cargo build --workspace                   # Build all Rust crates
```

**API Client Generation:**

```bash
pnpm api:generate  # OpenAPI spec -> regenerate typed client -> build -> lint fix
```

**Testing:**

```bash
pnpm test                                    # All unit tests in parallel
pnpm --filter @cipherbox/api test:cov        # API tests with coverage (Jest)
pnpm --filter @cipherbox/crypto test:coverage # Crypto tests with coverage (Vitest)
pnpm --filter @cipherbox/core test:coverage   # Core tests with coverage (Vitest)
pnpm --filter @cipherbox/sdk-core test:coverage
pnpm --filter @cipherbox/sdk test:coverage
pnpm --filter @cipherbox/api-client test:coverage
pnpm test:web-e2e                            # Web E2E (Playwright, needs mock-ipns-routing)
pnpm --filter @cipherbox/sdk-e2e test        # SDK E2E (Vitest, needs running API)
pnpm --filter @cipherbox/load-tests test     # Load tests (Vitest, needs running API)
cargo test --workspace                       # All Rust tests
```

**Type Checking:**

```bash
pnpm typecheck  # Builds all SDK packages then type-checks web app
```

**Linting:**

```bash
pnpm lint       # ESLint all TS/JS files
pnpm lint:fix   # ESLint with auto-fix
pnpm lint:md    # Markdownlint all .md files
```

**Database Migrations:**

```bash
pnpm --filter @cipherbox/api migrate:dev         # Run migrations
pnpm --filter @cipherbox/api migration:run        # Run migrations (alias)
pnpm --filter @cipherbox/api migration:revert     # Revert last migration
pnpm --filter @cipherbox/api migration:generate   # Generate migration from entity diff
```

## Platform Requirements

**Development (macOS):**

- Node.js 22+, pnpm 10+
- Rust stable 1.93+
- FUSE-T (for desktop FUSE mount, `brew install --cask fuse-t`)
- PostgreSQL 16, IPFS Kubo v0.40.0, Redis 7 (local or remote host)

**CI (GitHub Actions):**

- Ubuntu latest - lint, typecheck, test, build, SDK E2E, vector parity, Linux Cargo
- Ubuntu 22.04 - Linux Cargo check/test/coverage (system deps: libfuse3-dev, etc.)
- macOS latest - macOS Cargo check/test with FUSE-T
- Windows latest - Windows Cargo check/test with WinFsp 2.1
- Service containers: PostgreSQL 16-alpine, Kubo v0.40.0, Redis 7-alpine

**Staging:**

- VPS at 76.13.151.200 (Hostinger)
- Docker Compose: API (node:22-alpine) + supporting services
- TEE Worker: local Docker Compose service in simulator mode (node:20-alpine image on GHCR; was an external Phala Cloud CVM until PR #472)
- Caddy reverse proxy for HTTPS
- Domains: `api-staging.cipherbox.cc`, `app-staging.cipherbox.cc`
- Container registry: `ghcr.io`

**Production Docker Images:**

- API: `node:22-alpine` multi-stage build (`apps/api/Dockerfile`)
- TEE Worker: `node:20-alpine` multi-stage build (`apps/tee-worker/Dockerfile`)

## Release and Versioning

**Tool:** Release Please (Google)

- Config: `release-please-config.json`
- Manifest: `.release-please-manifest.json`
- All packages share unified root version (0.30.1); individual packages/crates also tracked
- Conventional Commits drive version bumps (feat = minor, fix = patch)
- Root tag format: `cipher-box-vX.Y.Z` (uses `include-component-in-tag: true`)
- Staging deploy tags: `staging-v<version>-rc-<N>` (triggers `deploy-staging.yml`)

**CI Workflows (`/.github/workflows/`):**

| Workflow             | Trigger                              | Purpose                                                                                                              |
| -------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| `ci.yml`             | PR to main                           | Lint, typecheck, test, build, API spec verify, migration drift check, Cargo check/test on 3 platforms, vector parity |
| `e2e.yml`            | Push to main, dispatch               | Web E2E tests with Playwright                                                                                        |
| `release-please.yml` | Push to main                         | Create/update release PR, publish GitHub Releases                                                                    |
| `deploy-staging.yml` | Push `staging-v*` tag, workflow_call | Build Docker images, deploy API/web/TEE worker to staging VPS                                                        |
| `build-desktop.yml`  | -                                    | Desktop app build                                                                                                    |
| `desktop-e2e.yml`    | -                                    | Desktop E2E tests                                                                                                    |
| `load-test.yml`      | -                                    | Load test runs                                                                                                       |
| `pr-title.yml`       | -                                    | PR title validation                                                                                                  |
| `release-gate.yml`   | -                                    | Release gating checks                                                                                                |
| `tag-staging.yml`    | -                                    | Create staging tags                                                                                                  |
| `codecov-base.yml`   | -                                    | Base branch coverage upload                                                                                          |

## Cryptography Stack

**Symmetric Encryption:**

- AES-256-GCM - File and metadata encryption (Web Crypto API in TS; `aes-gcm` crate in Rust)
- AES-256-CTR - Streaming encryption for large files and media playback (Web Crypto API in TS; `aes`+`ctr` crates in Rust)

**Asymmetric Encryption:**

- ECIES (secp256k1) - Key wrapping via `eciesjs` (TS) / `ecies` pure mode (Rust)
- ECDSA (secp256k1) - Keypair from Web3Auth MPC Core Kit
- Ed25519 - IPNS record signing via `@noble/ed25519` (TS) / `ed25519-dalek` (Rust)

**Key Derivation:**

- HKDF-SHA256 - Deterministic IPNS keypair and folder key derivation
- Random generation - Content encryption keys via `crypto.getRandomValues()` (TS) / `rand` (Rust)

**Memory Safety:**

- `zeroize` crate - Secure memory wiping for all key material in Rust
- Manual clearing in TypeScript (best effort)

---

<!-- Stack analysis: 2026-03-29 -->
