# Codebase Structure

**Analysis Date:** 2026-03-27

## Directory Layout

```text
cipher-box/
├── apps/                          # Deployable applications
│   ├── api/                       # NestJS backend API
│   │   ├── src/
│   │   │   ├── auth/              # Authentication (Web3Auth, identity providers, JWT)
│   │   │   │   ├── controllers/   # Identity controller (Google, Email, SIWE)
│   │   │   │   ├── decorators/    # Allow-scope decorator
│   │   │   │   ├── dto/           # Login, token, identity DTOs
│   │   │   │   ├── entities/      # User, RefreshToken, AuthMethod
│   │   │   │   ├── guards/        # JWT auth guard
│   │   │   │   ├── services/      # Auth-method, email-otp, google-oauth, SIWE, token, JWT-issuer, web3auth-verifier, test-auth
│   │   │   │   └── strategies/    # Passport JWT strategy
│   │   │   ├── common/            # Shared guards, types, Redis module
│   │   │   ├── device-approval/   # Cross-device MFA bulletin board
│   │   │   ├── health/            # Health check endpoint
│   │   │   ├── ipfs/              # IPFS upload/download relay (Kubo provider)
│   │   │   ├── ipns/              # IPNS publish/resolve relay (delegated routing)
│   │   │   ├── metrics/           # Prometheus metrics (prom-client)
│   │   │   ├── migration/         # CID migration between pinning providers
│   │   │   ├── migrations/        # TypeORM migration files
│   │   │   ├── republish/         # BullMQ IPNS republish scheduling
│   │   │   ├── shares/            # Share CRUD, share keys, share invites
│   │   │   ├── tee/               # TEE key epoch management
│   │   │   ├── vault/             # Vault init/retrieval, quota, pinned CIDs
│   │   │   ├── app.module.ts      # Root NestJS module
│   │   │   ├── data-source.ts     # TypeORM data source config
│   │   │   └── main.ts            # Bootstrap entry point
│   │   ├── scripts/               # OpenAPI generation script
│   │   └── test/                  # E2E test config
│   ├── desktop/                   # Tauri v2 desktop application
│   │   ├── src/                   # Tauri webview TypeScript
│   │   │   ├── auth.ts            # Web3Auth Core Kit auth (Google, Email, SIWE, MFA)
│   │   │   ├── main.ts            # Webview entry point
│   │   │   └── polyfills.ts       # Browser polyfills
│   │   ├── src-tauri/             # Rust backend
│   │   │   ├── src/
│   │   │   │   ├── commands/      # Tauri IPC commands (auth, vault, sync, OAuth, debug)
│   │   │   │   ├── fuse/          # FUSE mount, debounced publish (+ Windows subdir)
│   │   │   │   ├── registry/      # Device registry (IPNS-based)
│   │   │   │   ├── sync/          # Background sync daemon
│   │   │   │   ├── tray/          # System tray icon and menu
│   │   │   │   ├── keychain.rs    # Platform credential storage
│   │   │   │   ├── main.rs        # Rust entry point
│   │   │   │   ├── state.rs       # Global AppState
│   │   │   │   └── updater.rs     # Auto-updater
│   │   │   ├── vendor/            # Vendored fuser crate (patched for FUSE-T)
│   │   │   └── Cargo.toml         # Desktop crate dependencies
│   │   └── public/                # Static assets (Google callback, icons)
│   └── web/                       # React web application
│       ├── src/
│       │   ├── components/        # UI components
│       │   │   ├── auth/          # Login forms (Email, Google, Wallet)
│       │   │   ├── file-browser/  # File list, upload, download, dialogs, context menu
│       │   │   ├── layout/        # Shell, header, sidebar, footer
│       │   │   ├── mfa/           # MFA challenge UI
│       │   │   ├── settings/      # Settings tabs
│       │   │   ├── ui/            # Reusable UI primitives
│       │   │   └── vault/         # Vault init components
│       │   ├── hooks/             # React hooks (30+ custom hooks)
│       │   ├── lib/               # Non-React utilities
│       │   │   ├── api/           # API helper functions (auth, vault, ipfs)
│       │   │   ├── crypto/        # Web Crypto API helpers
│       │   │   ├── device/        # Device identity and info
│       │   │   ├── wagmi/         # Wagmi wallet provider config
│       │   │   ├── web3auth/      # Core Kit provider and hooks
│       │   │   ├── api-config.ts  # Axios instance + API client config
│       │   │   ├── sdk-provider.ts # CipherBoxClient singleton lifecycle
│       │   │   └── sw-registration.ts # Service worker registration
│       │   ├── routes/            # Page components (7 routes)
│       │   ├── services/          # Business logic (15 service files)
│       │   ├── stores/            # Zustand stores (12 stores)
│       │   ├── styles/            # Global CSS
│       │   ├── utils/             # Utility functions
│       │   ├── workers/           # Service workers (decrypt-sw.ts)
│       │   ├── App.tsx            # Root component
│       │   └── main.tsx           # React entry point
│       └── public/                # Static assets
├── packages/                      # Shared TypeScript SDK packages
│   ├── crypto/                    # @cipherbox/crypto - Pure crypto primitives
│   │   └── src/
│   │       ├── aes/               # AES-256-GCM and AES-256-CTR
│   │       ├── ecies/             # ECIES secp256k1 key wrapping
│   │       ├── ed25519/           # Ed25519 signing
│   │       ├── device/            # Device identity keypair
│   │       ├── ipns/              # IPNS name derivation
│   │       ├── keys/              # HKDF key derivation
│   │       ├── utils/             # Byte helpers, key generation
│   │       ├── vault/             # Vault IPNS keypair derivation
│   │       ├── constants.ts       # Crypto constants
│   │       ├── types.ts           # CryptoError, VaultKey, EncryptedData
│   │       └── index.ts           # Public API exports
│   ├── core/                      # @cipherbox/core - Domain types and metadata
│   │   └── src/
│   │       ├── bin/               # RecycleBinMetadata, encrypt/decrypt
│   │       ├── file/              # FileMetadata, FilePointer, encrypt/decrypt, IPNS derivation
│   │       ├── folder/            # FolderMetadata, FolderChild, encrypt/decrypt
│   │       ├── ipns/              # IPNS record creation, marshaling, signing
│   │       ├── registry/          # DeviceRegistry, encrypt/decrypt
│   │       ├── vault/             # Vault init, key encrypt/decrypt, blob v2 format
│   │       └── index.ts           # Public API exports
│   ├── api-client/                # @cipherbox/api-client - Generated HTTP client
│   │   └── src/
│   │       ├── generated/         # Orval-generated API functions (DO NOT EDIT)
│   │       │   ├── auth/
│   │       │   ├── device-approval/
│   │       │   ├── health/
│   │       │   ├── identity/
│   │       │   ├── invites/
│   │       │   ├── ipfs/
│   │       │   ├── ipns/
│   │       │   ├── root/
│   │       │   ├── share-invites/
│   │       │   ├── shares/
│   │       │   ├── tee/
│   │       │   └── vault/
│   │       ├── models/            # Generated TypeScript types
│   │       ├── instance.ts        # Axios instance, config, interceptors
│   │       └── index.ts           # Re-exports all generated + config
│   ├── sdk-core/                  # @cipherbox/sdk-core - Stateless orchestration
│   │   └── src/
│   │       ├── download/          # downloadAndDecrypt
│   │       ├── file/              # createFileMetadata, resolveFileMetadata, updateFileMetadata
│   │       ├── folder/            # fetchAndDecryptMetadata, createSubfolder, updateFolderMetadataAndPublish
│   │       ├── ipfs/              # addToIpfs, fetchFromIpfs, unpinFromIpfs
│   │       ├── ipns/              # createAndPublishIpnsRecord, resolveIpnsRecord, verifyIpnsSignature
│   │       ├── pinning/           # BYO-IPFS providers (Kubo, PSA, Pinata, DualPin)
│   │       ├── upload/            # uploadFile
│   │       ├── vault/             # publishVaultKeyBlob, loadVaultKeyBlob
│   │       ├── perf.ts            # Performance instrumentation (withPerf)
│   │       ├── types.ts           # SdkContext, TeeKeys, ProgressCallback
│   │       └── index.ts           # Public API exports
│   └── sdk/                       # @cipherbox/sdk - Stateful client
│       └── src/
│           ├── bin/               # Recycle bin operations
│           ├── share/             # Share operations, shared-write operations
│           ├── state/             # FolderTree, KeyCache
│           ├── client.ts          # CipherBoxClient class
│           ├── events.ts          # SdkEvent types, SdkEventEmitter
│           ├── types.ts           # CipherBoxClientConfig, FolderState
│           └── index.ts           # Public API exports
├── crates/                        # Rust crate workspace (mirrors packages/)
│   ├── crypto/                    # cipherbox-crypto - Pure crypto
│   │   └── src/
│   │       ├── aes.rs, aes_ctr.rs # AES-256-GCM/CTR
│   │       ├── ecies.rs           # ECIES wrapping
│   │       ├── ed25519.rs         # Ed25519 signing
│   │       ├── hkdf.rs            # HKDF key derivation
│   │       ├── ipns_name.rs       # IPNS name derivation
│   │       ├── utils.rs           # Byte helpers
│   │       └── lib.rs             # Crate root
│   ├── core/                      # cipherbox-core - Domain types
│   │   └── src/
│   │       ├── folder.rs, file.rs, bin.rs, registry.rs
│   │       ├── vault_blob.rs      # v2 blob serialize/deserialize
│   │       ├── ipns.rs            # IPNS record creation
│   │       ├── decrypt.rs         # Metadata decryption from IPFS
│   │       └── lib.rs             # Crate root
│   ├── api-client/                # cipherbox-api-client - HTTP client
│   │   └── src/
│   │       ├── auth.rs, ipfs.rs, ipns.rs
│   │       ├── client.rs          # ApiClient struct
│   │       ├── types.rs           # Request/response types
│   │       └── lib.rs             # Crate root
│   ├── sdk/                       # cipherbox-sdk - Stateful client
│   │   └── src/
│   │       ├── client.rs          # CipherBoxSdkClient
│   │       ├── queue.rs           # WriteQueue
│   │       ├── state.rs           # KeyState, SyncStatus
│   │       ├── sync.rs            # SyncDaemon
│   │       ├── registry.rs        # Device registry
│   │       └── lib.rs             # Crate root
│   └── fuse/                      # cipherbox-fuse - FUSE filesystem
│       └── src/
│           ├── inode.rs           # InodeTable
│           ├── cache.rs           # MetadataCache, ContentCache
│           ├── file_handle.rs     # OpenFileHandle
│           ├── operations.rs      # FUSE callbacks (feature: fuse)
│           ├── read_ops.rs        # Read operations (feature: fuse)
│           ├── write_ops.rs       # Write operations (feature: fuse)
│           ├── dir_ops.rs         # Directory operations (feature: fuse)
│           ├── platform/          # Platform-specific code
│           └── lib.rs             # Crate root
├── tee-worker/                    # TEE IPNS republishing worker
│   └── src/
│       ├── middleware/            # Auth middleware
│       ├── routes/                # health, public-key, republish, migrate, connection-test
│       ├── services/              # Crypto services
│       ├── types/                 # Type definitions
│       └── index.ts               # Express entry point
├── tests/                         # Test suites
│   ├── web-e2e/                   # Playwright browser E2E tests
│   │   ├── tests/                 # Test specs
│   │   ├── page-objects/          # Page object models
│   │   ├── fixtures/              # Test fixtures
│   │   └── utils/                 # Test helpers
│   ├── sdk-e2e/                   # SDK integration tests
│   │   └── src/                   # Test files
│   ├── desktop-e2e/               # Desktop E2E tests
│   │   ├── fixtures/              # Test fixtures
│   │   └── scripts/               # Test scripts
│   ├── load/                      # Load testing (k6 or similar)
│   │   └── src/                   # Load test scenarios
│   └── vectors/                   # Cross-platform test vectors
│       ├── core/                  # Core metadata test vectors
│       └── crypto/                # Crypto operation test vectors
├── tools/                         # Development tools
│   └── mock-ipns-routing/         # Mock delegated routing for E2E tests
│       └── src/                   # Express mock server
├── docker/                        # Docker/infrastructure configs
│   └── grafana/                   # Grafana dashboards, alerts, scripts
├── docs/                          # Project documentation
├── designs/                       # Pencil design files (.pen)
├── scripts/                       # Root-level utility scripts
├── 00-Preliminary-R&D/            # Finalized specifications (DO NOT MODIFY)
│   ├── Documentation/             # PRD, Technical Architecture, API Spec, etc.
│   └── poc/                       # Console proof-of-concept (historical)
├── .planning/                     # GSD planning artifacts
│   ├── codebase/                  # Codebase analysis (this file)
│   ├── phases/                    # Phase planning documents
│   ├── quick/                     # Quick task planning
│   ├── milestones/                # Milestone tracking
│   ├── adr/                       # Architecture decision records
│   ├── research/                  # Research notes
│   ├── security/                  # Security analysis
│   └── todos/                     # TODO tracking (pending/done)
├── Cargo.toml                     # Rust workspace root
├── package.json                   # Root package.json (scripts, devDeps)
├── pnpm-workspace.yaml            # pnpm workspace config
├── turbo.json                     # Turborepo build config (if present)
└── tsconfig.json                  # Root TypeScript config
```

## Directory Purposes

**`apps/api/`:**

- Purpose: NestJS backend API server
- Contains: Controllers, services, entities, DTOs, migrations, guards
- Key files: `src/main.ts` (entry), `src/app.module.ts` (root module), `src/data-source.ts` (TypeORM config)
- Build: `pnpm --filter api build` (NestJS CLI -> `dist/`)

**`apps/web/`:**

- Purpose: React web application (file browser, auth, settings)
- Contains: Components, hooks, stores, services, routes, workers
- Key files: `src/main.tsx` (entry), `src/App.tsx` (root), `src/lib/sdk-provider.ts` (SDK lifecycle)
- Build: `pnpm --filter web build` (Vite -> `dist/`)

**`apps/desktop/`:**

- Purpose: Tauri v2 desktop app with FUSE mount
- Contains: TypeScript webview (auth) + Rust backend (FUSE, sync, keychain)
- Key files: `src/auth.ts` (webview auth), `src-tauri/src/main.rs` (Rust entry)
- Build: `pnpm --filter desktop build` (Tauri CLI)

**`packages/crypto/`:**

- Purpose: Pure cryptographic primitives shared by all TypeScript consumers
- Contains: AES, ECIES, Ed25519, HKDF, key generation, byte utilities
- Key files: `src/index.ts` (public API), `src/aes/`, `src/ecies/`, `src/ed25519/`
- Build: `tsup` -> `dist/`

**`packages/core/`:**

- Purpose: CipherBox domain types, metadata schemas, vault init
- Contains: FolderMetadata, FileMetadata, DeviceRegistry, RecycleBinMetadata, IPNS records, vault blob v2
- Key files: `src/index.ts`, `src/folder/types.ts`, `src/file/types.ts`, `src/vault/blob.ts`
- Build: `tsup` -> `dist/`

**`packages/api-client/`:**

- Purpose: Generated typed HTTP client from OpenAPI spec
- Contains: Orval-generated API functions, model types, axios instance configuration
- Key files: `src/index.ts`, `src/instance.ts`, `src/generated/` (auto-generated)
- Build: `tsup` -> `dist/`. Regenerate: `pnpm api:generate`

**`packages/sdk-core/`:**

- Purpose: Stateless orchestration functions (upload, download, IPNS, folder CRUD, vault blob)
- Contains: Function modules organized by concern, no state management
- Key files: `src/index.ts`, `src/types.ts` (SdkContext), `src/upload/`, `src/download/`, `src/vault/`
- Build: `tsup` -> `dist/`

**`packages/sdk/`:**

- Purpose: Stateful SDK client with event system
- Contains: CipherBoxClient, FolderTree, KeyCache, bin/share operations, SdkEvent types
- Key files: `src/client.ts`, `src/events.ts`, `src/share/`, `src/state/`
- Build: `tsup` -> `dist/`

**`crates/`:**

- Purpose: Rust crate workspace mirroring TypeScript packages
- Contains: crypto, core, api-client, sdk, fuse crates
- Key files: Each crate's `src/lib.rs`
- Build: `cargo build` (workspace root)

**`tee-worker/`:**

- Purpose: Standalone TEE worker for IPNS republishing (Phala Cloud)
- Contains: Express routes, crypto services, auth middleware
- Key files: `src/index.ts` (entry), `src/routes/republish.ts`
- Build: `tsc` -> `dist/`

**`tests/`:**

- Purpose: Integration, E2E, and load test suites
- Contains: Playwright tests, SDK E2E, desktop E2E, load tests, cross-platform test vectors
- Key files: `web-e2e/tests/`, `sdk-e2e/src/`, `vectors/`

## Key File Locations

**Entry Points:**

- `apps/api/src/main.ts`: Backend API bootstrap
- `apps/web/src/main.tsx`: Web app React root
- `apps/desktop/src/main.ts`: Desktop webview entry
- `apps/desktop/src-tauri/src/main.rs`: Desktop Rust entry
- `tee-worker/src/index.ts`: TEE worker Express entry

**Configuration:**

- `package.json`: Root workspace scripts and devDeps
- `pnpm-workspace.yaml`: Workspace package locations (`apps/*`, `packages/*`, `tests/*`)
- `Cargo.toml`: Rust workspace members and shared dependencies
- `apps/api/src/data-source.ts`: TypeORM database configuration
- `apps/api/src/app.module.ts`: NestJS module registration
- `apps/desktop/src-tauri/Cargo.toml`: Desktop Rust dependencies + feature flags

**SDK Public APIs:**

- `packages/crypto/src/index.ts`: Crypto exports (AES, ECIES, Ed25519, HKDF, utilities)
- `packages/core/src/index.ts`: Domain type exports (FolderMetadata, FileMetadata, vault, IPNS)
- `packages/api-client/src/index.ts`: Generated API client exports
- `packages/sdk-core/src/index.ts`: Stateless operation exports (upload, download, IPNS, folder)
- `packages/sdk/src/index.ts`: Stateful client exports (CipherBoxClient, events, share ops)

**Generated Code (DO NOT EDIT):**

- `packages/api-client/src/generated/`: Orval-generated API functions
- `packages/api-client/src/models/`: Orval-generated TypeScript types

## Naming Conventions

**Files:**

- TypeScript source: `kebab-case.ts` or `camelCase.ts` (e.g., `vault-blob.ts`, `fileHandle.ts`)
- React components: `PascalCase.tsx` (e.g., `FileBrowser.tsx`, `ShareDialog.tsx`)
- Zustand stores: `kebab-case.store.ts` (e.g., `auth.store.ts`, `folder.store.ts`)
- Services: `kebab-case.service.ts` (e.g., `upload.service.ts`)
- Hooks: `camelCase.ts` with `use` prefix (e.g., `useAuth.ts`, `useFileUpload.ts`)
- NestJS: `kebab-case.{controller,service,module,entity,dto}.ts`
- Rust: `snake_case.rs` (e.g., `vault_blob.rs`, `file_handle.rs`)
- Test files: `*.spec.ts` (API unit), `*.test.ts` (packages), `*.spec.ts` (E2E)

**Directories:**

- TypeScript packages: `kebab-case` (e.g., `api-client`, `sdk-core`)
- Rust crates: `kebab-case` (e.g., `api-client`, `fuse`)
- NestJS modules: `kebab-case` (e.g., `device-approval`, `shares`)
- React components: `kebab-case` directories (e.g., `file-browser`, `auth`)

**Code:**

- Types/Interfaces: `PascalCase` (e.g., `FolderMetadata`, `FilePointer`, `SdkContext`)
- Functions: `camelCase` (e.g., `encryptAesGcm`, `fetchAndDecryptMetadata`)
- Rust functions: `snake_case` (e.g., `encrypt_aes_gcm`, `derive_vault_ipns_keypair`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `AES_KEY_SIZE`, `BLOB_V2_VERSION`)
- API request fields: `camelCase` (e.g., `rootFolderKey`, `ipnsName`)
- Database columns: `snake_case` (e.g., `encrypted_ipns_key`, `key_epoch`)

## Where to Add New Code

**New SDK Feature (shared between web and desktop):**

1. Pure crypto: `packages/crypto/src/` (if new cryptographic primitive)
2. Domain types: `packages/core/src/` (if new metadata schema or type)
3. Stateless operation: `packages/sdk-core/src/` (if new IPFS/IPNS/folder operation)
4. Stateful orchestration: `packages/sdk/src/` (if needs state management or events)
5. Rust equivalent: Mirror in corresponding `crates/` directory
6. Tests: Co-located `__tests__/` directory in each package
7. Cross-platform vectors: `tests/vectors/` for crypto/core parity verification

**New API Endpoint:**

1. Create/extend NestJS module in `apps/api/src/<module-name>/`
2. Add controller, service, DTOs, entities as needed
3. Run `pnpm api:generate` to regenerate `packages/api-client/`
4. Add migration in `apps/api/src/migrations/` if new entity (use `IF NOT EXISTS`)
5. Test: `apps/api/src/<module>/**.spec.ts` (Jest)

**New Web UI Feature:**

1. Component: `apps/web/src/components/<category>/ComponentName.tsx`
2. Hook: `apps/web/src/hooks/useFeatureName.ts`
3. Service: `apps/web/src/services/feature-name.service.ts` (if business logic)
4. Store: `apps/web/src/stores/feature-name.store.ts` (if new state domain)
5. Route: Add to `apps/web/src/routes/index.tsx`
6. Test: `apps/web/src/stores/__tests__/`, `tests/web-e2e/tests/`

**New Desktop Feature:**

1. Tauri command: `apps/desktop/src-tauri/src/commands/<name>.rs`
2. FUSE operation: `crates/fuse/src/` (platform-agnostic) or `apps/desktop/src-tauri/src/fuse/` (app-specific)
3. Webview UI: `apps/desktop/src/`
4. Register command in `apps/desktop/src-tauri/src/main.rs`

**New Utility/Helper:**

- Shared crypto: `packages/crypto/src/`
- Shared domain logic: `packages/core/src/`
- Web-only utility: `apps/web/src/utils/` or `apps/web/src/lib/`
- Rust-only utility: `crates/<appropriate-crate>/src/`

**New Test Suite:**

- API unit tests: `apps/api/src/<module>/<name>.spec.ts` (Jest)
- Package unit tests: `packages/<pkg>/src/__tests__/<name>.test.ts` (Vitest)
- Web E2E: `tests/web-e2e/tests/<feature>.spec.ts` (Playwright)
- SDK E2E: `tests/sdk-e2e/src/<name>.test.ts`
- Load tests: `tests/load/src/`
- Test vectors: `tests/vectors/{crypto,core}/`

## Special Directories

**`packages/api-client/src/generated/`:**

- Purpose: Orval-generated typed API client functions
- Generated: Yes (`pnpm api:generate`)
- Committed: Yes (committed alongside API changes)
- DO NOT EDIT manually -- regenerate after API endpoint changes

**`packages/api-client/src/models/`:**

- Purpose: Orval-generated TypeScript model types
- Generated: Yes (same as above)
- Committed: Yes

**`apps/desktop/src-tauri/vendor/fuser/`:**

- Purpose: Vendored fuser crate with socket-read patch for FUSE-T compatibility
- Generated: No (manually patched)
- Committed: Yes
- Critical patch: `src/channel.rs` loop-read for Unix domain socket fragmentation

**`apps/api/src/migrations/`:**

- Purpose: TypeORM database migrations (incremental, idempotent)
- Generated: Partially (TypeORM CLI generates skeleton, manually reviewed)
- Committed: Yes
- Pattern: Use `IF NOT EXISTS` for idempotency, timestamp ordering matters

**`tests/vectors/`:**

- Purpose: Cross-platform test vectors for crypto/core parity between TypeScript and Rust
- Generated: No (manually authored)
- Committed: Yes

**`00-Preliminary-R&D/Documentation/`:**

- Purpose: Finalized v1.11.1 specification documents
- Generated: No
- Committed: Yes
- DO NOT MODIFY -- create new docs in `.planning/` or `docs/`

**`.planning/`:**

- Purpose: GSD workflow planning, analysis, phase documents
- Generated: Yes (by GSD commands and agents)
- Committed: Yes

**`docker/`:**

- Purpose: Docker Compose configs, Grafana dashboards, deployment scripts
- Contains: `grafana/dashboards/`, `grafana/alerts/`, `grafana/scripts/`
- Used for: Staging/production infrastructure

## Implementation Status

| Component             | Location                   | Status                  |
| --------------------- | -------------------------- | ----------------------- |
| Backend API           | `apps/api/`                | Implemented             |
| Web Frontend          | `apps/web/`                | Implemented             |
| Desktop App           | `apps/desktop/`            | Implemented             |
| TEE Worker            | `tee-worker/`              | Implemented             |
| @cipherbox/crypto     | `packages/crypto/`         | Implemented             |
| @cipherbox/core       | `packages/core/`           | Implemented             |
| @cipherbox/api-client | `packages/api-client/`     | Implemented (generated) |
| @cipherbox/sdk-core   | `packages/sdk-core/`       | Implemented             |
| @cipherbox/sdk        | `packages/sdk/`            | Implemented             |
| cipherbox-crypto      | `crates/crypto/`           | Implemented             |
| cipherbox-core        | `crates/core/`             | Implemented             |
| cipherbox-api-client  | `crates/api-client/`       | Implemented             |
| cipherbox-sdk         | `crates/sdk/`              | Implemented             |
| cipherbox-fuse        | `crates/fuse/`             | Implemented             |
| Playwright E2E        | `tests/web-e2e/`           | Implemented             |
| SDK E2E               | `tests/sdk-e2e/`           | Implemented             |
| Test Vectors          | `tests/vectors/`           | Implemented             |
| Mock IPNS Routing     | `tools/mock-ipns-routing/` | Implemented             |

---

<!-- Structure analysis: 2026-03-27 -->
