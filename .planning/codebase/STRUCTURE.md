# Codebase Structure

**Analysis Date:** 2026-03-29

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
│   │   │   │   ├── services/      # auth-method, email-otp, google-oauth, SIWE, token, jwt-issuer, web3auth-verifier, test-auth
│   │   │   │   └── strategies/    # Passport JWT strategy
│   │   │   ├── common/            # Shared guards, pipes, Redis module, types
│   │   │   ├── device-approval/   # Cross-device MFA bulletin board
│   │   │   ├── health/            # Health check endpoint
│   │   │   ├── ipfs/              # IPFS upload/download relay
│   │   │   │   └── providers/     # Local (Kubo), PSA, Pinata, DualPin provider implementations
│   │   │   ├── ipns/              # IPNS publish/resolve relay (delegated routing)
│   │   │   │   └── __tests__/     # Integration and security specs
│   │   │   ├── metrics/           # Prometheus metrics (prom-client)
│   │   │   ├── migration/         # CID migration between pinning providers
│   │   │   ├── migrations/        # TypeORM incremental migration files (timestamped)
│   │   │   ├── republish/         # BullMQ IPNS republish scheduling
│   │   │   ├── shares/            # Share CRUD, share keys, share invites
│   │   │   ├── tee/               # TEE key epoch management and rotation log
│   │   │   ├── vault/             # Vault init/retrieval, quota, pinned CIDs
│   │   │   ├── app.module.ts      # Root NestJS module
│   │   │   ├── data-source.ts     # TypeORM data source config
│   │   │   └── main.ts            # Bootstrap entry point
│   │   └── test/                  # Jest E2E test config
│   ├── desktop/                   # Tauri v2 desktop application
│   │   ├── src/                   # Tauri webview TypeScript
│   │   │   ├── auth.ts            # Web3Auth Core Kit auth (Google, Email, SIWE, MFA)
│   │   │   ├── main.ts            # Webview entry point
│   │   │   └── polyfills.ts       # Browser polyfills
│   │   └── src-tauri/             # Rust backend
│   │       ├── src/
│   │       │   ├── commands/      # Tauri IPC commands (auth, vault, sync, OAuth, debug, util)
│   │       │   ├── fuse/          # FUSE mount + debounced publish (platform subdir for Windows)
│   │       │   ├── registry/      # Device registry sync
│   │       │   ├── sync/          # Background sync daemon
│   │       │   ├── tray/          # System tray icon and menu (status.rs)
│   │       │   ├── keychain.rs    # Platform credential storage (macOS Keychain / Windows Credential Store)
│   │       │   ├── main.rs        # Rust entry point
│   │       │   ├── state.rs       # Global AppState
│   │       │   └── updater.rs     # Auto-updater
│   │       ├── vendor/fuser/      # Vendored fuser crate (socket-read patch for FUSE-T)
│   │       └── Cargo.toml         # Desktop crate dependencies
│   └── web/                       # React web application
│       └── src/
│           ├── components/        # UI components
│           │   ├── auth/          # Login forms (EmailLoginForm, GoogleLoginButton, WalletLoginButton, LinkedMethods)
│           │   ├── file-browser/  # File list, upload, download, dialogs, context menu, shared browser
│           │   ├── layout/        # AppShell, AppHeader, AppSidebar, AppFooter, NavItem, StorageQuota
│           │   ├── mfa/           # MFA challenge UI, device approval, recovery phrase
│           │   ├── settings/      # StorageTab, SecurityTab, ConnectionTest, MigrationProgress
│           │   ├── ui/            # Reusable UI primitives (Modal, Portal)
│           │   └── vault/         # VaultExport component
│           ├── hooks/             # React hooks (30+ custom hooks — see Hook Inventory below)
│           ├── lib/               # Non-React utilities and infrastructure
│           │   ├── api/           # API helper functions (auth.ts, vault.ts, ipfs.ts, migration.ts)
│           │   ├── crypto/        # Web Crypto key wrapping helpers (key-wrapping.ts)
│           │   ├── device/        # Device identity (identity.ts) and info (info.ts)
│           │   ├── wagmi/         # Wagmi wallet provider config (config.ts, provider.tsx)
│           │   ├── web3auth/      # Core Kit provider (core-kit-provider.tsx, core-kit.ts, hooks.ts)
│           │   ├── api-config.ts  # Shared axios instance + orval singleton registration
│           │   ├── clear-user-stores.ts # Centralized Zustand store cleanup on logout
│           │   ├── errors.ts      # API error detection utilities (isConflictError, etc.)
│           │   ├── faro.ts        # Grafana Faro observability (Phase 30)
│           │   ├── logger.ts      # Structured logger with level filtering (Phase 28)
│           │   ├── sdk-provider.ts # CipherBoxClient singleton lifecycle
│           │   └── sw-registration.ts # Service worker registration
│           ├── routes/            # Page components (7 routes)
│           │   ├── FilesPage.tsx  # Main file browser route
│           │   ├── BinPage.tsx    # Recycle bin route
│           │   ├── SharedPage.tsx # Shared-with-me route
│           │   ├── SettingsPage.tsx
│           │   ├── InvitePage.tsx
│           │   ├── Login.tsx
│           │   └── index.tsx      # React Router route definitions
│           ├── services/          # Business logic (stateless, SDK-calling functions)
│           │   ├── bin.service.ts           # Bin/restore operations (~971 lines)
│           │   ├── delete.service.ts        # File/folder deletion
│           │   ├── device-approval.service.ts
│           │   ├── device-registry.service.ts
│           │   ├── download.service.ts      # File download orchestration
│           │   ├── file-crypto.service.ts   # Client-side file encryption/decryption
│           │   ├── file-metadata.service.ts # File metadata CRUD (~509 lines)
│           │   ├── folder.service.ts        # Folder navigation and mutations (~1059 lines)
│           │   ├── invite.service.ts        # Share invite handling (~332 lines)
│           │   ├── ipns.service.ts          # IPNS publish/resolve
│           │   ├── search-index.service.ts  # Client-side search index (~356 lines)
│           │   ├── share.service.ts         # Share key management (~507 lines)
│           │   ├── streaming-crypto.service.ts # Streaming AES-CTR encryption
│           │   ├── upload.service.ts        # File upload orchestration
│           │   └── index.ts                 # Barrel export
│           ├── stores/            # Zustand stores (12 stores)
│           │   ├── auth.store.ts
│           │   ├── bin.store.ts
│           │   ├── device-registry.store.ts
│           │   ├── download.store.ts
│           │   ├── folder.store.ts
│           │   ├── mfa.store.ts
│           │   ├── notification.store.ts
│           │   ├── quota.store.ts
│           │   ├── share.store.ts
│           │   ├── sync.store.ts
│           │   ├── upload.store.ts
│           │   ├── vault.store.ts
│           │   └── __tests__/     # Store unit tests
│           ├── styles/            # Per-feature CSS files (no CSS-in-JS)
│           ├── utils/             # Utility functions (fileTypes.ts, format.ts)
│           ├── workers/           # Service workers (decrypt-sw.ts)
│           ├── App.tsx            # Root component
│           └── main.tsx           # React entry point
├── packages/                      # Shared TypeScript SDK packages
│   ├── crypto/                    # @cipherbox/crypto — pure crypto primitives
│   │   └── src/
│   │       ├── aes/               # AES-256-GCM (encrypt/decrypt/seal) and AES-256-CTR (encrypt/decrypt)
│   │       ├── ecies/             # ECIES secp256k1 key wrapping (encrypt/decrypt/rewrap)
│   │       ├── ed25519/           # Ed25519 signing
│   │       ├── device/            # Device identity keypair
│   │       ├── ipns/              # IPNS name derivation
│   │       ├── keys/              # HKDF key derivation and hierarchy
│   │       ├── utils/             # Byte helpers, key generation
│   │       ├── vault/             # Vault IPNS keypair derivation
│   │       ├── constants.ts       # Crypto constants (key sizes, versions)
│   │       ├── types.ts           # CryptoError, VaultKey, EncryptedData
│   │       └── index.ts           # Public API exports
│   ├── core/                      # @cipherbox/core — domain types and metadata schemas
│   │   └── src/
│   │       ├── bin/               # RecycleBinMetadata (schema, types, encrypt, derive-ipns)
│   │       ├── file/              # FileMetadata, FilePointer (schema, types, metadata ops, derive-ipns)
│   │       ├── folder/            # FolderMetadata, FolderChild (schema, types, metadata ops, derive-ipns)
│   │       ├── ipns/              # IPNS record creation, marshaling, signing
│   │       ├── registry/          # DeviceRegistry (schema, types, encrypt, derive-ipns)
│   │       ├── vault/             # Vault init, key encrypt/decrypt, blob v2 format
│   │       └── index.ts           # Public API exports
│   ├── api-client/                # @cipherbox/api-client — generated HTTP client
│   │   └── src/
│   │       ├── generated/         # Orval-generated API functions (DO NOT EDIT — regenerate with pnpm api:generate)
│   │       ├── models/            # Orval-generated TypeScript types (DO NOT EDIT)
│   │       ├── instance.ts        # Axios instance factory, interceptors, setApiClientConfig
│   │       └── index.ts           # Re-exports all generated + config
│   ├── sdk-core/                  # @cipherbox/sdk-core — stateless orchestration
│   │   └── src/
│   │       ├── download/          # downloadAndDecrypt
│   │       ├── file/              # createFileMetadata, resolveFileMetadata, updateFileMetadata
│   │       ├── folder/            # fetchAndDecryptMetadata, createSubfolder, updateFolderMetadataAndPublish
│   │       ├── ipfs/              # addToIpfs, fetchFromIpfs, unpinFromIpfs
│   │       ├── ipns/              # createAndPublishIpnsRecord, resolveIpnsRecord, verifyIpnsSignature
│   │       ├── pinning/           # BYO-IPFS provider implementations (Kubo, PSA, Pinata, DualPin)
│   │       ├── upload/            # uploadFile
│   │       ├── vault/             # publishVaultKeyBlob, loadVaultKeyBlob
│   │       ├── perf.ts            # Performance instrumentation (withPerf wrapper)
│   │       ├── types.ts           # SdkContext, TeeKeys, ProgressCallback
│   │       └── index.ts           # Public API exports
│   └── sdk/                       # @cipherbox/sdk — stateful client
│       └── src/
│           ├── bin/               # Recycle bin operations
│           ├── share/             # Share operations and shared-write contexts
│           ├── state/             # FolderTree, KeyCache
│           ├── client.ts          # CipherBoxClient class
│           ├── error.ts           # SDK error types
│           ├── events.ts          # SdkEvent types, SdkEventEmitter
│           ├── types.ts           # CipherBoxClientConfig, FolderState
│           └── index.ts           # Public API exports
├── crates/                        # Rust crate workspace (mirrors packages/)
│   ├── crypto/                    # cipherbox-crypto — pure crypto
│   │   └── src/                   # aes.rs, aes_ctr.rs, ecies.rs, ed25519.rs, hkdf.rs, ipns_name.rs, utils.rs
│   ├── core/                      # cipherbox-core — domain types
│   │   └── src/                   # folder.rs, file.rs, bin.rs, registry.rs, vault_blob.rs, ipns.rs, decrypt.rs
│   ├── api-client/                # cipherbox-api-client — HTTP client
│   │   └── src/                   # client.rs, auth.rs, ipfs.rs, ipns.rs, types.rs
│   ├── sdk/                       # cipherbox-sdk — stateful client
│   │   └── src/                   # client.rs, queue.rs, state.rs, sync.rs, registry.rs
│   └── fuse/                      # cipherbox-fuse — FUSE filesystem
│       └── src/
│           ├── platform/          # macos.rs, linux.rs, windows/ (platform-specific mount)
│           ├── inode.rs           # InodeTable
│           ├── cache.rs           # MetadataCache, ContentCache
│           ├── file_handle.rs     # OpenFileHandle
│           ├── operations.rs      # FUSE callbacks
│           ├── read_ops.rs, write_ops.rs, dir_ops.rs  # Operation split by type
│           └── lib.rs             # Crate root
├── tee-worker/                    # TEE IPNS republishing worker (Phala Cloud)
│   └── src/
│       ├── middleware/            # Auth middleware (auth.ts)
│       ├── routes/                # health, public-key, republish, migrate, connection-test
│       ├── services/              # ipns-signer, key-manager, migration-worker, ssrf-validation, tee-keys
│       ├── types/                 # dstack-sdk type declarations
│       └── index.ts               # Express entry point
├── tests/                         # Test suites
│   ├── web-e2e/                   # Playwright browser E2E tests
│   │   ├── tests/                 # Test specs (*.spec.ts)
│   │   ├── page-objects/          # Page object models
│   │   ├── fixtures/              # Test fixtures
│   │   └── utils/                 # Test helpers
│   ├── sdk-e2e/                   # SDK integration tests (Vitest)
│   ├── desktop-e2e/               # Desktop E2E tests
│   ├── load/                      # Load testing (Vitest-based scenarios)
│   └── vectors/                   # Cross-platform test vectors (crypto + core)
├── tools/
│   └── mock-ipns-routing/         # Mock delegated routing server for E2E tests
├── docker/                        # Infrastructure configs
│   ├── grafana/                   # Grafana dashboards, alerts, provisioning
│   ├── Caddyfile                  # Reverse proxy config (staging)
│   ├── alloy-config.river         # Grafana Alloy / telemetry collector config
│   └── docker-compose.staging.yml
├── docs/                          # Project documentation
│   ├── ARCHITECTURE.md, AUTHENTICATION_ARCHITECTURE.md
│   ├── DATABASE_EVOLUTION_PROTOCOL.md, METADATA_EVOLUTION_PROTOCOL.md
│   ├── METADATA_SCHEMAS.md
│   └── VAULT_EXPORT_FORMAT.md
├── designs/                       # Pencil design files (.pen) — read via Pencil MCP only
├── scripts/                       # Root-level utility scripts
│   ├── generate-test-vectors.ts
│   ├── check-api-client.sh
│   └── check-vector-parity.sh
├── 00-Preliminary-R&D/            # Finalized specifications v1.11.1 (DO NOT MODIFY)
│   └── Documentation/             # PRD, Technical Architecture, API Spec, Data Flows, etc.
├── .planning/                     # GSD planning artifacts
│   ├── codebase/                  # Codebase analysis documents (this file)
│   ├── phases/                    # Phase planning documents
│   ├── quick/                     # Quick task planning
│   ├── milestones/                # Milestone tracking
│   ├── adr/                       # Architecture decision records
│   ├── research/                  # Research notes
│   └── security/                  # Security analysis
├── .github/workflows/             # CI/CD pipelines (ci, e2e, deploy-staging, release-please, etc.)
├── Cargo.toml                     # Rust workspace root
├── package.json                   # Root package.json (scripts, devDeps)
├── pnpm-workspace.yaml            # pnpm workspace config (apps/*, packages/*, tests/*, tools/*)
└── tsconfig.base.json             # Root TypeScript config
```

## Directory Purposes

**`apps/api/`:**

- Purpose: NestJS backend API server — zero-knowledge relay, auth, IPNS republish scheduling
- Contains: Controllers, services, entities, DTOs, migrations, guards, Prometheus metrics
- Key files: `src/main.ts` (entry), `src/app.module.ts` (root module), `src/data-source.ts` (TypeORM config)
- Build: `pnpm --filter api build` (NestJS CLI → `dist/`)

**`apps/web/`:**

- Purpose: React web application (file browser, auth, settings, shared vault UI)
- Contains: Components, hooks, stores, services, routes, lib utilities, CSS styles, service worker
- Key files: `src/main.tsx` (entry), `src/App.tsx` (root), `src/lib/sdk-provider.ts` (SDK lifecycle), `src/lib/api-config.ts` (shared axios instance)
- Build: `pnpm --filter web build` (Vite → `dist/`)

**`apps/desktop/`:**

- Purpose: Tauri v2 desktop app — FUSE transparent mount, system tray, auto-sync
- Contains: TypeScript webview (auth) + Rust backend (FUSE via SMB backend, sync, keychain, tray)
- Key files: `src/auth.ts` (webview auth), `src-tauri/src/main.rs` (Rust entry), `src-tauri/vendor/fuser/` (patched crate)
- Build: `pnpm --filter desktop build` (Tauri CLI)

**`packages/crypto/`:**

- Purpose: Pure cryptographic primitives shared by all TypeScript consumers (web, desktop webview, SDK)
- Contains: AES-256-GCM, AES-256-CTR, ECIES secp256k1 key wrapping, Ed25519, HKDF, key generation
- Key files: `src/index.ts` (public API), `src/aes/`, `src/ecies/`, `src/keys/hierarchy.ts`
- Build: `tsup` → `dist/`

**`packages/core/`:**

- Purpose: CipherBox domain types, metadata schemas, vault blob format
- Contains: FolderMetadata, FileMetadata, FilePointer, DeviceRegistry, RecycleBinMetadata, IPNS records, vault blob v2
- Key files: `src/index.ts`, `src/folder/types.ts`, `src/file/types.ts`, `src/vault/blob.ts`
- Build: `tsup` → `dist/`

**`packages/api-client/`:**

- Purpose: Generated typed HTTP client from OpenAPI spec (Orval)
- Contains: Orval-generated API functions by module, model types, axios instance factory
- Key files: `src/index.ts`, `src/instance.ts`, `src/generated/` (auto-generated — DO NOT EDIT)
- Build: `tsup` → `dist/`. Regenerate: `pnpm api:generate` (run after any API endpoint change)

**`packages/sdk-core/`:**

- Purpose: Stateless orchestration functions — no class instances, no state
- Contains: Upload, download, IPNS publish/resolve, folder CRUD, vault blob, BYO-IPFS pinning
- Key files: `src/index.ts`, `src/types.ts` (SdkContext), `src/upload/`, `src/download/`, `src/vault/`, `src/perf.ts`
- Build: `tsup` → `dist/`

**`packages/sdk/`:**

- Purpose: Stateful SDK client exposing event-driven API for web and desktop consumers
- Contains: CipherBoxClient, FolderTree, KeyCache, bin/share/share-write operations, SdkEvent types
- Key files: `src/client.ts`, `src/events.ts`, `src/share/shared-write.ts`, `src/state/key-cache.ts`
- Build: `tsup` → `dist/`

**`crates/`:**

- Purpose: Rust crate workspace mirroring TypeScript packages — used by desktop app
- Contains: crypto, core, api-client, sdk, fuse crates
- Key files: Each crate's `src/lib.rs`, `Cargo.toml` (workspace root)
- Build: `cargo build` (workspace root)

**`tee-worker/`:**

- Purpose: Standalone TEE worker for automatic IPNS republishing every 3 hours (Phala Cloud primary, AWS Nitro fallback)
- Contains: Express routes, IPNS signer, key manager, SSRF validation, migration worker
- Key files: `src/index.ts` (entry), `src/routes/republish.ts`, `src/services/ipns-signer.ts`
- Build: `tsc` → `dist/`

**`tests/`:**

- Purpose: All non-unit test suites organized by scope
- Contains: Playwright E2E, SDK integration tests, desktop E2E, load tests, cross-platform test vectors
- Key files: `web-e2e/tests/`, `sdk-e2e/src/`, `vectors/`, `TESTING_STRATEGY.md`

## Key File Locations

**Entry Points:**

- `apps/api/src/main.ts`: Backend API bootstrap
- `apps/web/src/main.tsx`: Web app React root
- `apps/desktop/src/main.ts`: Desktop webview entry
- `apps/desktop/src-tauri/src/main.rs`: Desktop Rust entry
- `tee-worker/src/index.ts`: TEE worker Express entry

**Configuration:**

- `package.json`: Root workspace scripts and devDeps
- `pnpm-workspace.yaml`: Workspace package locations (`apps/*`, `packages/*`, `tests/*`, `tools/*`)
- `Cargo.toml`: Rust workspace members and shared dependencies
- `apps/api/src/data-source.ts`: TypeORM database configuration
- `apps/api/src/app.module.ts`: NestJS module registration
- `apps/desktop/src-tauri/tauri.conf.json`: Tauri window, bundle, and update configuration

**Web App Infrastructure (`apps/web/src/lib/`):**

- `lib/api-config.ts`: Single shared axios instance registered as the orval singleton — import `apiAxios` here
- `lib/sdk-provider.ts`: CipherBoxClient singleton lifecycle (create on login, destroy on logout)
- `lib/logger.ts`: Structured logger — use `logger.info/warn/error/debug()` instead of `console.*`
- `lib/faro.ts`: Grafana Faro observability (initFaro, setFaroUser, clearFaroUser, registerFaroTransport)
- `lib/errors.ts`: API error detection utilities (isConflictError, isNotFoundError, etc.)
- `lib/clear-user-stores.ts`: Call `clearAllUserStores()` on logout (clears all Zustand state)

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

- TypeScript source: `kebab-case.ts` (e.g., `vault-blob.ts`, `key-wrapping.ts`)
- React components: `PascalCase.tsx` (e.g., `FileBrowser.tsx`, `ShareDialog.tsx`)
- Zustand stores: `kebab-case.store.ts` (e.g., `auth.store.ts`, `folder.store.ts`)
- Services (web): `kebab-case.service.ts` (e.g., `upload.service.ts`, `share.service.ts`)
- React hooks: `use` prefix, camelCase (e.g., `useAuth.ts`, `useFileUpload.ts`, `useFolderMutations.ts`)
- NestJS modules: `kebab-case.{controller,service,module,entity,dto}.ts`
- Rust files: `snake_case.rs` (e.g., `vault_blob.rs`, `file_handle.rs`)
- Test files: `*.spec.ts` (API unit tests and E2E), `*.test.ts` (package unit tests with Vitest)

**Directories:**

- TypeScript packages and apps: `kebab-case` (e.g., `api-client`, `sdk-core`, `file-browser`)
- Rust crates: `kebab-case` (e.g., `api-client`, `fuse`)
- NestJS modules: `kebab-case` (e.g., `device-approval`, `shares`)
- React component subdirectories: `kebab-case` (e.g., `file-browser`, `auth`, `mfa`)

**Code:**

- Types/Interfaces: `PascalCase` (e.g., `FolderMetadata`, `FilePointer`, `SdkContext`)
- Functions: `camelCase` (e.g., `encryptAesGcm`, `fetchAndDecryptMetadata`)
- Rust functions and fields: `snake_case` (e.g., `encrypt_aes_gcm`, `derive_vault_ipns_keypair`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `AES_KEY_SIZE`, `BLOB_V2_VERSION`)
- API request/response fields: `camelCase` (e.g., `rootFolderKey`, `ipnsName`)
- Database columns: `snake_case` (e.g., `encrypted_ipns_key`, `key_epoch`)

## Hook Inventory (Phase 31 Decomposition)

Phase 31 decomposed the original monolithic `useSharedNavigation.ts` (1199 lines) into focused modules. The following hooks exist in `apps/web/src/hooks/`:

| Hook File                       | Lines | Responsibility                                            |
| ------------------------------- | ----- | --------------------------------------------------------- |
| `useAuth.ts`                    | 723   | Auth lifecycle, Web3Auth, device registration             |
| `useFileOperations.ts`          | 515   | File rename, delete, move, copy operations                |
| `useSharedNavigationActions.ts` | 484   | Shared folder navigation action handlers                  |
| `useFolderMutations.ts`         | 445   | Folder create/rename/delete mutations                     |
| `useDeviceApproval.ts`          | 461   | Device approval flow                                      |
| `useSharedNavigation.ts`        | 378   | Shared folder navigation state                            |
| `useSharedWriteOps.ts`          | 377   | Write operations on shared folders                        |
| `useFolderNavigation.ts`        | 312   | Folder tree navigation state                              |
| `useSearch.ts`                  | ~200  | Client-side search                                        |
| `useSyncPolling.ts`             | ~150  | Background IPNS sync polling                              |
| `useFileUpload.ts`              | ~130  | Upload state management                                   |
| `useFileDownload.ts`            | ~120  | Download orchestration                                    |
| `useFileDelete.ts`              | ~100  | Delete confirmation flow                                  |
| `folder-helpers.ts`             | 107   | Pure utility functions for folder navigation (not a hook) |
| `useInterval.ts`                | ~30   | Stable setInterval wrapper                                |
| `useOnlineStatus.ts`            | ~50   | Network online/offline detection                          |
| `useVisibility.ts`              | ~40   | Page visibility API                                       |

`apps/web/src/components/file-browser/useFileBrowserActions.ts` (625 lines) handles file browser action dispatch and is co-located with the component rather than in `hooks/`.

## Where to Add New Code

**New SDK Feature (shared between web and desktop):**

1. Pure crypto primitive: `packages/crypto/src/<type>/` + corresponding `crates/crypto/src/<type>.rs`
2. New metadata schema: `packages/core/src/<type>/` following pattern of `schema.ts`, `types.ts`, `encrypt.ts`, `derive-ipns.ts`
3. Stateless orchestration: `packages/sdk-core/src/<concern>/index.ts`
4. Stateful behavior / events: `packages/sdk/src/` — extend `CipherBoxClient` or add to `share/`
5. Unit tests: `packages/<pkg>/src/__tests__/<feature>.test.ts` (Vitest)
6. Rust equivalent: Mirror in `crates/<crate>/src/<feature>.rs`
7. Cross-platform vectors: `tests/vectors/{crypto,core}/` for parity verification

**New API Endpoint:**

1. Create/extend NestJS module in `apps/api/src/<module-name>/`
2. Standard module structure: `<name>.controller.ts`, `<name>.service.ts`, `<name>.module.ts`, `dto/`, `entities/`
3. Register module in `apps/api/src/app.module.ts`
4. Run `pnpm api:generate` to regenerate `packages/api-client/`
5. Add TypeORM migration in `apps/api/src/migrations/` if new entity — use `IF NOT EXISTS` pattern, timestamp ordering matters
6. Unit tests: `<module>/<name>.spec.ts` (Jest, co-located)

**New Web UI Feature:**

1. Component: `apps/web/src/components/<category>/ComponentName.tsx`
2. CSS: `apps/web/src/styles/<feature-name>.css` (separate CSS file, not inline)
3. Hook: `apps/web/src/hooks/useFeatureName.ts` (if reusable React logic)
4. Service: `apps/web/src/services/feature-name.service.ts` (if business logic calling SDK)
5. Store: `apps/web/src/stores/feature-name.store.ts` (if new state domain — use Zustand)
6. Route: Add page component to `apps/web/src/routes/` and register in `routes/index.tsx`
7. Logging: Use `import { logger } from '../lib/logger'` — never use `console.*` directly
8. Tests: Store tests in `stores/__tests__/`, E2E in `tests/web-e2e/tests/`

**New Desktop Feature:**

1. Tauri IPC command: `apps/desktop/src-tauri/src/commands/<name>.rs` + register in `main.rs`
2. FUSE filesystem logic: `crates/fuse/src/` (platform-agnostic) or `apps/desktop/src-tauri/src/fuse/` (app-specific)
3. Platform-specific FUSE: `crates/fuse/src/platform/{macos,linux,windows}.rs`
4. Webview TypeScript: `apps/desktop/src/` (auth flows only — most logic lives in Rust)

**New API Integration (external service):**

1. TEE key material: `tee-worker/src/services/`
2. IPFS provider: `packages/sdk-core/src/pinning/` (implement provider interface in `types.ts`)
3. Auth provider: `apps/api/src/auth/services/` + `apps/api/src/auth/strategies/`

**New Utility/Helper:**

- Shared crypto: `packages/crypto/src/`
- Shared domain logic: `packages/core/src/`
- Web infrastructure (non-React): `apps/web/src/lib/`
- Web React utilities: `apps/web/src/utils/` (format.ts, fileTypes.ts)
- Rust-only utility: `crates/<appropriate-crate>/src/`

**New Test:**

- API unit tests: `apps/api/src/<module>/<name>.spec.ts` (Jest, co-located with module)
- Package unit tests: `packages/<pkg>/src/__tests__/<name>.test.ts` (Vitest)
- Zustand store tests: `apps/web/src/stores/__tests__/<name>.test.ts`
- Web E2E: `tests/web-e2e/tests/<feature>.spec.ts` (Playwright)
- SDK E2E: `tests/sdk-e2e/src/<name>.test.ts` (Vitest)
- Load tests: `tests/load/src/`
- Test vectors: `tests/vectors/{crypto,core}/`

## Special Directories

**`packages/api-client/src/generated/`:**

- Purpose: Orval-generated typed API client functions organized by API module
- Generated: Yes (`pnpm api:generate`)
- Committed: Yes — commit alongside API changes
- DO NOT EDIT manually — always regenerate after endpoint changes

**`packages/api-client/src/models/`:**

- Purpose: Orval-generated TypeScript model types
- Generated: Yes (same command as above)
- Committed: Yes

**`apps/desktop/src-tauri/vendor/fuser/`:**

- Purpose: Vendored fuser crate with socket-read patch for FUSE-T compatibility on macOS
- Generated: No (manually patched)
- Committed: Yes
- Critical patch: `src/channel.rs` — peek at 4-byte header length, loop-read for Unix domain socket fragmentation

**`apps/api/src/migrations/`:**

- Purpose: TypeORM incremental database migrations
- Generated: Partially (CLI generates skeleton, reviewed manually)
- Committed: Yes
- Pattern: Use `IF NOT EXISTS` for idempotency; timestamp ordering is critical (create-table before modify-table)
- Baseline: `1700000000000-FullSchema.ts` (point-in-time snapshot, do not update)

**`tests/vectors/`:**

- Purpose: Cross-platform test vectors verifying crypto/core parity between TypeScript and Rust implementations
- Generated: No (manually authored)
- Committed: Yes
- Run parity check: `scripts/check-vector-parity.sh`

**`00-Preliminary-R&D/Documentation/`:**

- Purpose: Finalized v1.11.1 specification documents
- Generated: No
- Committed: Yes
- DO NOT MODIFY — create implementation docs in `.planning/` or `docs/` instead

**`.planning/`:**

- Purpose: GSD workflow planning artifacts — phases, milestones, ADRs, codebase analysis
- Generated: Yes (by GSD commands and agents)
- Committed: Yes

**`docker/`:**

- Purpose: Infrastructure configuration for staging/production
- Contains: `grafana/dashboards/`, `grafana/alerts/`, Caddyfile (reverse proxy), Alloy config (telemetry), docker-compose variants
- Not used for local dev

## Implementation Status

| Component             | Location                     | Status      |
| --------------------- | ---------------------------- | ----------- |
| Backend API           | `apps/api/`                  | Implemented |
| API Metrics           | `apps/api/src/metrics/`      | Implemented |
| Web Frontend          | `apps/web/`                  | Implemented |
| Web Logger            | `apps/web/src/lib/logger.ts` | Implemented |
| Web Observability     | `apps/web/src/lib/faro.ts`   | Implemented |
| Desktop App           | `apps/desktop/`              | Implemented |
| TEE Worker            | `tee-worker/`                | Implemented |
| @cipherbox/crypto     | `packages/crypto/`           | Implemented |
| @cipherbox/core       | `packages/core/`             | Implemented |
| @cipherbox/api-client | `packages/api-client/`       | Implemented |
| @cipherbox/sdk-core   | `packages/sdk-core/`         | Implemented |
| @cipherbox/sdk        | `packages/sdk/`              | Implemented |
| cipherbox-crypto      | `crates/crypto/`             | Implemented |
| cipherbox-core        | `crates/core/`               | Implemented |
| cipherbox-api-client  | `crates/api-client/`         | Implemented |
| cipherbox-sdk         | `crates/sdk/`                | Implemented |
| cipherbox-fuse        | `crates/fuse/`               | Implemented |
| Playwright E2E        | `tests/web-e2e/`             | Implemented |
| SDK E2E               | `tests/sdk-e2e/`             | Implemented |
| Test Vectors          | `tests/vectors/`             | Implemented |
| Mock IPNS Routing     | `tools/mock-ipns-routing/`   | Implemented |

---

_Structure analysis: 2026-03-29_
