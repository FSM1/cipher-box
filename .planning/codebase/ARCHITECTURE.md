# Architecture

**Analysis Date:** 2026-03-27
**Drift review:** 2026-06-19

## Pattern Overview

**Overall:** Zero-Knowledge Encrypted Cloud Storage with Layered SDK Architecture

**Key Characteristics:**

- Client-side-only encryption: server never sees plaintext data or unencrypted keys
- Dual-platform SDK hierarchy: mirrored TypeScript packages and Rust crates share identical data model
- Per-folder IPNS records for modular sharing; per-file IPNS records (v2 FilePointer) for independent file metadata
- Vault key blob v2: rootFolderKey stored on IPFS (not server), published to dedicated IPNS name
- ECIES key wrapping (secp256k1) for all key exchange; AES-256-GCM/CTR for content encryption
- TEE-based IPNS republishing with epoch-rotated keys and 4-week grace periods
- Two-phase auth: Web3Auth MPC Core Kit for deterministic key derivation + CipherBox backend for API tokens

## Layered SDK Architecture

The SDK is organized as a strict dependency chain. Each layer adds exactly one concern. This hierarchy is mirrored between TypeScript (packages/) and Rust (crates/).

### TypeScript SDK Layer Stack

```text
@cipherbox/crypto          Pure cryptographic primitives (AES, ECIES, Ed25519, HKDF)
       |
@cipherbox/core            Domain types + metadata schemas (FolderMetadata, FileMetadata, vault blob)
       |
@cipherbox/api-client      Generated typed HTTP client (Orval from OpenAPI spec)
       |
@cipherbox/sdk-core        Stateless orchestration functions (upload, download, IPNS publish/resolve, folder CRUD)
       |
@cipherbox/sdk             Stateful client (CipherBoxClient) with event emitter, folder tree, key cache, bin/share ops
```

**Dependency rules (enforced by package.json):**

- `@cipherbox/crypto` (`packages/crypto/`) -- depends on: `@noble/ed25519`, `@noble/hashes`, `eciesjs`, `@libp2p/crypto`, `ipns`, `multiformats`
- `@cipherbox/core` (`packages/core/`) -- depends on: `@cipherbox/crypto`, `@libp2p/crypto`, `@noble/ed25519`, `ipns`
- `@cipherbox/api-client` (`packages/api-client/`) -- depends on: `axios` (generated code, no crypto deps)
- `@cipherbox/sdk-core` (`packages/sdk-core/`) -- depends on: `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/api-client`
- `@cipherbox/sdk` (`packages/sdk/`) -- depends on: `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/api-client`, `@cipherbox/sdk-core`

### Rust Crate Layer Stack

```text
cipherbox-crypto           Pure crypto (mirrors @cipherbox/crypto)
       |
cipherbox-core             Domain types (mirrors @cipherbox/core)
       |
cipherbox-api-client       HTTP client (mirrors @cipherbox/api-client)
       |
cipherbox-sdk              Stateful client with sync daemon (mirrors @cipherbox/sdk)
       |
cipherbox-fuse             FUSE filesystem (platform-specific, uses all above)
```

**Rust dependencies (Cargo workspace at project root):**

- `cipherbox-crypto` (`crates/crypto/`) -- depends on: `aes-gcm`, `ecies`, `ed25519-dalek`, `hkdf`, `sha2`
- `cipherbox-core` (`crates/core/`) -- depends on: `cipherbox-crypto`
- `cipherbox-api-client` (`crates/api-client/`) -- depends on: `reqwest`
- `cipherbox-sdk` (`crates/sdk/`) -- depends on: `cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`
- `cipherbox-fuse` (`crates/fuse/`) -- depends on: all above + `fuser` (feature-gated)

### Cross-Platform Parity

The TypeScript and Rust SDKs implement the same data model and crypto operations, verified by shared test vectors at `tests/vectors/`. The desktop app (`apps/desktop/src-tauri/`) uses the Rust crate stack for all file operations while the Tauri webview uses `@cipherbox/crypto` for Web3Auth key derivation only.

## Applications

### Web Application (`apps/web/`)

**Purpose:** Full-featured encrypted file browser with client-side crypto.

**Entry point:** `apps/web/src/main.tsx`

**Framework:** React 18 + Vite + TypeScript

**State management:** Zustand stores (13 stores in `apps/web/src/stores/`):

- `auth.store.ts` -- access token, vault keypair (memory-only), TEE keys
- `vault.store.ts` -- decrypted rootFolderKey, rootIpnsKeypair, rootIpnsName
- `folder.store.ts` -- folder tree, children, navigation state
- `upload.store.ts` -- upload queue and progress
- `download.store.ts` -- download queue and progress
- `bin.store.ts` -- recycle bin state
- `share.store.ts` -- sent/received shares
- `sync.store.ts` -- IPNS polling sync state
- `device-registry.store.ts` -- multi-device registry
- `mfa.store.ts` -- MFA challenge state
- `notification.store.ts` -- toast notifications
- `quota.store.ts` -- storage quota tracking
- `vault-settings.store.ts` -- user-configurable vault parameters (retention, delete behavior, versioning limits, cooldown)

**SDK integration:** Singleton `CipherBoxClient` managed by `apps/web/src/lib/sdk-provider.ts`. Created after vault load, destroyed on logout. Hooks call client methods; stores subscribe to client events.

**Routing:** HashRouter with 7 routes defined in `apps/web/src/routes/index.tsx`:

- `/` -- Login page
- `/files/:folderId?` -- File browser (main view)
- `/shared` -- Shared items
- `/bin` -- Recycle bin
- `/settings` -- Settings page
- `/invite/:token` -- Share invite acceptance
- `/dashboard` -- Redirects to `/files`

**Service worker:** `apps/web/src/workers/decrypt-sw.ts` provides streaming media decryption for AES-CTR encrypted audio/video without downloading entire files.

### Backend API (`apps/api/`)

**Purpose:** Zero-knowledge relay for auth, IPFS/IPNS, vault metadata, shares, TEE coordination.

**Entry point:** `apps/api/src/main.ts`

**Framework:** NestJS 11 + TypeORM + PostgreSQL

**Module structure** (registered in `apps/api/src/app.module.ts`):

| Module                 | Location                              | Purpose                                                                                                                           |
| ---------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `AuthModule`           | `apps/api/src/auth/`                  | Web3Auth JWT verification, CipherBox JWT issuance, token rotation, identity providers (Google, Email OTP, SIWE), account deletion |
| `VaultModule`          | `apps/api/src/vault/`                 | Vault init/retrieval, encrypted key storage, quota tracking, pinned CID management                                                |
| `IpfsModule`           | `apps/api/src/ipfs/`                  | File upload relay to Kubo, download relay, CID registration, unpin                                                                |
| `IpnsModule`           | `apps/api/src/ipns/`                  | IPNS record publish/resolve relay, delegated routing, sequence number tracking                                                    |
| `SharesModule`         | `apps/api/src/shares/`                | Share CRUD, share keys (ECIES-wrapped per-recipient), share invites                                                               |
| `TeeModule`            | `apps/api/src/tee/`                   | TEE public key distribution, key epoch management, rotation logging                                                               |
| `RepublishModule`      | `apps/api/src/republish/`             | BullMQ job scheduling for TEE IPNS republishing (every 6 hours)                                                                   |
| `DeviceApprovalModule` | `apps/api/src/device-approval/`       | Bulletin board for cross-device MFA factor key exchange                                                                           |
| `MigrationModule`      | `apps/api/src/migration/`             | CID migration between IPFS pinning providers                                                                                      |
| `MetricsModule`        | `apps/api/src/metrics/`               | Prometheus metrics via prom-client                                                                                                |
| `HealthModule`         | `apps/api/src/health/`                | Health check endpoint via @nestjs/terminus                                                                                        |
| `RedisModule`          | `apps/api/src/common/redis.module.ts` | Shared Redis/ioredis connection                                                                                                   |
| `PendingUnpinModule`   | `apps/api/src/ipfs/pending-unpin/`    | Deferred IPFS unpin drain worker (BullMQ, every 5 min) and hourly Kubo-vs-DB pin-drift report                                      |

**Database entities** (15 entities, PostgreSQL):

- `User`, `RefreshToken`, `AuthMethod` (auth)
- `Vault`, `PinnedCid`, `PendingUnpin` (vault)
- `FolderIpns` (IPNS sequence tracking)
- `TeeKeyState`, `TeeKeyRotationLog` (TEE)
- `IpnsRepublishSchedule` (republish)
- `DeviceApproval` (device MFA)
- `Share`, `ShareKey`, `ShareInvite` (shares)
- `PinMigration` (migration)

**Migrations:** `apps/api/src/migrations/` (TypeORM migrations with `IF NOT EXISTS` for idempotency). `synchronize: false` in all environments.

### Desktop Application (`apps/desktop/`)

**Purpose:** Transparent encrypted file access via virtual filesystem (FUSE) mount at `~/CipherBox`.

**Entry points:**

- Tauri webview: `apps/desktop/src/main.ts` (auth UI)
- Rust backend: `apps/desktop/src-tauri/src/main.rs`

**Framework:** Tauri v2 + FUSE-T (macOS SMB backend) / WinFSP (Windows)

**Dual-language architecture:**

- TypeScript webview (`apps/desktop/src/auth.ts`): Web3Auth MPC Core Kit for authentication + key derivation. Communicates with Rust via Tauri IPC `invoke()`.
- Rust backend (`apps/desktop/src-tauri/src/`): All file operations use Rust crate stack. FUSE callbacks, metadata cache, content cache, debounced IPNS publish.

**Rust modules:**

| Module        | Location                               | Purpose                                       |
| ------------- | -------------------------------------- | --------------------------------------------- |
| `commands/`   | `apps/desktop/src-tauri/src/commands/` | Tauri IPC commands (auth, vault, sync, OAuth) |
| `fuse/`       | `apps/desktop/src-tauri/src/fuse/`     | FUSE mount/unmount, debounced publish         |
| `registry/`   | `apps/desktop/src-tauri/src/registry/` | Device registry (IPNS-based)                  |
| `sync/`       | `apps/desktop/src-tauri/src/sync/`     | Background sync daemon                        |
| `tray/`       | `apps/desktop/src-tauri/src/tray/`     | System tray icon and menu                     |
| `keychain.rs` |                                        | macOS Keychain / Windows Credential Manager   |
| `state.rs`    |                                        | Global AppState (auth tokens, key material)   |
| `updater.rs`  |                                        | Auto-updater                                  |

**FUSE architecture (crates/fuse/):**

- Platform-agnostic: `InodeTable`, `MetadataCache`, `ContentCache`, `OpenFileHandle`
- Platform-specific (feature-gated): `operations.rs`, `read_ops.rs`, `write_ops.rs`, `dir_ops.rs`
- Single-threaded callbacks: never block on network I/O in FUSE callbacks
- Write path: `write()` -> temp file -> `release()` -> encrypt + upload (background)
- Read path: `open()` -> async prefetch -> `read()` -> cache check -> return or EIO

### TEE Worker (`apps/tee-worker/`)

**Purpose:** Automatic IPNS republishing without user devices online. Runs as a Docker simulator on the staging VPS (since PR #472); Phala Cloud CVM in production.

**Entry point:** `apps/tee-worker/src/index.ts`

**Framework:** Express.js (standalone, not part of pnpm workspace)

**Routes:**

- `GET /health` -- Public health check
- `GET /public-key` -- TEE public key per epoch (auth required)
- `POST /republish` -- Batch IPNS signing (auth required)
- `POST /migrate` -- CID migration between providers (auth required)
- `POST /connection-test` -- IPFS endpoint connection test (auth required)
- `GET /metrics` -- Prometheus metrics (public, no auth)

**Security model:** Receives ECIES-encrypted IPNS private keys, decrypts with epoch-derived keys inside enclave, signs IPNS records, returns signed records. Keys exist in enclave memory only during signing, then zeroed.

## Data Flows

### File Upload Flow

1. Client generates random `fileKey` (AES-256, 32 bytes) and `iv` (96 bits) -- `packages/crypto/src/utils/`
2. Client encrypts file content with AES-256-GCM -- `packages/crypto/src/aes/`
3. Client wraps `fileKey` with user's `publicKey` via ECIES -- `packages/crypto/src/ecies/`
4. Client uploads encrypted blob to backend `POST /ipfs/upload` -- `packages/sdk-core/src/ipfs/`
5. Backend relays to IPFS (Kubo), returns CID -- `apps/api/src/ipfs/`
6. Client creates per-file FileMetadata (encrypted with parent `folderKey`) -- `packages/sdk-core/src/file/`
7. Client generates Ed25519 keypair for file IPNS, publishes FileMetadata -- `packages/core/src/file/derive-ipns.ts`
8. Client adds FilePointer to folder's children array (contains `fileMetaIpnsName`, `ipnsPrivateKeyEncrypted`) -- `packages/sdk-core/src/folder/`
9. Client encrypts updated folder metadata with `folderKey` (AES-256-GCM) -- `packages/core/src/folder/`
10. Client signs folder IPNS record with folder's Ed25519 `ipnsPrivateKey` -- `packages/core/src/ipns/`
11. Client batch-publishes folder + file IPNS records to backend -- `packages/sdk-core/src/ipns/`
12. Backend relays to IPFS network via delegated routing -- `apps/api/src/ipns/`

### File Download Flow

1. Client resolves folder IPNS to get FilePointer (contains `fileMetaIpnsName`) -- `packages/sdk-core/src/ipns/`
2. Client resolves file IPNS to get FileMetadata (contains `cid`, `fileKeyEncrypted`, `fileIv`) -- `packages/sdk-core/src/file/`
3. Client fetches encrypted blob from IPFS via backend `GET /ipfs/:cid` -- `packages/sdk-core/src/ipfs/`
4. Client ECIES-unwraps `fileKeyEncrypted` with user's `privateKey` -- `packages/crypto/src/ecies/`
5. Client decrypts content with AES-256-GCM (or AES-256-CTR for streaming media) -- `packages/sdk-core/src/download/`
6. Client clears `fileKey` from memory -- `packages/crypto/src/utils/`

### Authentication Flow

1. User authenticates via identity provider (Google OAuth, Email OTP, or SIWE wallet) -- `apps/web/src/lib/web3auth/` or `apps/desktop/src/auth.ts`
2. CipherBox backend issues a CipherBox JWT (RS256, iss=cipherbox, aud=web3auth) -- `apps/api/src/auth/controllers/identity.controller.ts`
3. Web3Auth MPC Core Kit derives deterministic secp256k1 keypair via TSS -- client-side
4. Client calls `POST /auth/login` with Web3Auth ID token and derived public key -- `apps/api/src/auth/auth.controller.ts`
5. Backend validates via JWKS, creates/finds user, issues access token (15min) + refresh token (7d in httpOnly cookie) -- `apps/api/src/auth/auth.service.ts`
6. Client retrieves vault: `GET /vault` returns encrypted keys -- `apps/api/src/vault/`
7. **Vault key blob v2 path:** Client derives vault key IPNS keypair via HKDF, resolves dedicated IPNS name, fetches v2 blob from IPFS, ECIES-unwraps rootFolderKey -- `packages/sdk-core/src/vault/`
8. **Legacy path:** Client ECIES-unwraps `rootFolderKeyEncrypted` from server response -- `packages/core/src/vault/init.ts`
9. Client initializes SDK client with decrypted keys -- `apps/web/src/lib/sdk-provider.ts`

### Share Flow (Read-Only and Writable)

1. Sharer looks up recipient's `publicKey` via API -- `apps/api/src/shares/`
2. Sharer ECIES-wraps the `folderKey` (or `fileKey`) with recipient's `publicKey` -- `packages/sdk/src/share/index.ts`
3. Sharer calls `POST /shares` with encrypted key, permission level, IPNS name -- `apps/api/src/shares/shares.controller.ts`
4. Recipient fetches shares via `GET /shares` -- sees share with `encryptedKey`
5. Recipient ECIES-unwraps key with their `privateKey` to get `folderKey` -- client-side
6. Recipient can now decrypt folder metadata and file content

**Writable shares (additional steps):**

7. Recipient performs write operations (upload, create subfolder, rename, delete) -- `packages/sdk/src/share/shared-write.ts`
8. Keys in FolderEntry/FilePointer wrap with OWNER's publicKey (owner can always access)
9. Share keys entries wrap with RECIPIENT's publicKey via `addShareKeysFn` -- `packages/sdk/src/share/shared-write.ts`
10. After adding items, re-wrap keys for all covering share recipients -- `packages/sdk/src/share/index.ts`

### Vault Key Blob v2

**Problem solved:** Previous architecture stored rootFolderKey on the server (encrypted). v2 moves key material to IPFS, published to a dedicated IPNS name, so the server never holds key blobs.

**Publish flow** (`packages/sdk-core/src/vault/index.ts`):

1. Derive vault key IPNS keypair via HKDF from user's private key -- `packages/crypto/src/vault/`
2. ECIES-wrap rootFolderKey with user's public key
3. Serialize as v2 blob (version prefix + encrypted key) -- `packages/core/src/vault/blob.ts`
4. Upload v2 blob to IPFS
5. Create and publish IPNS record pointing to blob CID

**Load flow** (`packages/sdk-core/src/vault/index.ts`):

1. Derive vault key IPNS keypair via HKDF
2. Resolve IPNS name to get blob CID
3. Fetch blob from IPFS
4. Detect version (must be v2) -- `packages/core/src/vault/blob.ts`
5. Deserialize and ECIES-unwrap rootFolderKey with user's private key

### Per-File IPNS Metadata (v2 FilePointer)

Each file has its own IPNS record containing encrypted `FileMetadata` (CID, wrapped key, IV, size, MIME type, versions). The parent folder stores only a slim `FilePointer` reference:

```typescript
// FilePointer in folder metadata (packages/core/src/file/types.ts)
type FilePointer = {
  type: 'file';
  id: string;
  name: string;
  fileMetaIpnsName: string; // Points to file's own IPNS record
  ipnsPrivateKeyEncrypted?: string; // ECIES-wrapped Ed25519 key for signing
  createdAt: number;
  modifiedAt: number;
};

// FileMetadata in file's own IPNS record (packages/core/src/file/types.ts)
type FileMetadata = {
  version: 'v1';
  cid: string;
  fileKeyEncrypted: string; // ECIES-wrapped AES-256 key
  fileIv: string;
  size: number;
  mimeType: string;
  encryptionMode?: 'GCM' | 'CTR';
  createdAt: number;
  modifiedAt: number;
  versions?: VersionEntry[]; // Past versions for file history
};
```

**Benefits:** File metadata updates (re-upload, version history) don't require re-publishing the parent folder's IPNS record. Reduces metadata publish contention.

## Key Abstractions

**SdkContext** (`packages/sdk-core/src/types.ts`):

- Purpose: Injected configuration replacing Zustand store access
- Contains: `apiUrl`, `getAccessToken()`, optional `axiosInstance`
- Pattern: Passed as explicit parameter to all sdk-core functions

**CipherBoxClient** (`packages/sdk/src/client.ts`):

- Purpose: Stateful orchestration with event-driven change notification
- Contains: FolderTree, KeyCache, BinState, event emitter
- Pattern: Zero React/Zustand/browser dependencies; all state flows through typed SdkEvent

**VaultKey** (`packages/crypto/src/types.ts`):

- Purpose: User's secp256k1 keypair for ECIES key wrapping
- Pattern: Memory-only, defensive-copied in CipherBoxClient, zeroed on destroy()

**FolderMetadata** (`packages/core/src/folder/types.ts`):

- Purpose: Encrypted container with FolderEntry and FilePointer children
- Pattern: Entire object encrypted as single AES-256-GCM blob with folderKey

**InodeTable** (`crates/fuse/src/inode.rs`):

- Purpose: Maps FUSE inode numbers to CipherBox folder/file entries
- Pattern: Inode reuse for stability (NFS/SMB clients require consistent inode numbers)

## Entry Points

**Web Application:**

- Location: `apps/web/src/main.tsx`
- Dev: `pnpm --filter web dev` (<http://localhost:5173>)
- Build: `pnpm --filter web build` (Vite)

**Backend API:**

- Location: `apps/api/src/main.ts`
- Dev: `pnpm --filter api dev` (<http://localhost:3000>)
- Build: `pnpm --filter api build` (NestJS CLI)
- Swagger UI: <http://localhost:3000/api-docs>

**Desktop Application:**

- Webview: `apps/desktop/src/main.ts`
- Rust: `apps/desktop/src-tauri/src/main.rs`
- Dev: `pnpm --filter desktop dev`
- Mount: `~/CipherBox` (macOS FUSE-T SMB)

**TEE Worker:**

- Location: `apps/tee-worker/src/index.ts`
- Dev: `pnpm --filter cipherbox-tee-worker dev`
- Deployed: Docker Compose service on the staging VPS, simulator mode (Phala Cloud CVM in production)

**API Client Generation:**

- Generate: `pnpm api:generate` (OpenAPI spec -> Orval -> typed client)
- Source: `apps/api/` OpenAPI decorators
- Output: `packages/api-client/src/generated/`

## Error Handling

**Strategy:** Fail-fast with typed errors per layer

**Patterns:**

- **Crypto layer:** `CryptoError` with generic messages (prevents oracle attacks) -- `packages/crypto/src/types.ts`, `crates/crypto/src/error.rs`
- **Core layer:** `CoreError` for metadata validation failures -- `crates/core/src/error.rs`
- **API client:** Axios interceptors with automatic token refresh + retry queue -- `packages/api-client/src/instance.ts`
- **SDK layer:** Operations wrapped with `withOperation()` for consistent start/end/error event emission -- `packages/sdk/src/client.ts`
- **API backend:** NestJS exception filters with HTTP status codes, global ValidationPipe (whitelist + forbidNonWhitelisted)
- **Desktop FUSE:** Returns errno codes (EIO, ENOENT, EPERM) to kernel; never blocks callbacks
- **Web UI:** Toast notifications for user errors (`apps/web/src/stores/notification.store.ts`)

## Cross-Cutting Concerns

**Logging:**

- API: NestJS Logger (structured, level varies by environment)
- Web: Direct `console.*` calls
- Desktop: Rust `log` crate with `env_logger`
- TEE Worker: `console.log` (Express)

**Validation:**

- API: class-validator decorators on DTOs, global ValidationPipe
- Core: `validateFolderMetadata()`, `validateFileMetadata()`, `validateBinMetadata()`, `validateDeviceRegistry()` in `packages/core/`
- IPNS: Client-side Ed25519 signature verification on resolve -- `packages/sdk-core/src/ipns/`

**Authentication:**

- Two-phase: Web3Auth MPC Core Kit (key derivation) + CipherBox backend (API tokens)
- Token lifecycle: access token (15min), refresh token (7d, httpOnly cookie, rotated on use)
- Desktop: Tauri IPC for credential handoff (private key never leaves process)

**Rate Limiting:**

- Global: `@nestjs/throttler` (10 req/s short, 100 req/min medium)
- Per-endpoint: `@Throttle()` decorator overrides (e.g., auth endpoints)
- Bypass: `X-Throttle-Bypass` header with secret (non-production only, for SDK E2E tests)

**Metrics:**

- Prometheus via `prom-client` -- `apps/api/src/metrics/`
- HTTP request metrics via `HttpMetricsInterceptor`
- Performance instrumentation via `withPerf()` in sdk-core -- `packages/sdk-core/src/perf.ts`

**Security Invariants:**

- Private key exists only in client RAM, zeroed on logout/destroy
- All files encrypted with unique random key + IV (no deduplication)
- Server stores only ECIES-wrapped keys (zero-knowledge)
- TEE keys exist in enclave memory only during signing, then zeroed
- IPNS records signed client-side, signature verified on resolve
- Vault key blob v2 stores rootFolderKey on IPFS, not server

---

<!-- Architecture analysis: 2026-03-27 -->
