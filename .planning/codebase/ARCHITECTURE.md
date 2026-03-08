# Architecture

**Analysis Date:** 2026-03-06

## Pattern Overview

**Overall:** Zero-Knowledge Encrypted Cloud Storage (Implemented)

**Key Characteristics:**

- Layered E2E encryption with zero-knowledge server design
- Client-side cryptographic operations with server acting as relay and storage proxy
- Per-folder IPNS records enabling modular sharing capabilities
- v2 FilePointer schema with per-file IPNS metadata records
- Two-phase authentication (Web3Auth MPC Core Kit + CipherBox backend JWT)

## Layers

**Web Client Layer (Implemented):**

- Purpose: Handle all encryption/decryption, key management, file browser UI
- Location: `apps/web/`
- Contains: React 18 + TypeScript + Tailwind CSS web app
- Depends on: Web3Auth MPC Core Kit, Web Crypto API, CipherBox Backend API
- Used by: End users via browser

**Backend API Layer (Implemented):**

- Purpose: Token management, IPFS/IPNS relay, vault metadata storage, TEE coordination
- Location: `apps/api/`
- Contains: NestJS API with auth, vault, IPFS, IPNS, shares, device-approval endpoints
- Depends on: PostgreSQL, IPFS (Kubo), Redis/BullMQ, Web3Auth JWKS
- Used by: Web client, desktop client

**Desktop Client Layer (Implemented):**

- Purpose: Transparent file access via virtual filesystem mount
- Location: `apps/desktop/`
- Contains: Tauri v2 shell with FUSE-T (SMB backend on macOS), WinFSP (Windows)
- Depends on: CipherBox Backend API, FUSE-T/WinFSP
- Used by: End users via Finder/Explorer

**Shared Crypto Library (Implemented):**

- Purpose: Reusable encryption/decryption primitives
- Location: `packages/crypto/`
- Contains: AES-256-GCM/CTR, ECIES, HKDF, metadata encryption/decryption
- Depends on: Web Crypto API, eciesjs, @noble/ed25519
- Used by: Web client, desktop client (via wasm/native bindings)

**TEE Layer (Implemented):**

- Purpose: Automatic IPNS republishing without user devices online
- Location: `tee-worker/`
- Contains: Phala Cloud worker for IPNS key decryption and record signing
- Depends on: Backend republish schedule, delegated routing service (Someguy on staging, delegated-ipfs.dev on production)
- Used by: Backend cron jobs (every 6 hours)

**Legacy PoC (Historical Reference Only):**

- Location: `00-Preliminary-R&D/poc/`
- Status: Superseded by production code. Not used in any production flow.

## Data Flow

**File Upload Flow:**

1. Client generates random `fileKey` (256-bit AES) and IV (96-bit)
2. Client encrypts file content with AES-256-GCM
3. Client wraps `fileKey` with user's `publicKey` via ECIES
4. Client sends encrypted blob to backend (POST `/ipfs/upload`, multipart/form-data field `file`)
5. Backend relays to IPFS (Kubo), returns CID
6. Client creates per-file FileMetadata (own IPNS record): cid, fileKeyEncrypted, fileIv, size
7. Client adds FilePointer to folder metadata children: nameEncrypted, nameIv, fileMetaIpnsName
8. Client encrypts folder metadata with `folderKey` (AES-256-GCM)
9. Client signs IPNS record with folder's Ed25519 `ipnsPrivateKey`
10. Client sends signed record to backend (POST `/ipns/publish`)
11. Backend publishes to IPFS network via delegated routing

**Authentication Flow:**

1. User authenticates via Web3Auth MPC Core Kit (email OTP, Google OAuth, magic link, or external wallet)
2. Web3Auth derives deterministic ECDSA keypair (secp256k1) via MPC threshold cryptography
3. Client authenticates with CipherBox backend using Web3Auth ID token (JWT)
4. Backend validates via JWKS, issues access token (15min) + refresh token (7d)
5. Backend returns encrypted vault keys and TEE public keys
6. Client decrypts `rootFolderKey` using `privateKey` (ECIES)
7. Session active until logout or token expiry

**State Management:**

- `privateKey`: Client RAM only, never persisted or transmitted
- `rootFolderKey`: Server stores encrypted with ECIES, client decrypts on login
- Folder/file keys: Stored encrypted in IPNS metadata records
- `ipnsPrivateKey`: Client encrypts with TEE public key for republishing enrollment

## Key Abstractions

**Vault:**

- Purpose: User's encrypted file storage namespace
- Location: `apps/api/src/vault/`, `apps/web/src/stores/vault.store.ts`
- Pattern: One vault per user, identified by `rootIpnsName`

**Folder:**

- Purpose: Encrypted container with child entries (files/folders)
- Location: `apps/web/src/services/folder.service.ts`, `packages/crypto/src/metadata/`
- Pattern: Each folder has own IPNS keypair, `folderKey` for metadata encryption

**FilePointer (v2):**

- Purpose: Slim reference in folder metadata pointing to per-file IPNS record
- Location: `packages/crypto/src/metadata/types.ts`
- Pattern: Contains encrypted name, timestamps, `fileMetaIpnsName` (reference to FileMetadata)

**FileMetadata:**

- Purpose: Per-file crypto material in dedicated IPNS record
- Location: `packages/crypto/src/metadata/types.ts`
- Pattern: Contains CID, `fileKeyEncrypted`, `fileIv`, size, encryption mode

**TEE Key Epoch:**

- Purpose: Rotation-safe TEE public key management
- Location: `apps/api/src/republish/`, `tee-worker/src/`
- Pattern: Client encrypts IPNS keys with current epoch, TEE supports previous for 4-week grace period

## Entry Points

**Web Application:**

- Location: `apps/web/src/main.tsx`
- Dev: `pnpm --filter web dev` (<http://localhost:5173>)
- Routes: `/auth`, `/vault`, file browser UI

**Backend API:**

- Location: `apps/api/src/main.ts`
- Dev: `pnpm --filter api dev` (<http://localhost:3000>)
- Endpoints: auth, vault, IPFS, IPNS, shares, device-approval, republish

**Desktop Application:**

- Location: `apps/desktop/src/main.ts` (Tauri frontend), `apps/desktop/src-tauri/` (Rust backend)
- Dev: `pnpm --filter desktop tauri dev`
- Mount point: `~/CipherBox` (macOS FUSE-T SMB)

**TEE Worker:**

- Location: `tee-worker/src/index.ts`
- Deployed to Phala Cloud

## Error Handling

**Strategy:** Fail-fast with user-facing error messages

**Patterns:**

- Web: Toast notifications for user errors, console.error for debug (see CONCERNS.md for logging tech debt)
- API: HTTP status codes with structured NestJS exception filters
- Desktop FUSE: Returns errno codes (EIO, ENOENT, EPERM) to kernel
- IPNS delegated routing: Exponential backoff with retry (3 attempts, 1s base, 30s cap)
- Token refresh: Automatic retry with queue deduplication (`apps/web/src/lib/api/client.ts`)

## Cross-Cutting Concerns

**Logging:**

- API: NestJS Logger (structured)
- Web: Direct console.\* calls (tech debt — see CONCERNS.md)
- Desktop: Rust `log` crate with `env_logger`

**Authentication:**

- Two-phase: Web3Auth MPC Core Kit for key derivation, CipherBox backend for API tokens
- Token rotation: Refresh tokens rotated on each use
- Zero-knowledge: Backend never sees private keys or plaintext

**Security Invariants:**

- Private key exists only in client RAM, cleared on logout
- All files encrypted with unique random key + IV (no deduplication)
- Server stores only encrypted keys (ECIES wrapped)
- TEE keys exist in enclave memory only during signing, then zeroed

---

Architecture analysis: 2026-03-06
