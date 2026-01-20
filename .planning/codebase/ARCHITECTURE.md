# Architecture

**Analysis Date:** 2026-01-20

## Pattern Overview

**Overall:** Specification-First / Pre-Implementation Technology Demonstrator

**Key Characteristics:**
- Complete specification documents define the target architecture before implementation
- Single proof-of-concept (PoC) console harness validates core IPFS/IPNS and encryption flows
- Layered E2E encryption with zero-knowledge server design
- Client-side cryptographic operations with server acting as relay and storage proxy
- Per-folder IPNS records enabling future modular sharing capabilities

## Layers

**Specification Layer:**
- Purpose: Define complete system design, security model, and implementation contract
- Location: `00-Preliminary-R&D/Documentation/`
- Contains: PRD, technical architecture, API spec, data flows, client spec, implementation roadmap
- Depends on: None (foundation documents)
- Used by: All implementation code (when built)

**Proof-of-Concept Layer:**
- Purpose: Validate IPFS/IPNS assumptions and encryption flows end-to-end
- Location: `00-Preliminary-R&D/poc/`
- Contains: Single-file console harness demonstrating file/folder operations
- Depends on: IPFS daemon, cryptographic libraries
- Used by: Architecture validation only (not production)

**Client Layer (Specified, Not Implemented):**
- Purpose: Handle all encryption/decryption, key management, UI
- Location: (Not yet created - see `00-Preliminary-R&D/Documentation/CLIENT_SPECIFICATION.md`)
- Contains: React 18 web app, Tauri/Electron desktop app with FUSE
- Depends on: Web3Auth SDK, Web Crypto API, CipherBox Backend API
- Used by: End users

**Backend Layer (Specified, Not Implemented):**
- Purpose: Token management, IPFS/IPNS relay, vault metadata storage, TEE coordination
- Location: (Not yet created - see `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md`)
- Contains: NestJS API with 15 endpoints
- Depends on: PostgreSQL, Pinata API, Web3Auth JWKS, TEE providers
- Used by: Client applications

**TEE Layer (Specified, Not Implemented):**
- Purpose: Automatic IPNS republishing without user devices online
- Location: External services (Phala Cloud primary, AWS Nitro fallback)
- Contains: Secure enclaves for IPNS key decryption and signing
- Depends on: Backend republish schedule
- Used by: Backend cron jobs

## Data Flow

**File Upload Flow:**

1. Client generates random `fileKey` (256-bit AES)
2. Client encrypts file content with AES-256-GCM
3. Client wraps `fileKey` with user's `publicKey` via ECIES
4. Client sends encrypted blob to backend (POST `/ipfs/add`)
5. Backend relays to Pinata, returns CID
6. Client updates folder metadata with new file entry
7. Client encrypts metadata with `folderKey`
8. Client signs IPNS record with folder's `ipnsPrivateKey`
9. Client encrypts `ipnsPrivateKey` with TEE `publicKey` for republishing
10. Client sends signed record + encrypted IPNS key to backend (POST `/ipns/publish`)
11. Backend publishes to IPFS network and stores republish schedule

**Authentication Flow:**

1. User authenticates via Web3Auth (4 methods supported)
2. Web3Auth derives deterministic ECDSA keypair (secp256k1)
3. Client authenticates with CipherBox backend (JWT or SIWE signature)
4. Backend verifies identity, issues access token (15min) + refresh token (7d)
5. Backend returns encrypted vault keys and TEE public keys
6. Client decrypts `rootFolderKey` using `privateKey`
7. Session active until logout or token expiry

**State Management:**
- `privateKey`: Client RAM only, never persisted or transmitted
- `rootFolderKey`: Server stores encrypted with ECIES, client decrypts on login
- Folder/file keys: Stored encrypted in IPNS metadata records
- `ipnsPrivateKey`: Client encrypts with TEE public key for republishing

## Key Abstractions

**Vault:**
- Purpose: User's encrypted file storage namespace
- Examples: Root folder IPNS record, associated metadata
- Pattern: One vault per user, identified by `rootIpnsName`

**Folder:**
- Purpose: Encrypted container with child entries (files/folders)
- Examples: Root folder, Documents, Archive (from PoC)
- Pattern: Each folder has own IPNS keypair, `folderKey` for metadata encryption

**File Entry:**
- Purpose: Encrypted file reference within folder metadata
- Examples: `hello.txt` in PoC
- Pattern: Contains encrypted name, CID, wrapped `fileKey`, IV, encryption mode

**TEE Key Epoch:**
- Purpose: Rotation-safe TEE public key management
- Examples: `currentEpoch`, `previousEpoch` for 4-week grace period
- Pattern: Client encrypts IPNS keys with current epoch, TEE supports previous for migration

## Entry Points

**PoC Console Harness:**
- Location: `00-Preliminary-R&D/poc/src/index.ts`
- Triggers: `npm run start` or `tsx src/index.ts`
- Responsibilities: Creates folder hierarchy, uploads/modifies/moves/deletes files, verifies IPNS resolution, cleans up (unpin, remove keys)

**Planned Web Application:**
- Location: (To be created)
- Triggers: Browser navigation to `/auth`, `/vault`, `/settings`
- Responsibilities: Authentication, file browser UI, encryption/decryption

**Planned Backend API:**
- Location: (To be created)
- Triggers: HTTP requests to 15 endpoints
- Responsibilities: Token management, IPFS/IPNS relay, vault storage, TEE coordination

**Planned Desktop Application:**
- Location: (To be created)
- Triggers: App launch, FUSE mount at `~/CipherVault`
- Responsibilities: Transparent file access, background sync

## Error Handling

**Strategy:** Fail-fast with explicit error messages

**Patterns:**
- PoC: Throws errors on failures, logs warnings for non-critical issues (e.g., pin removal)
- Specified Backend: HTTP status codes with structured error responses
- Specified Client: User-facing error messages, retry logic for transient failures
- TEE Republish: Exponential backoff (30s -> 60s -> 120s -> 240s -> 300s max)

## Cross-Cutting Concerns

**Logging:**
- PoC: Console logging with step markers (`=== Step Name ===`)
- Backend (specified): Structured logging, no private keys in logs (Security criterion S8)

**Validation:**
- PoC: Runtime type checking via TypeScript
- Backend (specified): Request validation via NestJS decorators
- Client (specified): Input sanitization before encryption

**Authentication:**
- Two-phase: Web3Auth for key derivation, CipherBox backend for API tokens
- Token rotation: Refresh tokens rotated on each use
- Zero-knowledge: Backend never sees private keys or plaintext

**Security Invariants:**
- Private key exists only in client RAM, cleared on logout
- All files encrypted with unique random key + IV (no deduplication)
- Server stores only encrypted keys (ECIES wrapped)
- TEE keys exist in enclave memory only for milliseconds during signing

---

*Architecture analysis: 2026-01-20*
