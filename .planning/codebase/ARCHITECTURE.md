# Architecture

**Analysis Date:** 2026-01-19

## Pattern Overview

**Overall:** Documentation-driven technology demonstrator

**Key Characteristics:**
- Documentation-first specification with versioned markdown documents defining product requirements, technical architecture, API contracts, and implementation roadmap
- Console-based proof-of-concept harness validating IPFS/IPNS integration without full backend/frontend dependencies
- Zero-knowledge encryption architecture with client-side key derivation and management
- Decentralized storage via IPFS/IPNS with server acting as relay-only (no plaintext access)

## Layers

**Documentation Layer:**
- Purpose: Complete specification for CipherBox v1.0 implementation
- Location: `Documentation/`
- Contains: PRD, technical architecture, API specification, client specification, data flows, implementation roadmap
- Depends on: Nothing (source of truth)
- Used by: Development implementation, GSD planning commands
- Format: Versioned markdown with YAML frontmatter (version, last_updated, status, ai_context)

**Proof-of-Concept Layer:**
- Purpose: Validate cryptographic and IPFS/IPNS assumptions without full system dependencies
- Location: `poc/`
- Contains: Single-file console harness demonstrating end-to-end file/folder encryption and IPFS/IPNS publish/resolve cycles
- Depends on: Local IPFS daemon (Kubo), optional Pinata API
- Used by: Technical validation, de-risking assumptions
- Pattern: Stateful harness with setup → operations → verification → teardown

**Planned Application Layer (Not Yet Implemented):**
- Frontend: React 18 + TypeScript web UI, Tauri/Electron desktop app with FUSE mount
- Backend: NestJS + TypeScript API server
- Database: PostgreSQL for user/vault/token/audit persistence
- Key Derivation: Web3Auth Network for deterministic ECDSA keypair generation

**Planned Crypto Layer (Specified):**
- Purpose: Client-side encryption/decryption with zero-knowledge guarantees
- Pattern: Layered encryption (file content → folder metadata → key wrapping)
- Algorithms: AES-256-GCM for symmetric encryption, ECIES secp256k1 for key wrapping
- Key Hierarchy: Web3Auth privateKey → ECIES wrapping → rootFolderKey → per-folder folderKey → per-file fileKey

**Planned Storage Layer (Specified):**
- Purpose: Decentralized, content-addressed storage with mutable pointers
- Pattern: IPFS for immutable content, IPNS for mutable folder metadata
- Server Role: Relay only (receives signed IPNS records from clients, publishes to IPFS/IPNS)
- Provider: Pinata for v1.0 pinning

## Data Flow

**PoC Harness Flow (Current Implementation):**

1. **Initialization:** Generate ECDSA keypair from env var, create IPFS HTTP client, initialize root folder with random AES-256 key and Ed25519 IPNS key
2. **Folder Creation:** Generate per-folder encryption keys and IPNS keys, encrypt folder names with parent folder key, wrap child keys with user public key (ECIES)
3. **File Upload:** Generate per-file AES-256 key, encrypt file content with AES-256-GCM, upload encrypted blob to IPFS, encrypt file metadata (name, key, CID) and add to parent folder
4. **Metadata Publish:** Encrypt folder metadata (children list) with folder key, upload to IPFS, sign IPNS record with folder's Ed25519 key, publish to IPNS
5. **Sync Verification:** Poll IPNS name until resolved CID matches published CID (measures propagation delay)
6. **File Operations:** Download encrypted metadata from IPNS-resolved CID, decrypt with folder key, extract file entry, download encrypted file from IPFS, decrypt with unwrapped file key
7. **Teardown:** Unpin all tracked CIDs from local IPFS and Pinata, remove all generated IPNS keys

**Specified Production Flow (Not Yet Implemented):**

1. **Auth:** User authenticates via Web3Auth (Email/Password/OAuth/Magic Link/External Wallet) → deterministic ECDSA keypair derived → client signs challenge → backend issues JWT
2. **Vault Bootstrap:** Client generates rootFolderKey, wraps with ECIES(publicKey), stores encrypted on server with vault record
3. **File Upload:** Client encrypts file → uploads to IPFS via backend relay → backend pins CID → client updates folder metadata → signs IPNS record → backend publishes
4. **Multi-Device Sync:** Second device authenticates → derives same keypair → fetches encrypted rootFolderKey → unwraps → resolves root IPNS name → recursively decrypts folder tree
5. **File Access:** Desktop FUSE mount intercepts file read → client resolves IPNS → fetches IPFS CID → decrypts → returns plaintext to OS

**State Management:**
- PoC: In-memory folder state with optional JSON export to `poc/state/state.json`
- Specified: Server stores encrypted keys + IPNS names in PostgreSQL, clients hold private key in RAM only during session

## Key Abstractions

**FolderState:**
- Purpose: Represents a folder with its encryption context and metadata
- Examples: `poc/src/index.ts` lines 43-50
- Pattern: In-memory state object with name, key (Uint8Array), IPNS identifiers, and encrypted metadata structure
- Fields: `name`, `key`, `ipnsName`, `ipnsKeyName`, `metadata` (FolderMetadata), `latestMetadataCid`

**FolderMetadata:**
- Purpose: Encrypted folder contents (list of child files/folders)
- Examples: `poc/src/index.ts` lines 35-41
- Pattern: JSON structure encrypted with folder's AES-256 key before IPFS upload
- Fields: `children` (array of FolderEntry | FileEntry), `metadata` (created/modified timestamps)

**FileEntry:**
- Purpose: Encrypted file reference within folder metadata
- Examples: `poc/src/index.ts` lines 23-33
- Pattern: Name encrypted with folder key, file key encrypted with user public key (ECIES), IPFS CID for content
- Fields: `type`, `nameEncrypted`, `nameIv`, `cid`, `fileKeyEncrypted`, `fileIv`, `size`, `created`, `modified`

**FolderEntry:**
- Purpose: Encrypted subfolder reference within folder metadata
- Examples: `poc/src/index.ts` lines 12-21
- Pattern: Name encrypted with parent folder key, subfolder key and IPNS key name encrypted with user public key (ECIES)
- Fields: `type`, `nameEncrypted`, `nameIv`, `ipnsName`, `folderKeyEncrypted`, `ipnsKeyNameEncrypted`, `created`, `modified`

**HarnessContext:**
- Purpose: Global execution context for PoC harness
- Examples: `poc/src/index.ts` lines 57-69
- Pattern: Singleton context passed through all operations, tracks pinned CIDs and IPNS keys for cleanup
- Fields: `ipfs`, `privateKey`, `publicKey`, `stateDir`, `pinnedCids`, `ipnsKeyNames`, `pinata`, poll configuration, stress test settings

## Entry Points

**PoC Console Harness:**
- Location: `poc/src/index.ts`
- Triggers: `npm start` in `poc/` directory (runs via tsx)
- Responsibilities: Execute full file/folder flow (create → upload → modify → rename → move → delete → teardown), measure IPNS propagation delays, verify correctness, unpin all resources

**Key Generation Script:**
- Location: `poc/scripts/gen-private-key.ts`
- Triggers: `npm run gen:key` in `poc/` directory
- Responsibilities: Generate 32-byte random ECDSA private key for harness `.env` configuration

**Documentation Entry:**
- Location: `00_START_HERE.md`
- Triggers: Human reader
- Responsibilities: Explain project structure, link to specifications, provide architecture overview

## Error Handling

**Strategy:** Fail-fast with descriptive error messages

**Patterns:**
- Crypto operations wrapped in try-catch with error propagation (e.g., `poc/src/index.ts` line 721)
- IPFS/IPNS failures throw errors with context (CID, IPNS name, operation)
- Timeout handling for IPNS propagation with configurable poll interval and timeout (lines 196-212)
- Graceful degradation for cleanup operations (warn on failure but continue, e.g., lines 227-229, 711-715)
- Validation errors throw with specific missing field/expected value information

## Cross-Cutting Concerns

**Logging:** Console.log with step markers (`logStep` function), formatted byte sizes, IPNS record size logging where available

**Validation:** Type-safe TypeScript with strict compiler settings (`tsconfig.json`), runtime CID/IPNS name resolution verification, content hash comparison after decrypt

**Authentication:** Not implemented in PoC (uses static private key from env var). Specified for production: Web3Auth → ECDSA keypair derivation → JWT/SIWE authentication with backend

---

*Architecture analysis: 2026-01-19*
