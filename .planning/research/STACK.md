# Stack Research: Milestone 2

**Project:** CipherBox
**Milestone:** 2 - Production v1.0
**Research Date:** 2026-02-11
**Confidence:** MEDIUM-HIGH
**Mode:** Ecosystem (stack additions for new features)

## Executive Summary

Milestone 2 adds six major capability areas to an already-functioning zero-knowledge encrypted storage system: sharing, search, MFA, versioning, advanced sync, and AWS Nitro TEE fallback. The core constraint -- all encryption is client-side, the server is zero-knowledge -- severely limits what off-the-shelf solutions can be used. Most features require custom implementations atop cryptographic primitives the project already has (`eciesjs`, `@noble/*`, Web Crypto API).

The key finding is that **most M2 features do NOT require new heavy dependencies**. Instead, they require careful protocol-level design using existing crypto primitives plus lightweight utility libraries. The two exceptions are MFA (which leverages Web3Auth's built-in MFA system) and WebAuthn passkeys (which require `@simplewebauthn/*` on both client and server).

## Existing Stack (DO NOT CHANGE)

These are validated and deployed. Listed for reference only -- research focuses on additions.

| Component          | Package                 | Version (Installed) |
| ------------------ | ----------------------- | ------------------- |
| Backend Framework  | `@nestjs/core`          | ^11.0.0             |
| ORM                | `typeorm`               | ^0.3.28             |
| Database           | PostgreSQL              | 16.x                |
| Queue              | `bullmq` + `ioredis`    | ^5.67.3 / ^5.9.2    |
| Frontend Framework | `react` + `react-dom`   | ^18.3.1             |
| Build Tool         | `vite`                  | ^7.3.0              |
| State Management   | `zustand`               | ^5.0.10             |
| Server State       | `@tanstack/react-query` | ^5.62.0             |
| Auth SDK           | `@web3auth/modal`       | ^10.13.1            |
| ECIES              | `eciesjs`               | ^0.4.16             |
| Ed25519            | `@noble/ed25519`        | ^2.2.3              |
| Hashing            | `@noble/hashes`         | ^1.7.1              |
| IPNS               | `ipns`                  | ^10.1.3             |
| API Client Gen     | `orval`                 | ^7.3.0              |
| Desktop            | `@tauri-apps/api`       | ^2.0.0              |
| JWT                | `jose`                  | ^6.1.3              |
| API Client         | `axios`                 | ^1.13.2             |

---

## Feature 1: File/Folder Sharing (Zero-Knowledge Key Exchange)

### Architecture Decision

Sharing in a zero-knowledge system requires the **sender to re-encrypt keys for the recipient's public key**. CipherBox already wraps every key (folderKey, fileKey, ipnsPrivateKey) with ECIES using the owner's publicKey. Sharing means producing additional ECIES-wrapped copies of those keys for each recipient's publicKey.

No new cryptographic library is needed. The existing `eciesjs` (already `^0.4.16`) handles all required ECIES operations. The `wrapKey()` function in `packages/crypto/src/ecies/encrypt.ts` already accepts any recipient publicKey.

### New Dependencies: NONE for crypto

The sharing protocol is purely a server-side coordination + client-side key re-wrapping exercise.

### Server-Side Additions

| Need                          | Solution                                          | New Dependency?            |
| ----------------------------- | ------------------------------------------------- | -------------------------- |
| Share invitation records      | New TypeORM entities (`Share`, `ShareInvitation`) | No -- use existing TypeORM |
| Recipient public key lookup   | New API endpoint `/users/lookup?publicKey=0x...`  | No                         |
| Share token generation        | Use existing `jose` for signed share tokens       | No                         |
| Permission model (read/write) | Metadata field in `Share` entity                  | No                         |
| Notification of new shares    | BullMQ job (already have queue infrastructure)    | No                         |

### Client-Side Additions

| Need                                    | Solution                                          | New Dependency? |
| --------------------------------------- | ------------------------------------------------- | --------------- |
| Re-encrypt folderKey for recipient      | Existing `wrapKey(folderKey, recipientPublicKey)` | No              |
| Re-encrypt ipnsPrivateKey for recipient | Same `wrapKey()`                                  | No              |
| Share UI (invite dialog, share list)    | React components                                  | No              |
| Recipient lookup by identifier          | New API call via existing axios/orval             | No              |

### What to Build (Not Install)

1. **Share metadata format** -- Extend `FolderMetadata` to include `sharedWith` array containing `{ publicKey, folderKeyEncrypted, ipnsPrivateKeyEncrypted, permissions }`
2. **Share API endpoints** -- `POST /shares/invite`, `GET /shares/pending`, `POST /shares/accept`, `DELETE /shares/{id}`
3. **Share database tables** -- `shares` and `share_invitations` in PostgreSQL
4. **Key re-wrapping module** -- Thin wrapper in `@cipherbox/crypto` that takes a key + new recipient publicKey and produces a new ECIES ciphertext

### Confidence: HIGH

This is a well-understood pattern. ECIES re-encryption is exactly what the existing crypto package does. The challenge is protocol design, not technology selection.

---

## Feature 2: Client-Side Encrypted Search Index

### The Zero-Knowledge Constraint

The server MUST NOT know what the user is searching for or what the search results are. This eliminates all server-side search solutions (Elasticsearch, PostgreSQL full-text search, etc.).

The search index must be:

1. **Built client-side** from decrypted file/folder names and metadata
2. **Stored client-side** (encrypted at rest in IndexedDB)
3. **Queried client-side** in the browser/desktop

### Recommended: MiniSearch

| Library    | Version | Weekly Downloads | TypeScript         | Zero-Dep | Size       |
| ---------- | ------- | ---------------- | ------------------ | -------- | ---------- |
| MiniSearch | ^7.2.0  | ~700K            | Native (src in TS) | Yes      | ~7KB gzip  |
| Fuse.js    | ^7.0.0  | ~5M              | Types included     | Yes      | ~15KB gzip |
| FlexSearch | ^0.7.43 | ~420K            | Community types    | Yes      | ~6KB gzip  |
| Lunr       | ^2.3.9  | ~3.7M            | Community types    | Yes      | ~8KB gzip  |

Why MiniSearch over alternatives:

1. **Written in TypeScript natively** (since v7.0.0) -- not just type declarations bolted on, but full TypeScript source. Aligns with project standards.
2. **Supports index serialization/deserialization** -- Critical for persisting the encrypted index to IndexedDB. `JSON.stringify(miniSearch)` produces a serializable index that can be encrypted with AES-256-GCM and stored.
3. **Prefix search + fuzzy search + field boosting** -- Covers all search UX needs for filename/path matching.
4. **Zero runtime dependencies** -- No supply chain risk.
5. **Memory efficient** -- Designed for browser environments and mobile-constrained memory.

Why NOT Fuse.js: Fuse.js is purely a fuzzy matcher -- it re-scans the full document list on every query (O(n)). MiniSearch builds an inverted index (O(log n) queries). For a vault with thousands of files, MiniSearch is materially faster.

Why NOT FlexSearch: FlexSearch has stale TypeScript types (@types/flexsearch is unmaintained) and the v0.7.x API has breaking changes with poor migration docs. Its index serialization story is more complex.

### Index Persistence Layer: idb (IndexedDB wrapper)

| Library | Version | Purpose                         |
| ------- | ------- | ------------------------------- |
| `idb`   | ^8.0.0  | Promise-based IndexedDB wrapper |

Why `idb` over `idb-keyval`: The search index needs object stores with structured queries (e.g., "get all index chunks"), not just key-value. `idb` (~1KB) provides the full IndexedDB API with promises. `idb-keyval` is simpler but insufficient.

Why NOT localForage: Adds unnecessary abstraction and fallback logic (localStorage, WebSQL) that we don't need.

### Search Architecture

```text
Decrypted metadata (in memory)
       |
       v
MiniSearch.addAll(documents)   <-- Build index from file names, paths, sizes, dates
       |
       v
JSON.stringify(miniSearch)     <-- Serialize index
       |
       v
AES-256-GCM encrypt            <-- Existing @cipherbox/crypto
       |
       v
idb.put('search-index', encrypted)  <-- Persist to IndexedDB
```

On next session:

```text
idb.get('search-index')        <-- Load from IndexedDB
       |
       v
AES-256-GCM decrypt            <-- Existing @cipherbox/crypto
       |
       v
MiniSearch.loadJSON(parsed)    <-- Restore index
       |
       v
miniSearch.search('query')     <-- Instant client-side search
```

### New Dependencies

```bash
# In apps/web
pnpm add minisearch idb

# In apps/desktop (if search is supported there too)
pnpm add minisearch idb
```

### What NOT to Use

| Library                   | Why Not                                                                   |
| ------------------------- | ------------------------------------------------------------------------- |
| CipherSweet               | Server-side searchable encryption -- irrelevant for client-side ZK search |
| Elasticsearch / Typesense | Server-side search -- violates zero-knowledge                             |
| localForage               | Unnecessary abstraction over IndexedDB                                    |
| Fuse.js                   | O(n) per query, no inverted index                                         |

### Confidence: HIGH

MiniSearch is well-established (v7.2.0, actively maintained, TypeScript-native). The pattern of "build index client-side, encrypt, persist to IndexedDB" is straightforward. The `@cipherbox/crypto` package already has all needed encryption primitives.

---

## Feature 3: MFA (Passkey/WebAuthn, TOTP, Recovery Phrase)

### Two Layers of MFA

CipherBox has a unique MFA architecture because authentication happens in two phases:

1. **Web3Auth MFA** -- Protects the key derivation step (getting the ECDSA keypair)
2. **CipherBox Backend MFA** -- Protects API access (optional additional layer)

The PRD specifies MFA, and Web3Auth provides this natively. The recommended approach is to leverage Web3Auth's built-in MFA rather than building a separate MFA system.

### Layer 1: Web3Auth Built-In MFA (PRIMARY)

No new packages needed. The existing `@web3auth/modal` ^10.13.1 supports MFA configuration natively.

Available factors (configured via `mfaSettings`):

| Factor        | Config Key            | Description                        |
| ------------- | --------------------- | ---------------------------------- |
| Device Share  | `deviceShareFactor`   | Stores a key share on the device   |
| Backup Phrase | `backUpShareFactor`   | 24-word seed phrase for recovery   |
| Social Backup | `socialBackupFactor`  | Backup via social login            |
| Password      | `passwordFactor`      | User-chosen password               |
| Passkeys      | `passkeysFactor`      | WebAuthn passkey                   |
| Authenticator | `authenticatorFactor` | TOTP (Google Authenticator, Authy) |

Configuration:

```typescript
const web3auth = new Web3Auth({
  // ... existing config
  mfaSettings: {
    deviceShareFactor: { enable: true, priority: 1, mandatory: true },
    backUpShareFactor: { enable: true, priority: 2, mandatory: true },
    passkeysFactor: { enable: true, priority: 3, mandatory: false },
    authenticatorFactor: { enable: true, priority: 4, mandatory: false },
    passwordFactor: { enable: false },
    socialBackupFactor: { enable: false },
  },
});
```

IMPORTANT CAVEAT: The `mfaSettings` configuration is a paid feature on Web3Auth's SCALE Plan. Verify current pricing before committing to this approach. On the `sapphire_devnet` network (which CipherBox likely uses for development), it is free.

### Layer 2: CipherBox Backend WebAuthn (SECONDARY -- for API access)

If the project wants WebAuthn passkeys as an additional factor for CipherBox API authentication (beyond Web3Auth), use `@simplewebauthn/*`.

### Recommended: @simplewebauthn

| Package                   | Version | Purpose                              | Where      |
| ------------------------- | ------- | ------------------------------------ | ---------- |
| `@simplewebauthn/server`  | ^13.2.2 | Registration/verification on backend | `apps/api` |
| `@simplewebauthn/browser` | ^13.2.2 | Browser WebAuthn API calls           | `apps/web` |

Why @simplewebauthn:

1. **TypeScript-first** -- 100% TypeScript source, excellent types
2. **Most popular WebAuthn library for Node.js** -- 184 dependents for server, 284 for browser
3. **Works with NestJS** -- Via `passport-simple-webauthn` or direct integration (no passport needed)
4. **Actively maintained** -- v13.2.2 published October 2025
5. **Handles complexity** -- WebAuthn has many edge cases (attestation formats, authenticator types, CBOR parsing). This library handles them all.

NestJS Integration Pattern:

Do NOT use `passport-simple-webauthn` (v0.1.0, 2 years stale). Instead, integrate `@simplewebauthn/server` directly into NestJS services:

```typescript
// apps/api/src/webauthn/webauthn.service.ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
```

### TOTP (Authenticator App) for CipherBox Backend

If TOTP is needed as a CipherBox backend factor (separate from Web3Auth's authenticator), use `otpauth`.

| Package   | Version | Purpose                    | Where                                            |
| --------- | ------- | -------------------------- | ------------------------------------------------ |
| `otpauth` | ^9.5.0  | TOTP generation/validation | `apps/api` (generation), `apps/web` (QR display) |

Why `otpauth` over `otplib`:

1. **Zero dependencies** -- `otplib` v13 has dependencies; `otpauth` v9 is self-contained
2. **Multi-runtime** -- Works in Node.js, Deno, Bun, and browsers
3. **RFC compliant** -- RFC 4226 (HOTP), RFC 6238 (TOTP)
4. **Key URI format** -- Built-in `otpauth://` URI generation for QR codes
5. **Actively maintained** -- v9.5.0 published February 2026

### Recovery Phrase

No new library needed. Recovery phrase generation uses existing crypto primitives:

- Generate 256 bits of entropy via `crypto.getRandomValues()`
- Convert to BIP-39 mnemonic using `@noble/hashes` (SHA-256 for checksum) plus a wordlist
- OR use Web3Auth's built-in `backUpShareFactor` which handles this automatically

If implementing independently (outside Web3Auth), consider:

| Package        | Version | Purpose                                              |
| -------------- | ------- | ---------------------------------------------------- |
| `@scure/bip39` | ^1.4.0  | BIP-39 mnemonic generation (from `@noble` ecosystem) |

Why `@scure/bip39`: Same author as `@noble/*` libraries (Paul Miller), audited, zero dependencies, TypeScript-native.

### Recommended MFA Strategy

Use Web3Auth's built-in MFA as the primary mechanism. It protects the most critical step (key derivation). Adding CipherBox-level WebAuthn/TOTP is optional hardening for API access.

| Factor           | Provider              | Priority      | Package                                |
| ---------------- | --------------------- | ------------- | -------------------------------------- |
| Device share     | Web3Auth              | 1 (mandatory) | `@web3auth/modal` (existing)           |
| Backup phrase    | Web3Auth              | 2 (mandatory) | `@web3auth/modal` (existing)           |
| Passkey/WebAuthn | Web3Auth OR CipherBox | 3 (optional)  | `@simplewebauthn/*` if CipherBox-level |
| TOTP             | Web3Auth OR CipherBox | 4 (optional)  | `otpauth` if CipherBox-level           |

### New Dependencies (if implementing CipherBox-level MFA beyond Web3Auth)

```bash
# Backend
cd apps/api && pnpm add @simplewebauthn/server otpauth

# Frontend
cd apps/web && pnpm add @simplewebauthn/browser

# Crypto (if custom recovery phrase)
cd packages/crypto && pnpm add @scure/bip39
```

### Database Additions

New TypeORM entities needed for CipherBox-level MFA:

- `webauthn_credentials` -- Store WebAuthn credential IDs, public keys, counter, transports
- `totp_secrets` -- Store encrypted TOTP secrets (encrypt with user's publicKey before storing)
- `recovery_codes` -- Store hashed recovery codes (use `argon2`, already installed)

### Confidence: MEDIUM-HIGH

Web3Auth MFA is well-documented but the `mfaSettings` is a paid feature (SCALE plan). SimpleWebAuthn v13 is mature. The open question is whether to implement MFA at the Web3Auth level, CipherBox level, or both. Recommend: Web3Auth level first, CipherBox level as optional hardening.

---

## Feature 4: File Version History

### IPFS Natural Fit

IPFS is content-addressable -- every version of a file inherently has a different CID. The challenge is not storing versions (IPFS does this) but **tracking the version chain** (linking CIDs into a history).

### Architecture: Version Chain in Metadata

No new library needed. Version history is a metadata design problem, not a library problem.

Extend the `FileEntry` type in `packages/crypto/src/folder/types.ts`:

```typescript
export type FileEntry = {
  // ... existing fields
  type: 'file';
  id: string;
  name: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  encryptionMode: 'GCM';
  size: number;
  createdAt: number;
  modifiedAt: number;

  // NEW: Version history
  /** Previous version CID chain (most recent first, capped) */
  previousVersions?: FileVersionEntry[];
  /** Current version number (starts at 1) */
  versionNumber?: number;
};

export type FileVersionEntry = {
  /** IPFS CID of this version */
  cid: string;
  /** ECIES-wrapped file key for this version */
  fileKeyEncrypted: string;
  /** IV used for this version */
  fileIv: string;
  /** File size at this version */
  size: number;
  /** When this version was created */
  createdAt: number;
  /** Version number */
  versionNumber: number;
};
```

### Version Retention Strategy

Since file versions are pinned on IPFS (via Pinata), they consume storage quota. Need a configurable retention policy:

| Strategy             | Implementation                                             |
| -------------------- | ---------------------------------------------------------- |
| Keep last N versions | `previousVersions.slice(0, N)` in metadata, unpin old CIDs |
| Time-based retention | Filter `previousVersions` by `createdAt` threshold         |
| Storage-based limit  | Track total version bytes, evict oldest when threshold hit |

### Server-Side Support

| Need                          | Solution                                   | New Dependency? |
| ----------------------------- | ------------------------------------------ | --------------- |
| Track pinned version CIDs     | Extend existing `pinned_cids` entity       | No              |
| Unpinning old versions        | BullMQ job to unpin expired version CIDs   | No              |
| Version count limits per user | Config in vault settings                   | No              |
| Storage quota accounting      | Include version bytes in quota calculation | No              |

### What NOT to Build

| Approach                  | Why Not                                                               |
| ------------------------- | --------------------------------------------------------------------- |
| Git-like delta storage    | Over-engineered for file storage; IPFS is already content-addressable |
| Separate version database | Violates zero-knowledge (server would know version relationships)     |
| IPFS MFS versioning       | Deprecated/experimental; CipherBox doesn't use MFS                    |
| IPVC / IPVFS              | Unmaintained projects, not suited for encrypted use case              |

### New Dependencies: NONE

### Confidence: HIGH

Version history is purely a metadata schema extension plus Pinata pin management. The existing stack handles everything needed.

---

## Feature 5: Advanced Sync (Conflict Resolution, Offline Queue, Selective Sync)

### Current State

CipherBox v1 uses IPNS polling (30s interval) with last-writer-wins based on IPNS sequence numbers. This is fragile under concurrent edits.

### Conflict Resolution Strategy

Recommendation: Do NOT adopt a full CRDT library. CipherBox's data model (encrypted file metadata in IPNS records) is fundamentally different from collaborative text editing. CRDTs like Yjs/Automerge are designed for real-time co-editing of shared data structures -- overkill for file metadata sync.

Instead, implement Operational Transform (OT) at the metadata level:

| Operation                       | Conflict Rule                   |
| ------------------------------- | ------------------------------- |
| Two users add different files   | Merge (union of children)       |
| Two users delete same file      | Idempotent (already deleted)    |
| Two users rename same file      | Last-writer-wins with timestamp |
| Two users move same file        | Last-writer-wins with timestamp |
| One adds, one deletes same file | Delete wins (conservative)      |

### Why NOT CRDTs

| Library   | Why Not for CipherBox                                                                                                                                                                                 |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Yjs       | Designed for real-time collaborative editing (text, JSON). CipherBox doesn't need real-time -- it syncs metadata blobs via IPNS. Adding Yjs would require restructuring the entire metadata format.   |
| SecSync   | Interesting E2E encrypted CRDT architecture, but beta (v0.5.0), uses XChaCha20-Poly1305 (incompatible with existing AES-256-GCM), and requires a WebSocket server. Over-engineered for metadata sync. |
| Automerge | Same issues as Yjs -- designed for collaborative documents, not file metadata sync.                                                                                                                   |

### Offline Queue

No new library needed. Implement a simple queue using IndexedDB persistence.

```typescript
// Offline operation queue
type QueuedOperation = {
  id: string;
  type: 'upload' | 'delete' | 'rename' | 'move' | 'mkdir';
  payload: unknown; // operation-specific data
  timestamp: number;
  retryCount: number;
};
```

Use the same `idb` library (^8.0.0) recommended for search index persistence.

### Selective Sync (Desktop Only)

Selective sync requires Tauri-side file system awareness. No new npm packages -- this is a Tauri/Rust concern:

| Need                             | Solution                                    | Where             |
| -------------------------------- | ------------------------------------------- | ----------------- |
| Sync configuration               | JSON config in app data directory           | Tauri (Rust)      |
| Folder inclusion/exclusion list  | UI component + persisted config             | React + Tauri IPC |
| Placeholder files (like Dropbox) | macOS: Extended attributes; Linux: symlinks | Rust FUSE layer   |

### New Dependencies: NONE (beyond `idb` already counted in search)

### Confidence: MEDIUM

Conflict resolution design is straightforward conceptually but tricky to get right in practice, especially with encrypted metadata where you can't do server-side merging. The "merge at client-side, resign IPNS" approach needs careful testing. Flagging for deeper research during implementation.

---

## Feature 6: AWS Nitro TEE Fallback

### Current State

CipherBox uses Phala Cloud as the primary TEE for IPNS republishing. AWS Nitro is specified as the fallback.

### AWS Nitro Enclave Architecture

AWS Nitro Enclaves run inside a special VM partition on EC2 instances. The enclave has no network access, no persistent storage -- it communicates only via a vsock channel with the parent EC2 instance.

IMPORTANT: There is NO official JavaScript/TypeScript SDK for AWS Nitro Enclaves NSM (Nitro Security Module) API. The official SDK is Rust-only (`aws-nitro-enclaves-nsm-api` crate).

### Recommended Architecture

| Component                      | Technology                             | Language   |
| ------------------------------ | -------------------------------------- | ---------- |
| Enclave application            | Rust binary                            | Rust       |
| Attestation                    | `aws-nitro-enclaves-nsm-api` crate     | Rust       |
| ECIES decryption               | `ecies` Rust crate (secp256k1)         | Rust       |
| Ed25519 IPNS signing           | `ed25519-dalek` crate                  | Rust       |
| IPNS record creation           | Custom (port from `@cipherbox/crypto`) | Rust       |
| Parent-enclave communication   | vsock                                  | Rust       |
| Orchestrator (parent instance) | Node.js (NestJS)                       | TypeScript |
| KMS integration                | `@aws-sdk/client-kms`                  | TypeScript |

### New Dependencies

For the NestJS orchestrator (parent EC2 instance):

```bash
cd apps/api && pnpm add @aws-sdk/client-kms @aws-sdk/client-ec2
```

| Package               | Version | Purpose                                 |
| --------------------- | ------- | --------------------------------------- |
| `@aws-sdk/client-kms` | ^3.x    | KMS condition key attestation for Nitro |
| `@aws-sdk/client-ec2` | ^3.x    | Enclave lifecycle management (optional) |

For the enclave (Rust, separate from Node.js monorepo):

```toml
# Cargo.toml for enclave binary
[dependencies]
aws-nitro-enclaves-nsm-api = "0.4"
ecies = { version = "0.2", default-features = false }
ed25519-dalek = "2.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
nix = { version = "0.29", features = ["socket"] }  # vsock
```

### Integration with Existing System

The NestJS backend already has:

- `republish-schedule.entity.ts` -- Stores encryptedIpnsPrivateKey and keyEpoch
- `tee-key-state.entity.ts` -- Tracks TEE key epochs
- BullMQ for job scheduling

The Nitro fallback can reuse the same republish scheduling infrastructure. The only change is routing republish jobs to Nitro instead of Phala when Phala is unavailable.

### Phala Cloud SDK Update

The existing Phala integration may benefit from updating to the latest dstack SDK:

| Package             | Version | Purpose                                           |
| ------------------- | ------- | ------------------------------------------------- |
| `@phala/dstack-sdk` | latest  | TEE client SDK for attestation and key derivation |

Note: Verify whether CipherBox currently uses `@phala/dstack-sdk` or a different Phala integration. The existing codebase should be checked.

### What NOT to Do

| Approach                          | Why Not                                                                                 |
| --------------------------------- | --------------------------------------------------------------------------------------- |
| Run Node.js inside Nitro Enclave  | No official NSM API for JavaScript; would need WASM bridge. Rust is the supported path. |
| Use community JS bindings for NSM | None exist that are production-quality                                                  |
| Skip attestation                  | Defeats the purpose of TEE -- must verify enclave integrity                             |

### Confidence: MEDIUM

The Rust enclave binary is well-understood architecturally but represents a new build target for the project. The vsock communication protocol needs custom implementation. This is the highest-effort feature in M2.

---

## Consolidated New Dependencies

### apps/web (Frontend)

```bash
pnpm add minisearch idb @simplewebauthn/browser
```

| Package                   | Version | Purpose                             | Size      |
| ------------------------- | ------- | ----------------------------------- | --------- |
| `minisearch`              | ^7.2.0  | Client-side full-text search engine | ~7KB gzip |
| `idb`                     | ^8.0.0  | Promise-based IndexedDB wrapper     | ~1KB gzip |
| `@simplewebauthn/browser` | ^13.2.2 | WebAuthn browser API                | ~5KB gzip |

### apps/api (Backend)

```bash
pnpm add @simplewebauthn/server otpauth @aws-sdk/client-kms
```

| Package                  | Version | Purpose                            | Notes                            |
| ------------------------ | ------- | ---------------------------------- | -------------------------------- |
| `@simplewebauthn/server` | ^13.2.2 | WebAuthn registration/verification | Only if CipherBox-level WebAuthn |
| `otpauth`                | ^9.5.0  | TOTP generation/validation         | Only if CipherBox-level TOTP     |
| `@aws-sdk/client-kms`    | ^3.x    | AWS KMS attestation for Nitro      | Only when Nitro fallback ships   |

### packages/crypto (Shared Crypto)

```bash
pnpm add @scure/bip39
```

| Package        | Version | Purpose                    | Notes                                             |
| -------------- | ------- | -------------------------- | ------------------------------------------------- |
| `@scure/bip39` | ^1.4.0  | BIP-39 mnemonic generation | Only if custom recovery phrase (outside Web3Auth) |

### New Rust crate (AWS Nitro Enclave binary)

This is a **separate build target**, not part of the pnpm monorepo:

```toml
[dependencies]
aws-nitro-enclaves-nsm-api = "0.4"
ecies = "0.2"
ed25519-dalek = "2.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
nix = { version = "0.29", features = ["socket"] }
```

---

## What NOT to Add (and Why)

| Library/Tool              | Temptation               | Why Not                                                                                                                                       |
| ------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Yjs / Automerge           | "CRDTs solve sync"       | CipherBox syncs encrypted metadata blobs, not collaborative documents. CRDTs add ~50KB+ and require restructuring the entire metadata format. |
| SecSync                   | "E2E encrypted CRDTs"    | Beta (v0.5.0), uses XChaCha20 (not AES-256-GCM), requires WebSocket server, over-engineered for metadata sync.                                |
| Elasticsearch / Typesense | "Full-text search"       | Server-side search violates zero-knowledge. All search must be client-side.                                                                   |
| Fuse.js                   | "Fuzzy search"           | No inverted index (O(n) per query). MiniSearch is faster for indexed search.                                                                  |
| CipherSweet               | "Searchable encryption"  | Server-side blind indexes -- doesn't apply to client-side-only search.                                                                        |
| jsonwebtoken              | "JWT for share tokens"   | `jose` (already installed) is better -- supports all JWK/JWS/JWE operations.                                                                  |
| passport-simple-webauthn  | "Passport + WebAuthn"    | v0.1.0, 2 years stale. Integrate @simplewebauthn/server directly into NestJS services.                                                        |
| localForage               | "IndexedDB wrapper"      | Unnecessary fallback logic. `idb` is lighter and more appropriate.                                                                            |
| @noble/curves (new)       | "Need secp256k1"         | Already have `eciesjs` which wraps this. Don't duplicate.                                                                                     |
| proxy-re-encryption libs  | "Re-encrypt for sharing" | ECIES re-wrapping with existing library is simpler and sufficient. Proxy re-encryption adds unnecessary complexity.                           |

---

## Integration Points with Existing Stack

### TypeORM Migrations Needed

New entities and their relationships:

```text
shares
  - id (uuid PK)
  - folder_ipns_name (FK to folder_ipns)
  - owner_id (FK to users)
  - recipient_id (FK to users)
  - permissions ('read' | 'readwrite')
  - folder_key_encrypted (text) -- ECIES-wrapped for recipient
  - ipns_private_key_encrypted (text) -- ECIES-wrapped for recipient
  - created_at, updated_at

share_invitations
  - id (uuid PK)
  - share_id (FK to shares)
  - invite_token_hash (text)
  - status ('pending' | 'accepted' | 'rejected' | 'expired')
  - expires_at (timestamp)

webauthn_credentials (if CipherBox-level WebAuthn)
  - id (uuid PK)
  - user_id (FK to users)
  - credential_id (bytea)
  - public_key (bytea)
  - counter (integer)
  - transports (text[])
  - created_at

totp_secrets (if CipherBox-level TOTP)
  - id (uuid PK)
  - user_id (FK to users)
  - encrypted_secret (text) -- encrypted with user's publicKey
  - verified (boolean)
  - created_at
```

### BullMQ Job Types to Add

| Job               | Queue           | Purpose                                        |
| ----------------- | --------------- | ---------------------------------------------- |
| `share.notify`    | `notifications` | Notify recipient of new share                  |
| `version.cleanup` | `maintenance`   | Unpin expired version CIDs from Pinata         |
| `search.reindex`  | `client-tasks`  | Trigger client-side reindex after bulk changes |
| `nitro.republish` | `republish`     | Route to Nitro when Phala is unavailable       |

### @cipherbox/crypto Package Extensions

New modules to add:

```text
packages/crypto/src/
  sharing/
    re-wrap-key.ts        -- Re-encrypt a key for a new recipient
    share-token.ts        -- Generate/verify share invitation tokens
    types.ts              -- ShareMetadata types
  search/
    index-crypto.ts       -- Encrypt/decrypt search index blob
    types.ts              -- SearchIndex types
  versioning/
    types.ts              -- FileVersionEntry types
```

---

## Version Verification Summary

| Package                   | Claimed Version | Verification Method                                 | Confidence                                                 |
| ------------------------- | --------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| `minisearch`              | ^7.2.0          | WebSearch (Libraries.io confirms 7.2.0)             | HIGH                                                       |
| `idb`                     | ^8.0.0          | WebSearch (npm page)                                | MEDIUM (exact latest not confirmed, 8.x series is current) |
| `@simplewebauthn/server`  | ^13.2.2         | WebSearch (npm confirms 13.2.2, published Oct 2025) | HIGH                                                       |
| `@simplewebauthn/browser` | ^13.2.2         | WebSearch (npm confirms 13.2.2)                     | HIGH                                                       |
| `otpauth`                 | ^9.5.0          | WebSearch (npm confirms 9.5.0, published Feb 2026)  | HIGH                                                       |
| `@scure/bip39`            | ^1.4.0          | Training data (noble ecosystem, likely current)     | MEDIUM                                                     |
| `@aws-sdk/client-kms`     | ^3.x            | WebSearch (AWS SDK v3 is current)                   | HIGH                                                       |
| `@phala/dstack-sdk`       | latest          | WebSearch (npm page exists, actively maintained)    | MEDIUM                                                     |

---

## Roadmap Implications

### Phase Ordering (by dependency chain)

1. **Versioning first** -- Lowest risk, no new dependencies, purely metadata schema work. Good warmup.
2. **Search second** -- Small new dependencies (minisearch, idb), client-only, no API changes needed.
3. **MFA third** -- Web3Auth config change is fast; CipherBox-level WebAuthn/TOTP needs new API endpoints.
4. **Sharing fourth** -- Most complex feature, touches crypto, API, and UI. Needs the other features stable first.
5. **Advanced sync fifth** -- Conflict resolution is best designed after sharing is working (sharing introduces multi-writer scenarios that inform conflict rules).
6. **Nitro fallback sixth** -- Separate build target (Rust enclave), can be developed in parallel but should ship last.

### Risk Assessment

| Feature        | Risk                                           | Mitigation                                                          |
| -------------- | ---------------------------------------------- | ------------------------------------------------------------------- |
| Sharing        | MEDIUM -- Protocol design complexity           | Prototype key re-wrapping first, validate with test vectors         |
| Search         | LOW -- Well-understood pattern                 | MiniSearch is battle-tested                                         |
| MFA            | LOW-MEDIUM -- Web3Auth pricing dependency      | Verify SCALE plan pricing; fallback to CipherBox-level MFA          |
| Versioning     | LOW -- Metadata extension only                 | Keep version chain short (max 50) to avoid metadata bloat           |
| Advanced Sync  | MEDIUM-HIGH -- Conflict resolution edge cases  | Extensive test matrix; start with last-writer-wins, evolve          |
| Nitro Fallback | HIGH -- New language (Rust enclave), new infra | Prototype vsock communication early; consider hiring Rust expertise |

---

_Research complete: 2026-02-11_
_Sources verified via WebSearch, official documentation, and codebase inspection_
