# Architecture Patterns

**Domain:** Zero-knowledge encrypted cloud storage with IPFS/IPNS
**Researched:** 2026-01-20
**Confidence:** HIGH (verified against finalized specifications and industry patterns)

## Executive Summary

CipherBox's specified architecture follows established zero-knowledge encrypted storage patterns with a unique twist: using IPFS/IPNS for decentralized content-addressable storage instead of traditional cloud blob storage. This research validates the architecture against industry patterns and identifies component boundaries, data flows, and build order recommendations.

**Architecture Validation:** The specified architecture is sound and follows industry best practices for zero-knowledge systems. The key innovation (TEE-based IPNS republishing) addresses a real IPNS limitation and is well-designed.

---

## Recommended Architecture

The CipherBox architecture consists of six primary components with clear boundaries and responsibilities.

### High-Level Component Diagram

```
                                 +-------------------+
                                 |    End Users      |
                                 +--------+----------+
                                          |
              +---------------------------+---------------------------+
              |                           |                           |
    +---------v---------+      +----------v----------+     +----------v----------+
    |   Web3Auth        |      |     Web Client      |     |   Desktop Client    |
    |   Network         |      |     (React 18)      |     |   (Tauri/FUSE)      |
    |                   |      |                     |     |                     |
    | - OAuth/Email     |      | - File browser UI   |     | - FUSE mount        |
    | - Key derivation  |      | - Crypto module     |     | - Crypto module     |
    | - MPC threshold   |      | - IPNS signing      |     | - Background sync   |
    +---------+---------+      +----------+----------+     +----------+----------+
              |                           |                           |
              |    (1) keypair            |    (2) encrypted data     |
              +------------+--------------+------------+--------------+
                           |                           |
                           v                           v
               +-----------+-------------+-------------+-----------+
               |                                                   |
               |              CipherBox Backend (NestJS)           |
               |                                                   |
               | +---------------+  +----------------+  +---------+|
               | | Auth Service  |  | Vault Service  |  | IPFS    ||
               | | - JWT verify  |  | - Key storage  |  | Relay   ||
               | | - Token mgmt  |  | - Quota track  |  | Service ||
               | +-------+-------+  +--------+-------+  +----+----+|
               |         |                   |               |     |
               +---------+-------------------+---------------+-----+
                         |                   |               |
                         v                   v               v
               +---------+-------+   +-------+-------+  +----+------+
               |   PostgreSQL    |   |   PostgreSQL  |  |  Pinata   |
               |   (Auth data)   |   |   (Vault data)|  |  (Pinning)|
               +-------+---------+   +-------+-------+  +-----+-----+
                       |                     |                |
                       +---------------------+                |
                                             |                |
                                    +--------v--------+       |
                                    |  TEE Provider   |       |
                                    |  (Phala Cloud)  |<------+
                                    |                 |  IPNS republish
                                    | - Key decrypt   |
                                    | - IPNS signing  |
                                    | - Memory zero   |
                                    +-----------------+
                                             |
                                             v
                                    +-----------------+
                                    |   IPFS Network  |
                                    |   (DHT/Pubsub)  |
                                    +-----------------+
```

### Component Boundaries

| Component | Responsibility | Communicates With | Trust Level |
|-----------|---------------|-------------------|-------------|
| **Web3Auth Network** | User authentication, deterministic key derivation (MPC/SSS) | Client apps only | Semi-trusted (threshold crypto) |
| **Web Client** | UI, client-side encryption, IPNS signing, file operations | Backend API, Web3Auth | Fully trusted (user device) |
| **Desktop Client** | FUSE mount, background sync, same crypto as web | Backend API, Web3Auth | Fully trusted (user device) |
| **Backend API** | Auth tokens, encrypted key storage, quota, IPFS/IPNS relay | PostgreSQL, Pinata, TEE | Zero-knowledge (never sees plaintext) |
| **PostgreSQL** | Persistent storage for users, tokens, encrypted keys, schedules | Backend only | Zero-knowledge (encrypted data only) |
| **Pinata** | IPFS pinning service, content availability | Backend relay | Zero-knowledge (encrypted blobs) |
| **TEE Provider** | IPNS republishing with hardware-protected signing | Backend (encrypted keys only) | Hardware-attested, ephemeral access |
| **IPFS Network** | Decentralized content storage, IPNS resolution | All via relays | Public (encrypted content only) |

---

## Data Flow

### Core Data Flow Principle

**All sensitive operations happen client-side.** The server is a "dumb pipe" for encrypted data.

```
USER DEVICE (trusted)                    SERVER (zero-knowledge)
+---------------------------+            +---------------------------+
|                           |            |                           |
|  privateKey (RAM only)    |            |  encryptedRootFolderKey   |
|  rootFolderKey (RAM)      |   <---->   |  encryptedIpnsPrivateKey  |
|  folderKeys (RAM)         |            |  encrypted file blobs     |
|  fileKeys (RAM)           |            |  IPNS names (public)      |
|                           |            |                           |
+---------------------------+            +---------------------------+
        |                                         |
        | plaintext                               | ciphertext only
        v                                         v
+---------------------------+            +---------------------------+
|  User sees:               |            |  Server sees:             |
|  - File names             |            |  - Random bytes           |
|  - File contents          |            |  - CIDs                   |
|  - Folder structure       |            |  - IPNS names             |
+---------------------------+            +---------------------------+
```

### Data Flow Direction Matrix

| Data Type | Client -> Server | Server -> Client | Never Leaves Client |
|-----------|-----------------|------------------|---------------------|
| privateKey | - | - | Yes (RAM only) |
| publicKey | Yes | Yes | - |
| rootFolderKey | Encrypted only | Encrypted only | Plaintext in RAM |
| ipnsPrivateKey | Encrypted only | Encrypted only | Plaintext in RAM |
| File content | Encrypted only | Encrypted only | Plaintext in RAM |
| File names | Encrypted in metadata | Encrypted in metadata | Plaintext in RAM |
| IPNS records | Signed locally | - | Signature happens locally |

### Key Data Flows

#### 1. Authentication Flow

```
User -> Web3Auth: Authenticate (OAuth/Email/Wallet)
Web3Auth -> Client: {privateKey, publicKey, idToken}
Client -> Backend: POST /auth/login {idToken, publicKey}
Backend: Verify JWT, find/create user
Backend -> Client: {accessToken, refreshToken, teeKeys}
Client -> Backend: GET /my-vault
Backend -> Client: {encryptedRootFolderKey, rootIpnsName}
Client: rootFolderKey = ECIES_Decrypt(encrypted, privateKey)
```

#### 2. File Upload Flow

```
Client: fileKey = randomBytes(32)
Client: ciphertext = AES-GCM(plaintext, fileKey)
Client: encryptedFileKey = ECIES(fileKey, publicKey)
Client -> Backend: POST /vault/upload {ciphertext}
Backend -> Pinata: Pin encrypted blob
Backend -> Client: {cid}
Client: Update folder metadata (add file entry)
Client: encryptedMetadata = AES-GCM(metadata, folderKey)
Client: Sign IPNS record with ipnsPrivateKey (Ed25519)
Client: encryptedIpnsKey = ECIES(ipnsPrivateKey, teePublicKey)
Client -> Backend: POST /ipns/publish {signedRecord, encryptedIpnsKey, keyEpoch}
Backend -> IPFS: Publish IPNS record
Backend: Schedule TEE republishing
```

#### 3. TEE Republishing Flow (Background)

```
Backend Cron: SELECT entries WHERE next_republish_at < NOW()
Backend -> TEE: POST /republish {encryptedIpnsKey, keyEpoch, cid}
TEE (in hardware): ipnsKey = ECIES_Decrypt(encrypted, teePrivateKey)
TEE (in hardware): signature = Ed25519_Sign(record, ipnsKey)
TEE (in hardware): zero(ipnsKey) // Immediate memory wipe
TEE -> Backend: {signature}
Backend -> IPFS: Publish signed IPNS record
Backend: UPDATE next_republish_at = NOW() + 3 hours
```

### Security Boundaries

```
+------------------------------------------------------------------+
|                    TRUST BOUNDARY: USER DEVICE                    |
|  +------------------------------------------------------------+  |
|  |  SECURITY CRITICAL ZONE                                    |  |
|  |  - privateKey generation/derivation                        |  |
|  |  - All ECIES decryption                                    |  |
|  |  - All AES-GCM encryption/decryption                       |  |
|  |  - IPNS record signing                                     |  |
|  |  - Memory management (key zeroing on logout)               |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
                              | HTTPS (encrypted transport)
                              | Only ciphertext crosses boundary
                              v
+------------------------------------------------------------------+
|                    ZERO-KNOWLEDGE ZONE                            |
|  +------------------------------------------------------------+  |
|  |  Backend + Database                                        |  |
|  |  - Stores only encrypted keys                              |  |
|  |  - Cannot decrypt any user data                            |  |
|  |  - Relays encrypted blobs to IPFS                          |  |
|  |  - Relays pre-signed IPNS records                          |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
                              | TEE enclave boundary
                              | Encrypted IPNS keys only
                              v
+------------------------------------------------------------------+
|                    TEE HARDWARE BOUNDARY                          |
|  +------------------------------------------------------------+  |
|  |  Phala Cloud / AWS Nitro                                   |  |
|  |  - Hardware-isolated memory                                |  |
|  |  - Keys exist only for milliseconds                        |  |
|  |  - Immediate memory zeroing after signing                  |  |
|  |  - Cannot persist or export keys                           |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

---

## Architecture Pattern Analysis

### Pattern 1: Client-Side Encryption with Key Wrapping

**What:** All encryption happens on user device. Symmetric keys (fileKey, folderKey) are wrapped with user's asymmetric public key (ECIES) before storage.

**Industry Validation:** This is the standard pattern for zero-knowledge systems. Used by Bitwarden, Tresorit, SpiderOak, and others ([Cloudwards](https://www.cloudwards.net/best-zero-knowledge-cloud-services/), [Hivenet](https://www.hivenet.com/post/zero-knowledge-encryption-the-ultimate-guide-to-unbreakable-data-security)).

**CipherBox Implementation:**
```
fileKey (256-bit AES) --> ECIES(fileKey, userPublicKey) --> stored in metadata
folderKey (256-bit AES) --> ECIES(folderKey, userPublicKey) --> stored in parent metadata
ipnsPrivateKey (Ed25519) --> ECIES(ipnsPrivateKey, userPublicKey) --> stored in vault/parent
```

**Assessment:** Correctly implemented. Follows industry standards.

### Pattern 2: Hierarchical Key Structure

**What:** Keys form a tree: Master (ECDSA) -> Folder Keys -> File Keys. Each level wraps the next.

**Industry Validation:** Standard for file system encryption. Allows granular access control (future sharing) and limits blast radius of key compromise.

**CipherBox Implementation:**
```
User ECDSA Keypair (Web3Auth)
    |
    +--> rootFolderKey (AES-256)
    |        |
    |        +--> file1Key, file2Key...
    |        |
    |        +--> subfolderKey
    |                 |
    |                 +--> fileN keys...
    |
    +--> rootIpnsPrivateKey (Ed25519)
             |
             +--> subfolderIpnsPrivateKey...
```

**Assessment:** Well-designed. Per-folder IPNS keys enable future sharing without re-encrypting everything.

### Pattern 3: Content-Addressable Storage with Mutable Pointers

**What:** IPFS provides immutable content storage (CID = hash of content). IPNS provides mutable pointers (name -> CID).

**Industry Validation:** This is IPFS's native architecture. Used by Filecoin, NFT metadata, decentralized websites. ([IPFS Docs](https://docs.ipfs.tech/concepts/ipns/))

**CipherBox Innovation:** Per-folder IPNS names instead of single root IPNS. This is less common but enables modular updates (change one folder without republishing entire tree).

**Assessment:** Sound architecture. Trade-off is more IPNS records to manage, but TEE republishing addresses this.

### Pattern 4: TEE for Background Operations

**What:** Trusted Execution Environment performs IPNS republishing without user device online.

**Industry Validation:** TEE for key management is established in cryptocurrency wallets and DeFi ([a16z](https://a16zcrypto.com/posts/article/trusted-execution-environments-tees-primer/), [Phala](https://phala.com/learn/What-Is-TEE)).

**CipherBox Innovation:** Novel application to IPNS republishing. Solves the 24-hour IPNS record expiry problem elegantly.

**Assessment:** Excellent design. Key epoch rotation with 4-week grace period handles key lifecycle properly.

---

## Architecture Validation

### Strengths

1. **True Zero-Knowledge:** Server mathematically cannot access user data. Private keys never leave client RAM.

2. **Per-Folder Modularity:** Each folder has independent IPNS keypair, enabling future sharing without global re-encryption.

3. **Deterministic Keys via Web3Auth:** Same user across auth methods gets same keypair. No key backup complexity for users.

4. **TEE Republishing:** Elegant solution to IPNS record expiry. Users don't need devices online 24/7.

5. **Signed-Record Relay:** Backend relays pre-signed IPNS records. Never has signing keys.

6. **Graceful Key Rotation:** 4-week TEE epoch grace period prevents lockouts during rotation.

### Potential Concerns

| Concern | Severity | Mitigation in Specs |
|---------|----------|---------------------|
| IPNS resolution latency (~30s) | Medium | Polling interval is tunable; aggressive local caching |
| TEE compromise exposes IPNS keys | Medium | Keys exist in TEE memory only milliseconds; epoch rotation limits exposure; file content keys unaffected |
| Web3Auth dependency | Medium | Key export for disaster recovery; SIWE auth option |
| Pinata single provider | Low | CIDs are portable; can migrate to different pinning service |
| No offline write queue (web) | Low | Desktop client can queue; web shows clear offline state |

### Recommended Mitigations (Not in Specs)

1. **IPNS Caching Layer:** Consider Redis/Memcached for IPNS resolution caching on backend to reduce IPFS DHT queries.

2. **Circuit Breaker for IPFS:** Backend should have circuit breaker pattern for IPFS/Pinata failures to prevent cascading failures.

3. **Metrics/Alerting:** Monitor IPNS resolution latency, TEE republish success rate, key epoch migration progress.

---

## Build Order Recommendations

Based on component dependencies, here is the recommended build order:

### Phase Dependency Graph

```
Phase 1: Foundation
    |
    v
Phase 2: Auth & Keys ----+
    |                    |
    v                    |
Phase 3: Storage & Crypto |
    |                    |
    v                    v
Phase 4: IPNS & Sync <---+
    |
    v
Phase 5: TEE Integration
    |
    v
Phase 6: Desktop Client
    |
    v
Phase 7: Polish & Launch
```

### Detailed Build Order

#### Phase 1: Foundation (Week 1-2)
**Goal:** Project infrastructure, no feature code yet.

**Components:**
- NestJS backend scaffold with PostgreSQL
- React frontend scaffold
- CI/CD pipeline
- Development environment (local IPFS, Pinata sandbox)

**Dependencies:** None

**Rationale:** Infrastructure must exist before feature development.

---

#### Phase 2: Authentication (Week 3-4)
**Goal:** User can sign in and get tokens.

**Components:**
1. Web3Auth integration (frontend)
2. JWT verification (backend)
3. Token management (access/refresh)
4. User table, nonce table (PostgreSQL)

**Build Order:**
```
1. Backend: /auth/nonce, /auth/login, /auth/refresh endpoints
2. Frontend: Web3Auth modal integration
3. Frontend: Auth context, token storage
4. Integration: Full auth flow test
```

**Dependencies:** Phase 1 complete

**Rationale:** Auth is prerequisite for all protected operations. Web3Auth provides keypair needed for encryption.

---

#### Phase 3: Storage & Encryption (Week 5-6)
**Goal:** User can upload/download encrypted files.

**Components:**
1. Crypto module (AES-GCM, ECIES) - shared between web/desktop
2. Vault initialization (backend + frontend)
3. File upload/download endpoints
4. Pinata integration
5. Storage quota tracking

**Build Order:**
```
1. Crypto module: Unit tests for AES-GCM, ECIES
2. Backend: /my-vault, /my-vault/initialize, /vault/upload, /vault/unpin
3. Frontend: Upload zone, download handler
4. Integration: Full upload/download roundtrip
```

**Dependencies:** Phase 2 (need auth tokens and keypair)

**Rationale:** File encryption is core value proposition. Must work before IPNS complexity.

---

#### Phase 4: IPNS & Metadata (Week 7-9)
**Goal:** Folder structure persists via IPNS.

**Components:**
1. IPNS record signing (client-side Ed25519)
2. IPFS/IPNS relay endpoints
3. Folder metadata encryption/decryption
4. Folder tree traversal
5. Multi-device sync (polling)

**Build Order:**
```
1. Backend: /ipfs/add, /ipfs/cat, /ipns/resolve, /ipns/publish
2. Frontend: IPNS record signing (libsodium.js)
3. Frontend: Folder metadata structure
4. Frontend: Tree traversal algorithm
5. Frontend: 30s polling sync
6. Integration: Multi-device sync test
```

**Dependencies:** Phase 3 (need encrypted files to reference in metadata)

**Rationale:** This is the complex phase. IPNS is the novel part of architecture. Needs careful implementation.

**Research Flag:** IPNS resolution latency may need deeper investigation during implementation.

---

#### Phase 5: TEE Integration (Week 10)
**Goal:** IPNS records auto-republish via TEE.

**Components:**
1. TEE key state table
2. IPNS republish schedule table
3. TEE key sync cron
4. Republish cron
5. Client TEE key handling

**Build Order:**
```
1. Database: tee_key_state, ipns_republish_schedule tables
2. Backend: TEE key sync cron (hourly)
3. Backend: Republish cron (3-hourly)
4. Backend: Include teeKeys in login response
5. Frontend: Encrypt ipnsPrivateKey with teePublicKey on publish
6. Integration: End-to-end republish test
```

**Dependencies:** Phase 4 (need working IPNS publishing)

**Rationale:** TEE is enhancement to IPNS. Core IPNS must work first.

**Research Flag:** Phala Cloud API integration may need deeper research.

---

#### Phase 6: Desktop Client (Week 11-12)
**Goal:** FUSE mount at ~/CipherVault.

**Components:**
1. Tauri shell with auth
2. FUSE mount implementation
3. Background sync daemon
4. System tray integration
5. Keychain storage for refresh tokens

**Build Order:**
```
1. Tauri scaffold with shared crypto module
2. Auth flow (system browser OAuth)
3. FUSE mount (read-only first)
4. FUSE write operations
5. Background sync
6. System tray
```

**Dependencies:** Phase 4-5 (need working backend, IPNS, TEE)

**Rationale:** Desktop is additional client. Web must work first.

---

#### Phase 7: Polish & Launch (Week 12+)
**Goal:** Production-ready release.

**Components:**
1. Error handling refinement
2. Performance optimization
3. Security audit
4. Documentation
5. Deployment

**Dependencies:** All previous phases

---

## Component Implementation Notes

### Crypto Module (Shared)

**Critical:** This module is shared between web and desktop. Build it as a standalone package.

```typescript
// packages/crypto/src/index.ts
export interface CryptoModule {
  // AES-256-GCM
  encryptFile(plaintext: Uint8Array, key: Uint8Array): Promise<EncryptedFile>;
  decryptFile(encrypted: EncryptedFile, key: Uint8Array): Promise<Uint8Array>;

  // ECIES (secp256k1)
  wrapKey(key: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>;
  unwrapKey(wrapped: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;

  // Ed25519 (for IPNS)
  generateIpnsKeypair(): Promise<KeyPair>;
  signIpnsRecord(record: IpnsRecord, privateKey: Uint8Array): Promise<Uint8Array>;

  // TEE key encryption
  encryptForTee(ipnsKey: Uint8Array, teePublicKey: Uint8Array): Promise<Uint8Array>;
}
```

**Libraries:**
- Web Crypto API for AES-GCM
- `@noble/secp256k1` or `ethers.js` for ECIES
- `libsodium-wrappers` for Ed25519

### IPNS Signing

**Critical:** IPNS records must be signed client-side. Backend only relays.

```typescript
// Client-side IPNS signing
async function publishMetadataUpdate(
  metadata: FolderMetadata,
  folderKey: Uint8Array,
  ipnsPrivateKey: Uint8Array,
  teePublicKey: Uint8Array,
  teeEpoch: number
): Promise<void> {
  // 1. Encrypt metadata
  const encrypted = await crypto.encryptFile(
    new TextEncoder().encode(JSON.stringify(metadata)),
    folderKey
  );

  // 2. Upload to IPFS
  const { cid } = await api.post('/ipfs/add', encrypted);

  // 3. Sign IPNS record locally
  const record = buildIpnsRecord(cid, nextSequenceNumber);
  const signature = await crypto.signIpnsRecord(record, ipnsPrivateKey);

  // 4. Encrypt IPNS key for TEE republishing
  const encryptedIpnsKey = await crypto.encryptForTee(ipnsPrivateKey, teePublicKey);

  // 5. Relay signed record + encrypted key
  await api.post('/ipns/publish', {
    ipnsName: deriveIpnsName(ipnsPrivateKey),
    ipnsRecord: base64Encode(signature),
    sequenceNumber: nextSequenceNumber,
    encryptedIpnsPrivateKey: base64Encode(encryptedIpnsKey),
    keyEpoch: teeEpoch
  });
}
```

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Server-Side Key Generation

**What:** Generating encryption keys on the server.

**Why Bad:** Breaks zero-knowledge. Server could retain keys.

**Instead:** All key generation happens client-side with `crypto.getRandomValues()`.

### Anti-Pattern 2: Storing Private Keys

**What:** Writing privateKey to localStorage, sessionStorage, or IndexedDB.

**Why Bad:** Persistent storage is accessible to XSS attacks.

**Instead:** Keep privateKey in RAM only. Clear on logout. Use memory-only React state.

### Anti-Pattern 3: Server-Side IPNS Signing

**What:** Sending IPNS private key to server for signing.

**Why Bad:** Server would have ability to redirect user's metadata.

**Instead:** Sign IPNS records client-side. Server only relays pre-signed records.

### Anti-Pattern 4: Deduplication

**What:** Using same key for identical files to enable deduplication.

**Why Bad:** Leaks information about file contents (can detect same file across users).

**Instead:** Every file gets unique random key and IV. Same file = different CID.

### Anti-Pattern 5: Single Root IPNS

**What:** Having one IPNS name for entire vault.

**Why Bad:** Any folder change requires updating root. No modular sharing possible.

**Instead:** Per-folder IPNS names. Update only affected folder chain.

---

## Sources

**Industry Patterns (HIGH confidence):**
- [Cloudwards: Best Zero-Knowledge Cloud Services](https://www.cloudwards.net/best-zero-knowledge-cloud-services/)
- [Hivenet: Zero-Knowledge Encryption Guide](https://www.hivenet.com/post/zero-knowledge-encryption-the-ultimate-guide-to-unbreakable-data-security)
- [Bitwarden: Zero-Knowledge Encryption](https://bitwarden.com/resources/zero-knowledge-encryption/)
- [InfoQ: Application Level Encryption](https://www.infoq.com/articles/ale-software-architects/)

**IPFS/IPNS (HIGH confidence):**
- [IPFS Docs: IPNS](https://docs.ipfs.tech/concepts/ipns/)
- [IPFS Docs: Privacy and Encryption](https://docs.ipfs.tech/concepts/privacy-and-encryption/)
- [IPFS Specs: IPNS Record](https://specs.ipfs.tech/ipns/ipns-record/)

**TEE Architecture (MEDIUM confidence):**
- [a16z: TEE Primer](https://a16zcrypto.com/posts/article/trusted-execution-environments-tees-primer/)
- [Phala: What is TEE](https://phala.com/learn/What-Is-TEE)
- [Microsoft: Trusted Execution Environment](https://learn.microsoft.com/en-us/azure/confidential-computing/trusted-execution-environment)

**Web3Auth (HIGH confidence):**
- [Web3Auth: Technical Architecture](https://web3auth.io/docs/overview/key-management/technical-architecture/)
- [Web3Auth: MPC Architecture](https://web3auth.io/docs/infrastructure/mpc-architecture)
- [Web3Auth: SSS Architecture](https://web3auth.io/docs/infrastructure/sss-architecture)

**CipherBox Specifications (PRIMARY source):**
- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md`
- `00-Preliminary-R&D/Documentation/DATA_FLOWS.md`
- `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md`
- `00-Preliminary-R&D/Documentation/CLIENT_SPECIFICATION.md`

---

## Summary

CipherBox's architecture is well-designed and follows industry best practices for zero-knowledge encrypted storage. The key innovations (per-folder IPNS, TEE republishing) are sound solutions to real problems.

**Build Order Summary:**
1. Foundation (infra)
2. Auth (Web3Auth + tokens)
3. Storage & Crypto (file upload/download)
4. IPNS & Sync (folder metadata, polling)
5. TEE Integration (auto-republish)
6. Desktop Client (FUSE mount)
7. Polish & Launch

**Critical Path:** Auth -> Crypto -> IPNS -> TEE

The architecture supports the full-stack vertical build approach recommended in PROJECT.md, allowing end-to-end testing of features as they're built.
