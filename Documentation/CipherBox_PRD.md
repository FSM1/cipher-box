# CipherBox - Product Requirements Document

**Product Name:** CipherBox  
**Status:** Specification Document  
**Created:** January 15, 2026  
**Last Updated:** January 15, 2026  

---

## Table of Contents

1. [Overview & Vision](#1-overview--vision)
2. [User Personas & Use Cases](#2-user-personas--use-cases)
3. [Functional Requirements](#3-functional-requirements)
4. [Non-Functional Requirements](#4-non-functional-requirements)
5. [Technical Architecture](#5-technical-architecture)
6. [Data Flows & Examples](#6-data-flows--examples)
7. [Roadmap](#7-roadmap)
8. [Appendix](#8-appendix)

---

## 1. Overview & Vision

### 1.1 Problem Statement

Existing cloud storage providers (Google Drive, Dropbox, OneDrive) offer centralized control of user data, creating fundamental risks:

- **Centralized Control:** Single company controls all user files and metadata.
- **Privacy Risk:** Servers hold plaintext or can derive insights from metadata and access patterns.
- **Data Hostage:** Users cannot easily migrate data or guarantee independence from provider.
- **Zero Transparency:** Users lack cryptographic guarantees about who can access their data.

Users demanding true privacy have limited options: self-hosted solutions (complex) or niche E2E-encrypted services (poor UX, still centralized infrastructure).

### 1.2 Vision

CipherBox delivers **privacy-first cloud storage with decentralized persistence and zero-knowledge guarantees**. 

Core pillars:
- **Client-side encryption:** Files encrypted before leaving device. Server never holds plaintext.
- **User-held keys:** Cryptographic keys generated and held client-side. Server has zero knowledge of key material.
- **Decentralized storage:** Files stored on IPFS (peer-to-peer, immutable, redundant network).
- **Transparent access:** Web UI and desktop mount hide IPFS complexity (no CIDs, no IPNS visible to user).
- **Data portability:** Users can export complete vault and decrypt independently with only their private key.

**For the cypherpunk:** CipherBox is for users who understand cryptography, value privacy guarantees over convenience, and want genuine decentralization without sacrificing UX.

### 1.3 Product Goals - v1.0

**Must-Have for v1.0:**
- ✓ Personal, private file storage replacing Dropbox/Google Drive
- ✓ Multi-method authentication (Email/Password, Passkeys, OAuth, Magic Link) without central key custody
- ✓ Web-based file browser (upload, download, organize)
- ✓ Desktop mount (macOS/Linux/Windows) for transparent file access
- ✓ Production-ready encryption (AES-256-GCM, ECDSA, secp256k1)
- ✓ Automatic multi-device sync via IPFS/IPNS
- ✓ Data portability (users can export vault and recover independently)
- ✓ Zero-knowledge server architecture (encryption keys never leave client)

**Out of Scope for v1.0:**
- ✗ Billing/Payment integration (deferred to v1.1)
- ✗ File versioning (deferred to v2)
- ✗ File/folder sharing (deferred to v2)
- ✗ Collaborative editing (deferred to v3)
- ✗ Mobile apps (deferred to v2)
- ✗ Team accounts (deferred to v3)
- ✗ Search/indexing (deferred to v2)

### 1.4 Success Criteria for v1.0

| Criterion | Target |
|-----------|--------|
| Auth latency | <3s (all methods) |
| File upload (<100MB) | <5s |
| File download (<100MB) | <5s |
| Multi-device sync latency | <30s (polling-based) |
| Vault initialization | <1s |
| Zero-knowledge guarantee | ✓ Server never holds plaintext or unencrypted keys |
| Data portability | ✓ Users can export and recover independently |
| Uptime | 99.5% |
| No private key leaks | ✓ Keys never logged, stored unencrypted, or transmitted to server |

### 1.5 Target User

**Primary persona:** Cypherpunks and crypto nerds who like novel applications of cryptography.

- Age: 25-50, technical background (often developers, security researchers, privacy advocates)
- Understanding: Grasp encryption concepts, IPFS fundamentals, key management
- Pain: Concerned about centralized cloud storage, want cryptographic guarantees
- Usage: 1GB-100GB+ personal files (code, financial records, research, personal documents)
- Platforms: macOS, Linux, Windows, web browser
- Motivation: Privacy, decentralization, independence from corporations

---

## 2. User Personas & Use Cases

### 2.1 Primary Persona: Cypherpunk Developer

**Profile:**
- Age: 28-45, works in tech/security/finance
- Technical comfort: High (understands cryptography, IPFS, distributed systems)
- Pain points: Worried about centralized cloud storage backdoors, surveillance, corporate data misuse
- Usage patterns: 10-500GB of sensitive code, research, financial data
- Platforms: Primarily macOS/Linux, secondary web access
- Values: Privacy guarantees, code transparency, decentralization

**Needs:**
- Cryptographically verifiable privacy (not just "trust us")
- Multi-device access without sync issues
- Self-hosting option for maximum control
- Clear understanding of what server can/cannot see

### 2.2 Key User Journeys

#### Journey 1: Signup & First Upload

```
1. User visits CipherBox.com
2. Chooses signup method: Email/Password, Passkey, Google, or Magic Link
3. For Email/Password:
   - Enters email + password
   - Backend verifies credentials, issues JWT
   - Client presents JWT to Torus Network
   - Torus derives ECDSA keypair, reconstructed in memory
4. For Passkey:
   - Browser prompts for biometric (Touch ID, Face ID) or PIN
   - Passkey signs challenge
   - Backend verifies, issues JWT
   - Same Torus derivation as above
5. For OAuth (Google/Apple/GitHub):
   - Standard OAuth flow
   - CipherBox backend issues JWT with subjectId
   - Client derives ECDSA keypair via Torus
6. Client queries: GET /my-vault
7. Server responds: 403 Vault Not Initialized
8. Client generates random 256-bit root folder key
9. Client encrypts root key: ECIES(rootKey, userPublicKey)
10. Client sends: POST /my-vault/initialize with encrypted key
11. Server stores in Vaults table, marks initialized
12. User sees empty vault, ready to upload
13. User drags file into web UI
14. File encrypted client-side, uploaded to IPFS, IPNS entry updated
15. User sees file in decrypted tree view
```

#### Journey 2: Multi-device File Access

```
1. User has uploaded files via web app on laptop
2. Opens CipherBox web UI on phone
3. Logs in (same email/password, same JWT → same Torus derivation → same ECDSA key)
4. GET /my-vault returns same vault data (same IPNS entry, same encrypted root key)
5. Client decrypts same root key (same private key → can decrypt)
6. Polls IPNS for folder metadata
7. Sees all files uploaded from laptop
8. Downloads file: fetches from IPFS, decrypts with file key from metadata
9. All without any server-side key sharing or sync infrastructure
```

#### Journey 3: Desktop Mount & Seamless Access

```
1. User installs CipherBox desktop app (macOS/Linux/Windows)
2. Logs in with same credentials (email/password, Passkey, or OAuth)
3. App derives same ECDSA keypair via Torus
4. FUSE mount created at ~/CipherVault
5. User opens Finder, navigates to ~/CipherVault
6. Sees folder tree with decrypted names (no CIDs, no IPFS internals visible)
7. Double-clicks PDF → opens in Preview
   - FUSE intercepts read
   - Fetches encrypted file from IPFS via CID
   - Decrypts with file key from metadata
   - Returns plaintext to application
8. User edits document, saves
   - FUSE intercepts write
   - Client re-encrypts
   - Uploads to IPFS (gets new CID)
   - Updates parent folder metadata, republishes IPNS
   - IPNS entry immediately updated
9. Other devices detect IPNS change in next poll cycle
   - See updated file, can access new version
```

#### Journey 4: Vault Export & Portability

```
1. User navigates to Settings → Export Vault
2. Client calls: GET /user/export-vault
3. Server returns JSON containing:
   - Root IPNS name (k51qzi5uqu5dlvj55...)
   - Encrypted root folder key (ECIES encrypted)
   - List of all CIDs in vault (collected during initialization)
   - Instructions for independent recovery
4. User downloads export.json
5. Weeks later, user decides to leave CipherBox
6. User has export.json + their private key
7. User can decrypt root key: rootKey = ECIES_Decrypt(rootKeyEncrypted, privateKey)
8. User resolves root IPNS via any IPFS gateway
9. User fetches all metadata from IPFS using CIDs in export
10. User decrypts all metadata using root key
11. User has complete access to entire vault without CipherBox service
12. Complete independence achieved, zero vendor lock-in
```

#### Journey 5: Account Linking (Email to Existing Google Account)

```
1. User signed up with Google (pubKey A generated via subjectId A)
2. Later, user wants to add email/password to same account
3. User navigates to Settings → Linked Accounts
4. Clicks "Add Email + Password"
5. Enters email address + new password
6. CipherBox backend verifies email (sends verification link)
7. User clicks link, confirms email ownership
8. Backend maps email credential to same subjectId (same as Google)
9. Backend stores in auth_providers table: (userId, "email", email_hash)
10. User can now login with either:
    - Google OAuth
    - Email + password
11. Both derive same ECDSA pubkey (because same subjectId)
12. Both can decrypt same vault (same root key, same IPNS entry)
13. Account seamlessly linked, vault access unchanged
```

---

## 3. Functional Requirements

### 3.1 Authentication Module

**Responsibility:** Support 4 auth methods, derive deterministic ECDSA keypairs, manage sessions.

#### 3.1.1 Multi-Method Authentication

**Supported Methods (v1):**
1. **Email + Password**
   - User enters email + password
   - Server verifies against Argon2 hash (password not stored plaintext)
   - Backend issues JWT with subjectId = userId + email

2. **Passkeys (WebAuthn/FIDO2)**
   - User registers passkey (biometric or PIN on device)
   - WebAuthn challenge signed by device
   - Server verifies challenge signature against stored passkey public key
   - Backend issues JWT with subjectId = userId

3. **OAuth 2.0 Aggregation (Google, Apple, GitHub)**
   - Standard OAuth flow via Web3Auth or direct integration
   - User consents to share profile
   - CipherBox backend receives OAuth token
   - Backend issues JWT with subjectId = userId

4. **Magic Link (Passwordless Email)**
   - User enters email
   - System sends link with unique token
   - User clicks link (token in URL)
   - Backend validates token, issues JWT with subjectId = userId

**Key Property:** All auth methods issue JWT with same **subjectId** for linked accounts.

#### 3.1.2 Key Derivation via Torus Network

**Process:**
```
1. Client receives JWT from CipherBox auth backend
   JWT contains: { subjectId, email (if applicable), provider, iat, exp, ... }

2. Client presents JWT to Torus Network (docs.web3auth.io)
   - Torus is external service (distributed verifier nodes)
   - Client sends: POST https://torus-nodes/api/v2/verify { JWT }

3. Torus verifiers independently verify JWT signature
   - Each verifier verifies JWT using CipherBox backend's public key
   - All verifiers agree JWT is valid

4. Torus verifiers share ECDSA private key material
   - Each verifier sends client its share of private key
   - Uses Shamir Secret Sharing (or evolved mechanism)
   - Requires honest majority of verifiers

5. Client reconstructs ECDSA private key in memory
   - Combines shares from multiple Torus nodes
   - Private key never exists on server or transmitted unencrypted
   - Private key held only in client RAM for this session

6. Client derives public key from private key
   - ECDSA pubkey = EC_point(private_key)
   - Publicly known from private key
```

**Determinism Guarantee:**
- Same subjectId → Torus derives same ECDSA private key
- Torus derivation is deterministic (verifiable by user)
- User can regenerate same keypair by re-authenticating with same method
- Cross-method linking: Same subjectId (from backend) → Same pubkey

**Acceptance Criteria:**
- [ ] Auth latency <3s (all methods combined with Torus derivation)
- [ ] No private keys transmitted over network
- [ ] No private keys stored on server
- [ ] No private keys written to logs
- [ ] Determinism verified (same subjectId → same keypair)

#### 3.1.3 Session Management

**JWT Token:**
- **Issued:** After auth credential verified, before Torus derivation
- **Contains:** subjectId, email (if available), providers (linked auth methods), iat, exp
- **Expiration:** 24 hours
- **Encoding:** Standard JWT (RS256 or HS256 signed by backend)
- **Storage:** In client memory (not localStorage, not disk)

**Session Lifecycle:**
```
1. User authenticates (email/pass, passkey, OAuth, or magic link)
2. Backend issues JWT
3. Client receives JWT
4. Client presents JWT to Torus
5. Torus derives keypair
6. Client fetches GET /my-vault (uses JWT as Authorization header)
7. Server validates JWT (checks expiration, signature)
8. Server returns vault data
9. Client decrypts root key with derived ECDSA private key
10. Session active: client has root key in memory, ready for file ops
11. On logout or 24h expiration: 
    - Session data cleared
    - Root key discarded from memory
    - Must re-authenticate to continue
```

**Logout Behavior:**
- Clear JWT from memory
- Clear root folder key from memory
- Clear ECDSA private key from memory
- Clear any cached metadata
- Redirect to login page

**Acceptance Criteria:**
- [ ] JWT expiration enforced (24h)
- [ ] No tokens persisted to disk/localStorage
- [ ] Logout clears all sensitive data
- [ ] Session validation on every protected API call

#### 3.1.4 Account Linking

**Manual Linking (User Initiates):**

```
Precondition: User has existing account (e.g., with Google)

1. User logs in with Google
2. User navigates to Settings → Linked Accounts
3. User clicks "Add Email + Password"
4. User enters email + desired password
5. System sends verification email to that address
6. User clicks verification link in email
7. User confirms they want to link email to existing account
8. Backend:
   - Verifies email ownership (token validation)
   - Hashes password with Argon2
   - Adds to auth_providers table: (userId, "email", email_hash)
   - Same userId, same subjectId → same vault access
9. User can now log in with either Google or email/password
10. Both methods → same ECDSA pubkey → same vault
```

**Auto-Detection (Backend Prevents Accidental Conflicts):**

```
Scenario: User signs up with Google as alice@gmail.com
Later: User tries to sign in with email alice@gmail.com + password

Backend logic:
1. Email+password login attempts
2. Backend checks auth_providers: is alice@gmail.com already linked to a user?
3. If YES: User already has account, use existing subjectId, issue JWT for login
4. If NO: User is new, create account, issue JWT

This prevents duplicate accounts from same email across different auth methods.
```

**Blocked Linking (Prevents Conflicts):**

```
Scenario: User A has account with Google (alice@gmail.com)
Later: User B tries to sign up with email bob@gmail.com

Backend logic:
1. Bob signs up with email bob@gmail.com
2. Bob adds password
3. Backend stores: (bobUserId, "email", bob_hashed_password)
4. Bob's vault linked to bobUserId

Later: Bob tries to add Google OAuth to his account
1. Bob clicks "Link Google"
2. Google OAuth returns bob@gmail.com
3. Backend checks auth_providers: is bob@gmail.com already used?
4. If YES for different user: Deny linking (email already used)
5. If NO or same user: Allow linking

This prevents email conflicts across accounts.
```

---

### 3.2 Storage & Encryption Module

**Responsibility:** Manage file encryption, IPFS storage, folder hierarchy, multi-device sync.

#### 3.2.1 Client-Side E2E Encryption

**File Upload Flow:**

```
1. User selects file (drag-drop or file picker)
2. Client generates random 256-bit AES key (per file)
3. Client generates random 96-bit IV (per file, for GCM)
4. Client encrypts file:
   ciphertext = AES-256-GCM(plaintext, key, IV)
   - Produces: ciphertext + 16-byte authentication tag

5. Client encrypts the file key (key wrapping):
   encryptedFileKey = ECIES(fileKey, userPublicKey)
   - ECIES: Elliptic Curve Integrated Encryption Scheme
   - Curve: secp256k1 (matches ECDSA)
   - Output: ephemeral_pubkey || nonce || ciphertext || auth_tag
   - Payload (ciphertext): the 256-bit file key

6. Client uploads encrypted file to backend:
   POST /vault/upload {
     encryptedFile: Blob,  // encrypted file content
     fileName: string,      // plaintext for server audit (optional)
     iv: hex_string         // IV for decryption
   }

7. Backend receives encrypted file
   - Never sees plaintext
   - Uploads to IPFS via Pinata/Infura
   - Receives CID (content-addressed hash)
   - Stores audit trail: (userId, CID, fileName, size, timestamp)

8. Backend returns to client:
   { cid: "QmXxxx...", size: 2048576 }

9. Client adds to folder metadata:
   {
     fileName_encrypted: AES-256-GCM(fileName, folderKey),
     iv_name: random_96_bits,
     cid: "QmXxxx",
     fileKey_encrypted: encryptedFileKey,
     fileSize: 2048576,
     created: timestamp,
     modified: timestamp
   }

10. Client encrypts folder metadata:
    metadataJSON = JSON.stringify(metadata)
    encryptedMetadata = AES-256-GCM(metadataJSON, folderKey)
    iv_metadata = random_96_bits

11. Client signs and publishes IPNS entry:
    ipnsEntry = {
      version: "1.0",
      encryptedMetadata: encryptedMetadata,
      iv: iv_metadata,
      signature: ECDSA_sign(hash(encryptedMetadata), privateKey)
    }
    Client calls: POST /vault/publish-ipns {
      ipnsName: "k51qzi5uqu5dlvj55...",
      signedEntry: ipnsEntry
    }

12. Server publishes to IPFS:
    - Receives signed entry from client
    - Publishes to IPNS (IPFS Name System)
    - Returns { success: true, cid: "QmYyy..." }

13. File now accessible to all devices with vault access
```

**File Download Flow:**

```
1. User requests file from web UI or FUSE mount
2. Client has folder metadata (from cache or fresh fetch)
3. Client extracts file entry:
   {
     cid: "QmXxxx",
     fileKey_encrypted: encryptedFileKey,
     iv: fileIV,
     fileName_encrypted: encryptedFileName
   }

4. Client decrypts file key:
   fileKey = ECIES_Decrypt(encryptedFileKey, userPrivateKey)

5. Client decrypts file name:
   fileName = AES-256-GCM_Decrypt(encryptedFileName, folderKey, iv_name)

6. Client fetches encrypted file from IPFS:
   GET /ipfs/QmXxxx → returns ciphertext + tag

7. Client decrypts file:
   plaintext = AES-256-GCM_Decrypt(ciphertext, fileKey, fileIV, tag)

8. Client presents plaintext to user
   - If web: download triggers browser download
   - If FUSE: mounted filesystem returns plaintext to application
```

**Encryption Primitives:**

| Algorithm | Purpose | Standard | Implementation |
|-----------|---------|----------|-----------------|
| AES-256-GCM | File content + metadata encryption | NIST | Web Crypto API or libsodium.js |
| ECIES (secp256k1) | Key wrapping (files, folders) | SEC 2 | libsodium.js or ethers.js |
| ECDSA (secp256k1) | IPNS entry signing, key derivation | NIST/SECG | Torus Network or libsodium.js |
| HKDF-SHA256 | Key derivation (backup, expansion) | RFC 5869 | Web Crypto API or libsodium.js |
| SHA-256 | Hashing (signatures, integrity) | NIST | Web Crypto API or libsodium.js |
| Argon2 | Password hashing | OWASP | argon2-browser or server-side |

**Acceptance Criteria:**
- [ ] File <100MB encrypts in <2s
- [ ] File <100MB uploads in <5s
- [ ] No plaintext file content transmitted to server
- [ ] No unencrypted file keys on server
- [ ] AES-256-GCM authentication verified (tampering detected)
- [ ] ECIES ciphertext not reversible without private key

---

#### 3.2.2 Folder Hierarchy & IPNS Structure

**Per-Folder IPNS Entries:**

```
Design: Each folder has its own IPNS entry (enables future per-folder sharing)

Root Folder:
- IPNS Name: k51qzi5uqu5dlvj55... (derived from userId)
- Published to IPFS by server
- Contains encrypted metadata of root's children

Subfolder (e.g., Documents):
- IPNS Name: k51qzi5uqu5dlvj66... (derived from parentIPNSName + folderName)
- Contains encrypted metadata of Documents's children
- Reference in parent: ipnsName field

Example Tree:
/
├── Documents (ipnsName: k51qzi5uqu5dlvj66...)
│   ├── Work
│   │   ├── resume.pdf
│   │   ├── budget.xlsx
│   └── Personal
│       └── photo.jpg
└── Archive
    └── 2025
        └── scan.pdf
```

**IPNS Entry Format:**

```json
{
  "version": "1.0",
  "encryptedMetadata": "0x...",  // AES-256-GCM encrypted
  "iv": "0x...",                  // 96-bit IV for GCM
  "signature": "0x..."            // ECDSA signature of encryptedMetadata
}
```

**Decrypted Metadata Structure:**

```json
{
  "children": [
    {
      "type": "folder",
      "nameEncrypted": "0xabcd...",
      "nameIv": "0x1234...",
      "ipnsName": "k51qzi5uqu5dlvj66...",
      "subfolderKeyEncrypted": "0xECIES(...)",
      "created": 1705268100,
      "modified": 1705268100
    },
    {
      "type": "file",
      "nameEncrypted": "0xdef0...",
      "nameIv": "0x5678...",
      "cid": "QmXxxx...",
      "fileKeyEncrypted": "0xECIES(...)",
      "fileIv": "0x1111...",
      "size": 2048576,
      "created": 1705268100,
      "modified": 1705268100
    }
  ],
  "metadata": {
    "created": 1705268100,
    "modified": 1705268100,
    "owner": "userId"
  }
}
```

**Key Management for Folders:**

```
Root Folder Key:
- Random 256-bit symmetric key
- Stored encrypted on server: ECIES(rootKey, userPublicKey)
- Retrieved on login from GET /my-vault
- Decrypted client-side with ECDSA private key

Subfolder Key:
- Random 256-bit symmetric key (per subfolder)
- Stored encrypted in parent metadata: ECIES(subfolderKey, userPublicKey)
- Extracted when traversing folder tree
- Decrypted client-side with ECDSA private key

File Key:
- Random 256-bit symmetric key (per file)
- Stored encrypted in folder metadata: ECIES(fileKey, userPublicKey)
- Extracted when downloading file
- Decrypted client-side with ECDSA private key

All keys encrypted with same user's public key (flat hierarchy for v1)
```

**Tree Traversal (Pseudocode):**

```typescript
async function fetchFileTree(ipnsName: string, folderKey: Uint8Array): Promise<FolderNode> {
  // 1. Resolve IPNS to latest CID
  const cid = await ipfs.name.resolve(ipnsName);
  
  // 2. Fetch signed entry from IPFS
  const signedEntryJSON = await ipfs.cat(cid);
  const signedEntry = JSON.parse(signedEntryJSON);
  
  // 3. Verify signature (optional: client-side cache validation)
  const messageHash = SHA256(signedEntry.encryptedMetadata);
  const isValid = ECDSA_verify(messageHash, signedEntry.signature, userPublicKey);
  if (!isValid) throw new Error("Metadata signature invalid");
  
  // 4. Decrypt metadata with folder key
  const metadataJSON = AES256GCM_Decrypt(
    signedEntry.encryptedMetadata,
    folderKey,
    signedEntry.iv
  );
  const metadata = JSON.parse(metadataJSON);
  
  // 5. Process children
  const tree = { children: [] };
  for (const child of metadata.children) {
    if (child.type === "folder") {
      // Decrypt folder name
      const folderName = AES256GCM_Decrypt(
        child.nameEncrypted,
        folderKey,
        child.nameIv
      );
      
      // Extract and decrypt subfolder key
      const subfolderKey = ECIES_Decrypt(
        child.subfolderKeyEncrypted,
        userPrivateKey
      );
      
      // Recursively fetch subfolder
      const childTree = await fetchFileTree(child.ipnsName, subfolderKey);
      tree.children.push({
        type: "folder",
        name: folderName,
        subtree: childTree
      });
    } else if (child.type === "file") {
      // Decrypt file name
      const fileName = AES256GCM_Decrypt(
        child.nameEncrypted,
        folderKey,
        child.nameIv
      );
      
      // Extract file key
      const fileKey = ECIES_Decrypt(
        child.fileKeyEncrypted,
        userPrivateKey
      );
      
      tree.children.push({
        type: "file",
        name: fileName,
        cid: child.cid,
        fileKey: fileKey,
        size: child.size
      });
    }
  }
  
  return tree;
}
```

**Acceptance Criteria:**
- [ ] Per-folder IPNS entries enable future per-folder sharing
- [ ] Tree traversal <2s for 1000 files
- [ ] Metadata signature verification implemented
- [ ] No plaintext folder/file names transmitted
- [ ] All keys properly nested and encrypted

---

#### 3.2.3 Write Operations

**Create Folder:**

```
1. User names folder "NewFolder" and confirms
2. Client generates new 256-bit symmetric key (folder key)
3. Client generates new IPNS entry name (or derives from parent + name)
4. Client encrypts folder name: AES256GCM(userName, parentFolderKey)
5. Client encrypts folder key: ECIES(folderKey, userPublicKey)
6. Client creates empty children array for new folder
7. Client creates empty metadata JSON for new folder
8. Client encrypts metadata: AES256GCM(metadataJSON, folderKey)
9. Client signs and publishes new IPNS entry: POST /vault/publish-ipns
10. Client updates parent folder metadata:
    - Add child entry with name_encrypted, ipnsName, subfolderKeyEncrypted
11. Client re-encrypts and publishes parent IPNS entry
```

**Upload File:**

```
1. User selects file (drag-drop)
2. Follow "File Upload Flow" from 3.2.1 steps 1-12
3. Client gets CID from server response
4. Client adds file entry to containing folder's metadata
5. Client re-encrypts and publishes folder IPNS entry
```

**Rename File/Folder:**

```
1. User renames "old.pdf" to "new.pdf"
2. Client updates folder metadata:
   - Find file entry with old encrypted name
   - Re-encrypt name: AES256GCM("new.pdf", folderKey)
   - Update nameEncrypted field
3. Client re-encrypts and publishes folder IPNS entry
4. File CID unchanged (just metadata updated)
```

**Move File/Folder:**

```
1. User moves "file.pdf" from Documents to Documents/Work
2. Client removes file entry from Documents metadata
3. Client republishes Documents IPNS entry (without file)
4. Client adds file entry to Documents/Work metadata
5. Client republishes Documents/Work IPNS entry (with file)
6. File CID unchanged (just moved in hierarchy)
```

**Delete File:**

```
1. User deletes "file.pdf" from Documents
2. Client removes file entry from Documents metadata
3. Client republishes Documents IPNS entry
4. File CID remains on IPFS (immutable), but no longer referenced
5. Note: v1 immediate delete (no recovery), v2+ will have soft-delete
```

**Acceptance Criteria:**
- [ ] Create folder: <1s
- [ ] Rename/move: <500ms
- [ ] IPNS publish: <2s
- [ ] Multiple operations: no conflicts
- [ ] No incomplete states (all-or-nothing semantics)

---

### 3.3 Key Management Module

**Responsibility:** Derive, protect, and lifecycle-manage encryption keys.

#### 3.3.1 Key Hierarchy

```
User Authentication (Email/Pass, Passkey, OAuth, or Magic Link)
    ↓
CipherBox Auth Backend verifies credentials
    ↓
Issues JWT with subjectId = userId
    ↓
Client presents JWT to Torus Network
    ↓
Torus derives ECDSA Keypair (secp256k1)
    │
    ├─ ECDSA Private Key (secp256k1)
    │  ├─ Held ONLY in client memory
    │  ├─ Never transmitted
    │  ├─ Never persisted to disk
    │  ├─ Used for:
    │  │  ├─ ECIES decryption (of folder/file keys)
    │  │  └─ IPNS entry signing
    │  └─ Discarded on logout
    │
    └─ ECDSA Public Key (secp256k1)
       ├─ Stored in Vaults table on server
       ├─ Used by server to:
       │  ├─ Validate IPNS signatures (optional)
       │  └─ Display in user settings
       └─ Used by client to:
          └─ Encrypt all data keys (ECIES)

Root Folder Key (AES-256)
    ├─ Generated on vault initialization
    ├─ Random 256 bits
    ├─ Stored encrypted on server: ECIES(rootKey, pubkey)
    ├─ Retrieved on login: GET /my-vault
    ├─ Decrypted client-side with ECDSA private key
    └─ Used to encrypt/decrypt root metadata

Subfolder Keys (AES-256, one per folder)
    ├─ Random 256 bits per folder
    ├─ Stored encrypted in parent metadata: ECIES(subfolderKey, pubkey)
    ├─ Decrypted client-side when traversing tree
    └─ Used to encrypt/decrypt subfolder metadata

File Keys (AES-256, one per file)
    ├─ Random 256 bits per file
    ├─ Stored encrypted in folder metadata: ECIES(fileKey, pubkey)
    ├─ Decrypted client-side when downloading
    └─ Used to encrypt/decrypt file content
```

#### 3.3.2 Key Storage & Protection

**Private Key (ECDSA):**
- **Storage:** Client RAM only (never written to disk)
- **Duration:** Session lifetime (24h or until logout)
- **Lifecycle:**
  - Generated: On user authentication via Torus
  - Used: For ECIES decryption and IPNS signing
  - Destroyed: On logout or session expiration

**Root Folder Key:**
- **Storage (at rest):** Server database, encrypted with ECIES(rootKey, pubkey)
- **Storage (in transit):** HTTPS only
- **Lifecycle:**
  - Generated: On vault initialization
  - Stored: Immediately after generation
  - Retrieved: On each login
  - Destroyed: On logout (cleared from memory)

**Subfolder/File Keys:**
- **Storage:** In IPFS (encrypted in folder metadata), never on server
- **Lifecycle:**
  - Generated: When folder/file created
  - Stored: In parent folder metadata (encrypted)
  - Retrieved: When traversing tree or accessing file
  - Destroyed: When folder/file deleted

**Acceptance Criteria:**
- [ ] Private key never written to disk unencrypted
- [ ] Private key never logged
- [ ] Private key cleared on logout
- [ ] Root key decryption succeeds with correct ECDSA private key
- [ ] Root key decryption fails with wrong private key

---

### 3.4 Web UI Module

**Responsibility:** Provide user interface for vault access, settings, data export.

#### 3.4.1 Pages & Components

**Login/Signup Page (`/auth`)**

```
- Display title "CipherBox"
- Tagline: "Privacy-first encrypted cloud storage"
- Auth method buttons (4 options):
  [ Sign up with Google ]
  [ Sign up with Apple  ]
  [ Sign up with GitHub ]
  [ Sign up with Email  ]
  [ Register Passkey    ]
  [ Sign in with Passkey]
  [ Magic Link          ]
- Existing user? "Sign in" link

For Email/Password:
- Email input field
- Password input field (toggle show/hide)
- "Sign up" or "Sign in" button
- Password strength indicator (on signup)

For Passkey:
- "Register Passkey" button (on signup)
- Browser prompts for biometric/PIN
- "Sign in with Passkey" button (on signin)
- Browser prompts for biometric/PIN

For OAuth & Magic Link:
- Click button → browser redirect → OAuth provider/email
- On return, auto-logged in
```

**Vault Page (`/vault`)**

```
Main Layout:
- Left sidebar: Folder tree navigation
- Main area: Current folder contents (files & subfolders)
- Top bar: Breadcrumb (Root > Documents > Work)

Folder Tree (Left):
- Expand/collapse subfolders
- Click folder → navigate and show contents
- Right-click → context menu (rename, delete, move)

Content Area (Main):
- List view: Name | Size | Modified | Action
- Decrypted file/folder names (no CIDs visible)
- Icon based on type (folder vs file types)
- Drag-drop zone for uploads

Actions:
- [ + Folder ] button → create new folder
- [ Upload ] button → file picker
- Drag-drop files → upload multiple
- Right-click file → download, rename, delete, move
- Multi-select → bulk delete, bulk move

Storage Indicator:
- "500 MiB / 500 MiB" (for v1 free tier)
- Progress bar showing usage
- "Upgrade" link (deferred to v1.1)

Sync Status:
- "Last synced: 2 minutes ago"
- Spinner if currently syncing
- Refresh button (force refresh)
```

**Settings Page (`/settings`)**

```
Sections:

1. Linked Accounts
   - Display current auth method (e.g., "Signed in via Google")
   - List all linked providers:
     * [ Unlink ] Google
     * [ Unlink ] Email + Password
   - "Add Email + Password" button (if not added)
   - "Add Passkey" button

2. Passkeys
   - List all registered passkeys:
     * MacBook Pro (Touch ID) - Registered Jan 14, 2026
     * [ Remove ]
   - "Register New Passkey" button

3. Account & Security
   - Display public key (for reference, future use)
   - Display userId (for reference)

4. Data & Privacy
   - [ Export Vault ] button
     - Triggers download of vault.json (CIDs + encrypted root key)
     - Includes recovery instructions

5. Danger Zone
   - [ Delete Account ] button
     - Confirm dialog: "Permanently delete your account and vault?"
     - Lists consequences (immediate deletion)
     - [ Cancel ] [ Delete ]

6. Session
   - [ Logout ] button
   - "Logout all other devices" (future, if multi-session supported)
```

**Export Modal**

```
Title: "Export Your Vault"
Message: "Download your vault data for independent recovery"

Content:
- "Your vault is encrypted and can be recovered independently"
- "Keep this file safe"
- File name: vault_export_YYYY-MM-DD.json

Example contents (encrypted, but format shown):
{
  "version": "1.0",
  "exportedAt": "2026-01-15T04:09:00Z",
  "rootIpnsName": "k51qzi5uqu5dlvj55...",
  "rootFolderKeyEncrypted": "0xECIES(...)",
  "allCids": ["QmXxxx...", "QmYyy...", "QmZzzz..."],
  "instructions": "To recover: decrypt rootFolderKeyEncrypted with your private key,
                   resolve rootIpnsName via any IPFS gateway, fetch all metadata from CIDs"
}

Buttons:
[ Download ] [ Cancel ]
```

#### 3.4.2 Technical Stack

- **Framework:** React 18 + TypeScript
- **Styling:** Tailwind CSS (or similar)
- **State Management:** React Context + Hooks (or Redux if complex)
- **Encryption:** Web Crypto API
- **IPFS Client:** kubo-rpc-client (JSON-RPC to IPFS gateway)
- **WebAuthn:** SimpleWebAuthn library
- **OAuth:** Web3Auth SDK or direct OAuth libraries
- **HTTP Client:** Axios or Fetch API

**Acceptance Criteria:**
- [ ] Load vault page within 2s (cached)
- [ ] First load within 5s (fetching metadata)
- [ ] Upload file through drag-drop in <5s
- [ ] Decrypted file names display correctly
- [ ] Logout clears all sensitive data
- [ ] Export generates valid JSON
- [ ] Responsive design (works on mobile, tablet, desktop)

---

### 3.5 Desktop Application (macOS/Linux/Windows)

**Responsibility:** Mount encrypted vault as local folder, background sync.

#### 3.5.1 FUSE Mount

**Features:**

```
Mount Point: ~/CipherVault/ (user-configurable)

Directory Operations:
- List files: shows decrypted names
- Create folder: encrypts name, publishes IPNS
- Create file: (via save from application)
- Rename: updates metadata, republishes
- Delete: removes entry, republishes
- Move: removes from source, adds to destination

File Operations:
- Read: FUSE intercepts, fetches from IPFS, decrypts, returns plaintext
- Write: FUSE intercepts, encrypts, uploads to IPFS, updates IPNS
- Execute: (forbidden for security)
- Symlink: (not supported)

Behavior:
- File reads are transparent (user doesn't know they're from IPFS)
- File writes trigger immediate re-encryption and upload
- Large files (>1GB) may show progress indicator
- Permissions: User-only (600 on unix, locked on Windows)
```

#### 3.5.2 Background Sync

**Polling Strategy:**

```
Desktop App:
- Poll interval: 10-30 seconds (configurable)
- On each poll:
  1. Fetch root IPNS entry (check for changes)
  2. If changed: Refresh metadata tree (only changed folders)
  3. Update FUSE mount display
  4. Notify user if new files appear

Desktop Sync:
- Traverse entire folder tree periodically
- Compare local hashes vs IPFS metadata
- Detect external changes (file modified in web UI)
- Update local metadata cache
```

#### 3.5.3 Authentication & Session

**Login Flow:**
```
1. App launches
2. If no session: show login window
3. User chooses auth method
4. App follows same auth flow as web (Torus derivation)
5. Session stored securely (OS keychain)
6. FUSE mount activates
7. App runs in system tray
```

**Logout & Cleanup:**
```
1. User clicks "Logout"
2. FUSE mount unmounted
3. Session cleared
4. Private key destroyed
5. App waits for re-authentication
```

#### 3.5.4 Technical Stack

**macOS:**
- Language: Swift or Electron (TBD)
- FUSE: macFUSE (via fuse-t for userland FUSE)
- Encryption: CommonCrypto or libsodium
- Keychain: SecureEnclav for key storage

**Linux:**
- Language: Rust (for performance) or Node.js (for code reuse)
- FUSE: FUSE2 or FUSE3
- Encryption: libsodium
- Keychain: Secret Service API or KWallet

**Windows:**
- Language: C# (.NET) or Electron
- FUSE: WinFSP (Windows FUSE alternative)
- Encryption: libsodium or CNG (Cryptography API: Next Generation)
- Keychain: Windows Credential Manager

**Acceptance Criteria:**
- [ ] FUSE mount succeeds in <3s
- [ ] File read latency <500ms (cached)
- [ ] File read latency <2s (uncached, IPFS fetch)
- [ ] File write triggers IPNS publish in <5s
- [ ] Multi-platform builds (macOS, Linux, Windows)
- [ ] No plaintext on disk

---

## 4. Non-Functional Requirements

### 4.1 Security

**Encryption Standards:**
- **AES-256-GCM:** Symmetric encryption (NIST-approved, authenticated)
- **ECDSA (secp256k1):** Asymmetric signing and key derivation
- **ECIES (secp256k1):** Key wrapping and asymmetric encryption
- **HKDF-SHA256:** Key derivation function
- **SHA-256:** Hashing and integrity
- **Argon2:** Password hashing (server-side only)
- **WebAuthn/FIDO2:** Phishing-resistant authentication

**Zero-Knowledge Architecture:**
- Server never holds plaintext files
- Server never holds unencrypted encryption keys
- Server stores only: userId, pubkey, encrypted root key, IPNS name
- No key derivation secrets on server
- Logs exclude PII and ciphertexts

**Acceptance Criteria:**
- [ ] Code audit (internal, pre-launch)
- [ ] Dependency scanning (automated, Snyk/Dependabot)
- [ ] No hardcoded secrets
- [ ] No unencrypted sensitive data in logs
- [ ] HTTPS enforced (all connections)
- [ ] CORS properly configured

### 4.2 Privacy

**Metadata Privacy:**
- Folder/file names: Encrypted
- Timestamps: Visible (acceptable for v1)
- File sizes: Visible via CID (inherent to IPFS)
- Access patterns: Visible at network level (acceptable)

**No Tracking:**
- No Google Analytics, Mixpanel, or similar
- No usage telemetry without explicit opt-in
- No cookies for tracking

**IPFS Privacy:**
- Files pinned via Pinata/Infura
- No guarantee about access pattern visibility to pinning service
- Document in privacy policy

**Data Portability:**
- Users can export vault (CIDs + encrypted root key)
- Users can decrypt independently without CipherBox
- No vendor lock-in

**Acceptance Criteria:**
- [ ] Privacy policy published and clear
- [ ] No third-party analytics
- [ ] Users can disable telemetry
- [ ] Export functionality works offline (for recovery)

### 4.3 Performance

**File Operations:**
- Upload <100MB: <5s
- Download <100MB: <5s
- Create folder: <1s
- Rename/move: <500ms
- Vault initialization: <1s

**IPNS Resolution:**
- Resolve IPNS to CID: <2s typical (with caching)
- Cache TTL: 1 hour (IPNS entries don't change frequently)

**Scalability:**
- Support users with 100k+ files (via pagination, lazy loading)
- Support vaults up to 100GB+ (no hard limit, quota-based)

**Acceptance Criteria:**
- [ ] Latency measured and monitored
- [ ] P95 latency <5s for file ops
- [ ] Cache hit rate >80% for repeated access

### 4.4 Reliability

**IPFS Redundancy:**
- Pin data on multiple IPFS nodes (via Pinata/Infura)
- If one node fails, data remains accessible
- Replication factor: 3+ (via pinning service)

**Data Backup:**
- Root IPNS: Pinned on multiple services (future enhancement)
- Metadata: Versioned (IPFS immutable, no corruption risk)
- Database: Daily backup (if server-side data exists)

**Error Handling:**
- IPFS unavailable: Cache locally, retry with exponential backoff
- IPNS publish fails: Queue locally, retry on next sync
- Network error: Graceful degradation, clear user messaging

**Acceptance Criteria:**
- [ ] Uptime 99.5%
- [ ] RTO <1 hour (recovery time objective)
- [ ] RPO <24 hours (recovery point objective)
- [ ] Error messages user-friendly

### 4.5 Observability

**Logging:**
- Auth events (success/failure, no passwords)
- API calls (endpoint, user_id, duration, no PII)
- Errors (stack traces, context, no secrets)
- Log retention: 30 days

**Metrics:**
- Successful uploads/downloads per day
- IPNS publish success rate
- File operation latency (P50, P95, P99)
- Storage usage distribution
- Error rates (IPFS failures, validation failures)

**Monitoring:**
- Server health checks (uptime, response time)
- IPFS gateway health
- Database performance
- Alert on: IPFS unavailability, high error rates, slow API

**Acceptance Criteria:**
- [ ] Metrics dashboards operational
- [ ] Alerts configured and tested
- [ ] No plaintext data in logs

---

## 5. Technical Architecture

### 5.1 System Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    End User Devices                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐ │
│  │   Web Browser    │  │  Desktop App     │  │   Mobile   │ │
│  │   (React 18)     │  │  (Tauri/Electron)│  │   (v2+)    │ │
│  │  FUSE Mount: N   │  │  FUSE Mount: YES │  │   FUSE: N  │ │
│  └────────┬─────────┘  └────────┬─────────┘  └────────────┘ │
│           │                     │                             │
└───────────┼─────────────────────┼─────────────────────────────┘
            │                     │
            └─────────────────────┘
                      │
           ┌──────────┴──────────┐
           │                     │
           ▼                     ▼
    ┌──────────────┐      ┌─────────────────┐
    │  Torus       │      │  CipherBox      │
    │  Network     │      │  Auth Backend   │
    │  (External)  │      │  (Node.js +     │
    │              │      │   NestJS)       │
    │ Key Share    │      │                 │
    │ Derivation   │      │ - JWT issuance  │
    └──────────────┘      │ - Credential    │
                          │   verification  │
                          │ - IPNS proxy    │
                          └────────┬────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
            ┌────────────────┐  ┌──────────┐  ┌─────────┐
            │  PostgreSQL    │  │ Pinata/  │  │ IPFS    │
            │  Database      │  │ Infura   │  │ Network │
            │                │  │ (Pinning │  │ (P2P    │
            │ - Users        │  │ Service) │  │ Storage)│
            │ - Vaults       │  │          │  │         │
            │ - Auth         │  │ Pins     │  │ Immut.  │
            │   Providers    │  │ encrypted│  │ Content │
            │ - Audit Trail  │  │ data     │  │         │
            └────────────────┘  └──────────┘  └─────────┘
```

### 5.2 Tech Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Frontend** | React 18 + TypeScript | Modern, popular, good for encryption UI |
| **Web Crypto** | Web Crypto API | Native browser, no external crypto dependency |
| **IPFS Client (Web)** | kubo-rpc-client | JSON-RPC to IPFS gateway, simple |
| **WebAuthn** | SimpleWebAuthn | Standards-based, FIDO2 compliance |
| **OAuth** | Web3Auth or direct | Torus integration for key derivation |
| **Desktop (macOS)** | Tauri or Electron + Swift | Light footprint, native FUSE support |
| **Desktop (Linux)** | Tauri or Electron + Rust | FUSE support, good performance |
| **Desktop (Windows)** | Electron or C# | WinFSP for FUSE equivalent |
| **Backend Server** | Node.js + NestJS + TypeScript | Type-safe, scalable, same language as frontend |
| **Database** | PostgreSQL | ACID, structured data, audit trail |
| **Cache** | Redis (optional) | Fast session lookups, future rate limiting |
| **IPFS Backend** | Pinata API or go-ipfs | Pinata for MVP simplicity, go-ipfs for control |
| **Deployment** | Docker + Kubernetes (future) | Containerization, horizontal scaling |

### 5.3 API Endpoints (NestJS Backend)

**Base URL:** `https://api.cipherbox.io`

#### Authentication Endpoints

```
POST /auth/register
  Body: { email, password } OR {} (for OAuth/Passkey/Magic Link redirects)
  Response: { jwt, userId, pubkey }

POST /auth/login
  Body: { email, password } OR { token } (OAuth/Magic Link)
  Response: { jwt, userId, pubkey }

GET /auth/passkey-challenge
  Response: { challenge, salt }

POST /auth/register-passkey
  Body: { displayName, attestationObject, clientDataJSON }
  Response: { credentialId, status }

POST /auth/login-passkey
  Body: { credentialId, assertionObject, clientDataJSON }
  Response: { jwt, userId, pubkey }

POST /auth/link-provider
  Authorization: Bearer JWT
  Body: { provider, token, email (if verifying) }
  Response: { status: "linked" }

POST /auth/logout
  Authorization: Bearer JWT
  Response: { status: "logged_out" }
```

#### Vault Management Endpoints

```
GET /my-vault
  Authorization: Bearer JWT
  Response: { vaultId, ownerPublicKey, rootFolderEncryptedEncryptionKey, initializedAt }

POST /my-vault/initialize
  Authorization: Bearer JWT
  Body: { publicKey, encryptedRootFolderKey }
  Response: { vaultId, status: "initialized" }

POST /vault/upload
  Authorization: Bearer JWT
  Body: FormData { encryptedFile: File, iv: string }
  Response: { cid, size, uploadedAt }

POST /vault/publish-ipns
  Authorization: Bearer JWT
  Body: { ipnsName, signedEntry: JSON }
  Response: { success, cid }
```

#### User & Settings Endpoints

```
GET /user/profile
  Authorization: Bearer JWT
  Response: { userId, email, pubkey, linkedProviders: [] }

PUT /user/profile
  Authorization: Bearer JWT
  Body: { displayName? }
  Response: { updated: true }

DELETE /user/passkey/:credentialId
  Authorization: Bearer JWT
  Response: { deleted: true }

GET /user/export-vault
  Authorization: Bearer JWT
  Response: { vaultExport: { rootIpnsName, rootKeyEncrypted, allCids, instructions } }

DELETE /user/account
  Authorization: Bearer JWT
  Body: { confirmDelete: true }
  Response: { deleted: true }
```

### 5.4 Database Schema

```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255),
  password_hash VARCHAR(255),  -- Argon2 hash (only if email/password enabled)
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Authentication providers (OAuth, Passkey, Email, Magic Link)
CREATE TABLE auth_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50),  -- "google", "apple", "github", "email", "passkey", "magic_link"
  provider_id VARCHAR(255),  -- External ID from provider
  provider_metadata JSONB,  -- Extra data (email for email provider, etc.)
  linked_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, provider, provider_id)
);

-- Passkey credentials (WebAuthn)
CREATE TABLE passkeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id BYTEA UNIQUE NOT NULL,
  public_key BYTEA NOT NULL,
  sign_count INTEGER DEFAULT 0,
  device_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP
);

-- User vaults
CREATE TABLE vaults (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  owner_pubkey BYTEA NOT NULL,  -- ECDSA public key
  root_folder_encrypted_key BYTEA NOT NULL,  -- ECIES(rootKey, pubkey)
  root_ipns_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  initialized_at TIMESTAMP,
  updated_at TIMESTAMP DEFAULT NOW()
);

-- IPNS entry references (for audit trail, optional)
CREATE TABLE ipns_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ipns_name VARCHAR(255) UNIQUE NOT NULL,
  latest_cid VARCHAR(255),
  last_published TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Volume audit trail
CREATE TABLE volume_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  upload_id VARCHAR(255) UNIQUE,
  bytes_uploaded BIGINT NOT NULL,
  cid VARCHAR(255) NOT NULL,
  uploaded_at TIMESTAMP DEFAULT NOW()
);

-- Pinned CIDs (track what's pinned where)
CREATE TABLE pinned_cids (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cid VARCHAR(255) NOT NULL,
  size_bytes BIGINT,
  pinned_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, cid)
);
```

### 5.5 Key Derivation Specification

#### Complete Key Derivation Formula

**Input:** User authentication (credentials + auth method)
**Output:** ECDSA keypair (secp256k1) guaranteed deterministic across all auth methods

**Step 1: Credential Verification (Backend)**

```
POST /auth/[register|login]
  Credential: email + password, WebAuthn challenge, OAuth token, or magic link token
  
Backend:
  1. Verify credential against stored data
  2. Determine userId (new user for signup, existing for login/linking)
  3. Generate subjectId = hash(userId + auth_method)  (consistent across all methods for same user)
  4. Create JWT payload:
     {
       "subjectId": "0x...",
       "userId": "uuid",
       "email": "user@example.com",
       "providers": ["google", "email"],
       "iat": current_timestamp,
       "exp": current_timestamp + 86400  // 24h
     }
  5. Sign JWT with backend private key: JWT = RS256_sign(payload, backend_privkey)
  6. Return JWT to client
```

**Step 2: Torus Key Derivation (Client)**

```
Client receives JWT from backend

1. Client presents JWT to Torus Network:
   POST https://torus.distributed-verifiers.io/api/v2/verify
   {
     "verifier": "cipherbox-backend",
     "verifierId": subjectId,
     "idToken": JWT
   }

2. Torus Network:
   a) Route request to multiple verifier nodes (e.g., 5 nodes)
   b) Each node independently verifies JWT:
      - Checks JWT signature (using CipherBox backend's public key)
      - Verifies JWT expiration
      - Verifies JWT payload matches expected format
   c) If >3 nodes verify successfully:
      - Each node computes its share of ECDSA private key:
        share_i = ECDSA_PrivateKey_Fragment(subjectId, node_i)
        (using Shamir Secret Sharing or similar)
      - Each node sends its share to client (encrypted)

3. Client reconstructs ECDSA private key:
   - Receives shares from Torus nodes (encrypted with client's ephemeral public key)
   - Decrypts all shares
   - Combines shares: ECDSA_privateKey = Combine_Shares(share_1, share_2, share_3)
   - Derives public key: ECDSA_publicKey = EC_multiply(ECDSA_privateKey, G)
   - Stores private key in RAM for session duration
```

**Determinism Guarantee:**

```
Theorem: Same user authentication method → Same ECDSA keypair

Proof:
- Same user + same auth method → same userId
- Same userId → same subjectId (deterministic hash)
- Same subjectId → Torus derives same ECDSA private key (Torus is deterministic)
- Same private key → same public key (ECDSA is deterministic)

Therefore: User logs in multiple times with same method → same keypair → can decrypt same vault

Cross-Method Guarantee:
- User signs up with Google → subjectId_google = hash(userId + "google")
- User later links email/password
- Backend maps both credentials to same userId
- Email login → subjectId_email = hash(userId + "email")  (DIFFERENT!)

Wait, that would give different keys. Issue in design!

Resolution (as specified by user):
- subjectId should be independent of auth method
- subjectId = hash(userId) only
- All auth methods for same user derive from same userId → same subjectId → same keypair

Formula (corrected):
  subjectId = hash(userId)  // Independent of auth method
  
  Then:
  - Google login → userId_google → subjectId = hash(userId_google) → key_A
  - Link email → userId_google (same!) → subjectId = hash(userId_google) → key_A
  ✓ Same keypair across methods
```

#### Test Vectors

**Test Vector 1: Email Signup + Login Consistency**

```
Scenario: User signs up with email, then logs in with same email

Signup:
  Email: alice@example.com
  Password: correcthorsebatterystaple
  Backend: hash(alice@example.com) → userId_1
           hash(userId_1) → subjectId_1
           JWT = sign({ subjectId_1, userId_1, ... })
  Torus: subjectId_1 → ECDSA_privkey_1 → ECDSA_pubkey_1
  Client: privkey_1 ∈ memory

Login (1 day later):
  Email: alice@example.com
  Password: correcthorsebatterystaple
  Backend: hash(alice@example.com) → userId_1 (same!)
           hash(userId_1) → subjectId_1 (same!)
           JWT = sign({ subjectId_1, userId_1, ... })
  Torus: subjectId_1 → ECDSA_privkey_1 (same!) → ECDSA_pubkey_1 (same!)
  Client: privkey_1 ∈ memory (matches signup)

Result: ✓ Same keypair, can decrypt vault from signup
```

**Test Vector 2: OAuth + Email Linking**

```
Scenario: User signs up with Google, then adds email/password

Signup with Google:
  OAuth: Google returns alice@example.com
  Backend: hash(alice@example.com) → userId_1
           hash(userId_1) → subjectId_1
           JWT = sign({ subjectId_1, userId_1, ... })
  Torus: subjectId_1 → ECDSA_privkey_1 → ECDSA_pubkey_1
  Client: privkey_1 ∈ memory, creates root_vault_key_1

Add Email:
  Backend: User confirms alice@example.com ownership
           Links email to existing userId_1
           auth_providers: (userId_1, "google", "123456"), (userId_1, "email", "alice@example.com")

Later login with email:
  Email: alice@example.com
  Password: mysecurepassword
  Backend: hash(alice@example.com) → userId_1 (same!)
           hash(userId_1) → subjectId_1 (same!)
           JWT = sign({ subjectId_1, userId_1, ... })
  Torus: subjectId_1 → ECDSA_privkey_1 (same!) → ECDSA_pubkey_1 (same!)
  Client: privkey_1 ∈ memory

GET /my-vault:
  Server returns: root_vault_key_1 (encrypted with ECDSA_pubkey_1)
  Client decrypts: root_vault_key = ECIES_Decrypt(encrypted, privkey_1)
  ✓ Same root key, access same vault

Result: ✓ Cross-method access works, same vault unlocked
```

**Test Vector 3: Passkey Signup + OAuth Linking**

```
Scenario: User registers with Passkey, later adds OAuth

Passkey Signup:
  Passkey: Device stores credential
  WebAuthn challenge signed
  Backend: Passkey verified → userId_2
           hash(userId_2) → subjectId_2
           JWT = sign({ subjectId_2, userId_2, ... })
  Torus: subjectId_2 → ECDSA_privkey_2 → ECDSA_pubkey_2
  Client: privkey_2 ∈ memory

Add Google OAuth:
  Backend: Google returns bob@example.com
           Links Google to existing userId_2
           auth_providers: (userId_2, "passkey", "cred_id"), (userId_2, "google", "999")

Later login with Google:
  OAuth: Google returns bob@example.com
  Backend: hash(bob@example.com) → but wait, Passkey signup used what?
  
Issue: Need to track email separately or use OAuth-provided email consistently
Solution: Backend tracks email on signup, uses it consistently

Corrected:
  Passkey Signup: Backend generates userId_2, email is optional for passkey
  Google Add: Backend uses OAuth email (bob@example.com), links to userId_2
  Google Login: OAuth email → hash → userId_2 → subjectId_2 ✓

Result: ✓ Cross-method with Passkey works
```

---

## 6. Data Flows & Examples

### 6.1 Complete Auth Flow (Email + Password)

```
User navigates to CipherBox.com/auth

1. Frontend:
   User enters email + password
   User clicks "Sign up" or "Sign in"

2. Frontend → Backend:
   POST /auth/register or /auth/login
   Body: { email: "alice@example.com", password: "secure123" }

3. Backend:
   If signup:
     a) Check if email already in auth_providers
     b) If exists: Return 409 Conflict "Email already registered"
     c) If not:
        - Hash password: password_hash = Argon2("secure123", salt)
        - Create user: users(id, email, password_hash)
        - userId = user.id
        - subjectId = hash(userId)
   If login:
     a) Find user by email
     b) Verify password: Argon2_verify(password, password_hash)
     c) If invalid: Return 401 Unauthorized
     d) userId = user.id
     e) subjectId = hash(userId)

4. Backend → Frontend:
   Response: {
     jwt: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
     userId: "uuid-here",
     pubkey: "0x..." (initial, will be replaced after Torus)
   }

5. Frontend (Client):
   Stores JWT in memory (not localStorage!)
   Presents JWT to Torus Network

6. Frontend → Torus:
   POST https://torus-nodes/api/v2/verify
   Body: {
     verifier: "cipherbox-backend",
     verifierId: subjectId,
     idToken: JWT
   }

7. Torus Network:
   Multiple nodes verify JWT in parallel
   Each node verifies JWT signature with CipherBox backend's public key
   If >2/3 honest, nodes return their key shares

8. Frontend:
   Receives key shares from Torus nodes
   Reconstructs ECDSA private key in RAM
   Derives public key: pubkey = EC_multiply(privkey, G)

9. Frontend:
   Calls GET /my-vault
   Header: Authorization: Bearer JWT

10. Backend:
    Verifies JWT (signature, expiration)
    Finds user's vault in Vaults table
    Returns:
    {
      vaultId: "uuid",
      ownerPublicKey: "0x...",
      rootFolderEncryptedEncryptionKey: "0x..." (encrypted with pubkey)
    }

11. Frontend:
    Stores JWT in memory
    Stores ECDSA private key in memory (session-only)
    Decrypts root folder key:
    rootFolderKey = ECIES_Decrypt(
      rootFolderEncryptedEncryptionKey,
      ECDSA_privateKey
    )

12. Frontend:
    User now authenticated
    Redirect to /vault page
    Display file browser (initially empty or cached)
```

### 6.2 Complete File Upload Flow

```
User drags file "budget.xlsx" into /Documents folder

1. Frontend:
   Detects drop event
   File: budget.xlsx (2 MB)

2. Client Encryption:
   Generate random 256-bit file key
   Generate random 96-bit IV
   Encrypt file:
     ciphertext = AES256GCM_Encrypt(file_data, file_key, IV)
     output: (ciphertext, 16-byte_auth_tag)

3. Client Key Wrapping:
   Encrypt file key with user's public key:
     encryptedFileKey = ECIES(file_key, user_pubkey)
     output: (ephemeral_pubkey, nonce, ciphertext, auth_tag)

4. Frontend → Backend:
   POST /vault/upload
   Header: Authorization: Bearer JWT
   Body: FormData {
     encryptedFile: Blob (ciphertext),
     iv: "0x...",
     fileName: "budget.xlsx"  (optional, for audit)
   }

5. Backend:
   Verifies JWT
   Validates file size <quota
   Uploads encrypted file to Pinata API:
     POST https://api.pinata.cloud/pinning/pinFileToIPFS
     File: encryptedFile (encrypted blob)
   Receives: { IpfsHash: "QmBudget123...", PinSize: 2097152 }

6. Backend → Database:
   Insert into volume_audit:
     (userId, bytes=2097152, cid="QmBudget123...", timestamp)

7. Backend → Frontend:
   Response: {
     cid: "QmBudget123...",
     size: 2097152,
     uploadedAt: "2026-01-15T04:09:00Z"
   }

8. Frontend:
   Fetches Documents folder metadata from cache (or IPFS)
   Decrypts metadata with Documents folder key
   Adds new file entry:
     {
       type: "file",
       nameEncrypted: AES256GCM_Encrypt("budget.xlsx", documentsfolderkey),
       nameIv: "0x...",
       cid: "QmBudget123...",
       fileKeyEncrypted: encryptedFileKey,
       fileIv: "0x...",
       size: 2097152,
       created: current_timestamp,
       modified: current_timestamp
     }

9. Frontend:
   Re-encrypts Documents metadata:
     metadataJSON = JSON.stringify(metadata_with_new_file)
     encryptedMetadata = AES256GCM_Encrypt(metadataJSON, documentsfolderkey)

10. Frontend:
    Signs IPNS entry:
      entry = {
        version: "1.0",
        encryptedMetadata: encryptedMetadata,
        iv: iv_metadata,
        signature: ECDSA_sign(SHA256(encryptedMetadata), private_key)
      }

11. Frontend → Backend:
    POST /vault/publish-ipns
    Body: {
      ipnsName: "/ipns/k51qzi5uqu5dlvj66...",
      signedEntry: entry
    }

12. Backend:
    Publishes to IPFS IPNS:
      ipfs name publish --key=user_key QmNewCID
    Returns: { success: true, cid: "QmNewCID" }

13. Frontend:
    Updates UI: Shows "budget.xlsx" in /Documents with decrypted name
    Removes upload progress indicator

14. Other Devices:
    Poll /vault/root_ipns periodically
    Detect IPNS change
    Fetch new metadata
    See new file in next sync cycle (~30 seconds)

Result: ✓ File encrypted end-to-end, stored on IPFS, accessible to all authorized devices
```

### 6.3 Complete File Download Flow

```
User clicks file "budget.xlsx" in web UI, clicks "Download"

1. Frontend:
   Has Documents folder metadata cached (or fetches fresh)
   Locates file entry:
     {
       cid: "QmBudget123...",
       fileKeyEncrypted: encryptedFileKey,
       fileIv: "0x...",
       nameEncrypted: "0xabcd..."
     }

2. Client Decryption (Key):
   Decrypt file key with user's private key:
     fileKey = ECIES_Decrypt(encryptedFileKey, user_private_key)

3. Client Decryption (Name):
   Decrypt file name with Documents folder key:
     fileName = AES256GCM_Decrypt(nameEncrypted, documents_folder_key, nameIv)

4. Frontend → IPFS:
   Fetch encrypted file from IPFS gateway:
     GET https://ipfs.io/ipfs/QmBudget123...
   Response: encrypted_blob (ciphertext + auth_tag)

5. Client Decryption (File):
   Decrypt file:
     plaintext = AES256GCM_Decrypt(ciphertext, fileKey, fileIv, auth_tag)
   Auth tag verified (tampering detected immediately)

6. Frontend:
   Create blob from plaintext:
     blob = new Blob([plaintext], { type: "application/vnd.ms-excel" })
   Trigger browser download:
     const url = URL.createObjectURL(blob)
     const link = document.createElement('a')
     link.href = url
     link.download = "budget.xlsx"
     link.click()

7. Browser:
   Downloads file as "budget.xlsx"
   User receives plaintext file locally

8. Cleanup:
   Frontend discards plaintext from memory
   Closes blob URL
   (Garbage collection eventually clears plaintext from RAM)

Result: ✓ File decrypted client-side, never transmitted plaintext to server, downloaded by user
```

### 6.4 Multi-Device Sync Flow

```
Scenario: User edits file on laptop, checks phone for updates

Timeline:
T0: Laptop uploads file.xlsx
T+5s: IPNS updated, new CID published
T+10s: Phone polls IPNS, detects change
T+15s: Phone displays updated file in browser

Detailed:

T0 - Laptop Upload:
  1. Laptop uploads file via /vault/upload
  2. Backend stores encrypted file, returns CID
  3. Laptop publishes new IPNS entry (Documents folder)
  4. IPNS entry points to new CID

T+5s:
  New IPNS entry visible on IPFS network (propagation delay)

T+10s - Phone Detection:
  1. Phone polling timer triggers (every 10s for demo, normally 30s)
  2. Phone calls: GET /my-vault (retrieves root IPNS name)
  3. Phone resolves root IPNS to current CID
  4. Phone fetches encrypted root metadata from IPFS
  5. Phone decrypts root metadata
  6. Phone detects Documents folder entry, resolves its IPNS
  7. Documents IPNS now points to NEW CID (different from cache)
  8. Phone fetches new Documents metadata
  9. Phone decrypts new metadata
  10. Parses children, finds new file.xlsx entry
  11. Phone UI updates: "file.xlsx" now visible

T+15s - User Views:
  Phone displays updated file tree with file.xlsx
  User can download file.xlsx (which fetches from IPFS)

Implementation (Phone Code):
```typescript
async function pollForChanges() {
  const vault = await api.get('/my-vault');  // Get root IPNS name
  
  // Compare cached root IPNS CID with current
  const currentCid = await ipfs.name.resolve(vault.rootIpnsName);
  if (currentCid === cachedRootCid) {
    console.log("No changes, skip traversal");
    return;
  }
  
  // Changes detected, fetch new metadata
  cachedRootCid = currentCid;
  const rootMetadata = await fetchAndDecryptMetadata(
    vault.rootIpnsName,
    rootFolderKey
  );
  
  // Update UI
  updateFileTree(rootMetadata);
}

setInterval(pollForChanges, 30000);  // Every 30 seconds
```

Result: ✓ Multi-device sync automatic, no manual refresh needed, polling-based
```

### 6.5 Vault Export & Recovery

```
Scenario: User wants to export vault for backup / independence

1. Frontend:
   User navigates to Settings → Export Vault
   Clicks [ Download ]

2. Frontend → Backend:
   GET /user/export-vault
   Header: Authorization: Bearer JWT

3. Backend:
   Gathers vault export data:
   - Root IPNS name: k51qzi5uqu5dlvj55...
   - Encrypted root folder key: (from Vaults table)
   - All CIDs in vault: (collect via metadata traversal or maintain master list)
   
   Response: {
     vaultExport: {
       version: "1.0",
       exportedAt: "2026-01-15T04:09:00Z",
       rootIpnsName: "k51qzi5uqu5dlvj55...",
       rootFolderKeyEncrypted: "0xECIES(...)",
       allCids: [
         "QmBudget123...",
         "QmPhoto456...",
         "QmReport789...",
         ...
       ],
       instructions: "To recover your vault independently:
                     1. Save this file securely
                     2. Store your ECDSA private key securely
                     3. On any device with IPFS:
                        - Decrypt rootFolderKeyEncrypted with your private key
                        - Resolve rootIpnsName to get latest CID
                        - Fetch metadata JSON from IPFS
                        - Decrypt metadata using decrypted root folder key
                        - Recursively decrypt all subfolders and files
                     4. You now have complete access without CipherBox service"
     }
   }

4. Frontend:
   Creates JSON file: vault_export_2026-01-15.json
   Triggers browser download

5. User (Offline):
   Weeks/months later, decides to leave CipherBox
   Has: export.json + ECDSA_private_key (in wallet / secure storage)

6. User (Recovery):
   On any device with IPFS CLI or Python client:
   
   a) Load export.json:
      rootIpnsName = export.rootIpnsName
      encryptedRootKey = export.rootFolderKeyEncrypted
      allCids = export.allCids

   b) Decrypt root key:
      rootFolderKey = ECIES_Decrypt(encryptedRootKey, user_private_key)

   c) Resolve IPNS:
      $ ipfs name resolve /ipns/k51qzi5uqu5dlvj55...
      /ipfs/QmRoot789

   d) Fetch and decrypt metadata:
      $ ipfs get QmRoot789
      (file: root_metadata_encrypted.json)
      
      rootMetadata = AES256GCM_Decrypt(
        encrypted_json,
        rootFolderKey,
        iv_from_export
      )

   e) Recursively traverse and decrypt all subfolders/files:
      For each file in metadata:
        fileKey = ECIES_Decrypt(fileKeyEncrypted, user_private_key)
        file = AES256GCM_Decrypt(ciphertext, fileKey, fileIv)
        Save plaintext file locally

7. Result:
   User now has:
   - Complete decrypted vault locally
   - All files accessible
   - Independent of CipherBox service
   - ✓ Zero vendor lock-in achieved

Key Property:
   Server has zero knowledge of private key
   → Export is useless without private key
   → User with private key has complete independence
```

---

## 7. Roadmap

### v1.0 (Q1 2026 - 3 Month MVP)

**Must-Have:**
- ✓ Multi-method auth (Email/Pass, Passkeys, OAuth, Magic Link)
- ✓ File upload/download with E2E encryption
- ✓ Folder organization (create, rename, move, delete)
- ✓ Web UI (React)
- ✓ Desktop mount (macOS) with FUSE
- ✓ Multi-device sync via IPNS polling
- ✓ Zero-knowledge server architecture
- ✓ Vault export for portability

**Out of Scope:**
- Billing/payment (deferred to v1.1)
- File versioning
- Folder/file sharing
- Mobile apps
- Search/indexing

---

### v1.1 (Q1-Q2 2026 - Polish & Payments)

- Billing integration (Stripe)
- Usage tracking dashboard
- Free tier / paid tier enforcement
- Invoice generation
- Performance optimization (caching, parallelization)
- Security audit completion
- Bug fixes from v1 user feedback

---

### v2.0 (Q2-Q3 2026 - Features)

- File versioning (restore old versions)
- Soft-delete with trash recovery
- Read-only folder sharing (shareable links with password)
- Search functionality (encrypted client-side search)
- Mobile apps (iOS / Android)
- Desktop apps for Linux & Windows
- Offline sync capability

---

### v3.0 (Q4 2026 - Collaboration)

- Collaborative folder editing (multiple users in same folder)
- Team accounts and management
- Per-folder access control (granular permissions)
- Team billing
- Audit logs for team admins

---

### v4.0+ (Future)

- Real-time collaborative editing (like Google Docs)
- Local IPFS node integration
- Key rotation workflows
- Advanced sharing controls (expiring links, bandwidth limits)

---

## 8. Appendix

### 8.1 Glossary

- **ECDSA:** Elliptic Curve Digital Signature Algorithm. Used for signing IPNS entries and key derivation.
- **ECIES:** Elliptic Curve Integrated Encryption Scheme. Used for key wrapping (asymmetric encryption of symmetric keys).
- **AES-256-GCM:** Advanced Encryption Standard (256-bit key) with Galois/Counter Mode (authenticated encryption).
- **IPFS:** InterPlanetary File System. Peer-to-peer, content-addressed distributed storage network.
- **IPNS:** IPFS Name System. Mutable pointers to immutable IPFS content (CIDs).
- **CID:** Content Identifier. Hash of file content, used as immutable reference on IPFS.
- **FUSE:** Filesystem in Userspace. Kernel module allowing user-space filesystem implementation.
- **E2E Encryption:** End-to-End. Data encrypted on client; server never holds plaintext.
- **Zero-Knowledge:** Server has no knowledge of user data or encryption keys (cryptographic guarantee).
- **Torus Network:** Distributed key derivation service. Provides deterministic ECDSA keypair from JWT.
- **WebAuthn/FIDO2:** Standards for phishing-resistant authentication via device-bound credentials (Passkeys).
- **JWT:** JSON Web Token. Signed credential for authentication and key derivation.

### 8.2 Security Considerations

**Threat Model:**

- **Server Compromise:** Attacker gains access to CipherBox database and code.
  - Impact: Attacker has encrypted root keys, user pubkeys, IPNS names.
  - Cannot decrypt: All data encrypted with user's private key (only in client memory).
  - Mitigation: Private keys never stored on server.

- **Network Interception:** Attacker intercepts HTTPS traffic.
  - Impact: Attacker can observe ciphertexts (but not keys or plaintext).
  - Cannot decrypt: Ciphertexts encrypted with user's public key (asymmetric).
  - Mitigation: HTTPS enforced, certificate pinning (future).

- **Client Compromise:** Attacker gains control of user's device.
  - Impact: Attacker can access private key in RAM during session.
  - Mitigation: Limited exposure during session, keys discarded on logout.
  - Defense-in-depth: Passkeys require biometric/PIN (attacker can't bypass).

- **Weak Password:** User chooses weak password for email/password auth.
  - Impact: Attacker can brute-force password, derive private key via Torus.
  - Mitigation: Torus derivation is deterministic but not password-weak. Server-side verification enforces strong passwords.
  - Future: Enforce minimum entropy (zxcvbn or similar).

**Best Practices:**

- Use strong, unique passwords (or Passkeys instead).
- Backup vault export and store securely.
- Don't share recovery key with anyone.
- Keep software updated (app + OS).
- Use device lock (biometric, PIN) for physical security.

### 8.3 Privacy Policy Framework

**CipherBox Privacy Approach:**

- **No Third-Party Analytics:** No Google Analytics, Mixpanel, or equivalent.
- **Minimal Data Collection:** Only email, public key, and IPNS name on server.
- **No Metadata Retention:** Access logs deleted after 30 days.
- **No Tracking Cookies:** User consent before any non-essential cookies.
- **Data Portability:** Users can export complete vault independently.
- **GDPR Compliance:** Users can request deletion; we delete server-side data immediately. IPFS data remains immutable.

### 8.4 FAQ

**Q: If the server is compromised, is my data safe?**

A: Yes. The server holds encrypted data only. Your encryption keys are never stored on the server; they're generated and held only in your device's memory. Even if an attacker compromises the server, they cannot decrypt your files without your private key.

**Q: How is my private key kept safe?**

A: Your private key is generated by the Torus Network and reconstructed only in your device's memory during your session. It's never transmitted, stored on disk, or logged. On logout or after 24h, the key is discarded.

**Q: Can CipherBox employees see my files?**

A: No. CipherBox never has your encryption keys or plaintext files. We cannot decrypt your data even if we wanted to. This is enforced by the cryptography, not just policy.

**Q: What if I forget my password?**

A: If you use email/password, you can request a password reset (we'll verify email ownership). Your vault remains encrypted; resetting password just lets you re-authenticate. You don't lose access to your data.

**Q: What if I lose my device with the only Passkey?**

A: You can log in using an alternate auth method (email/password or OAuth). Once logged in, you can register a new Passkey on another device. Your vault access is preserved.

**Q: Can I recover my vault if I lose my private key?**

A: If you don't have a backup (vault export), and you lose access to all your auth methods, your vault cannot be recovered. This is the security/convenience tradeoff of zero-knowledge architecture. We recommend exporting your vault regularly.

**Q: Why decentralized storage (IPFS) instead of centralized cloud (S3)?**

A: IPFS provides:
- **Redundancy:** Content pinned on multiple nodes globally; single node failure doesn't lose data.
- **No vendor lock-in:** Your data exists on IPFS independent of CipherBox.
- **Immutability:** Data integrity guaranteed by content addressing (CIDs).
- **Alignment with privacy values:** Decentralized, no company controls the network.

**Q: Will CipherBox be open source?**

A: Not planned for v1. Future versions may be auditable or partially open-sourced. For now, focus is on MVP quality and security audit completion.

**Q: How much does it cost?**

A: v1 has a free 500 MiB tier indefinitely. Pricing for larger storage deferred to v1.1. Future plans include freemium model + paid tiers.

---

## Document Approval

- **Author:** [User]
- **Reviewed:** [Architect]
- **Approved:** [Date]
- **Status:** APPROVED FOR DEVELOPMENT

---

**End of CipherBox PRD**

