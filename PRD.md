# CipherBox: Private 🔒 Your files. Your keys. Interplanetary.

**Product Name:** CipherBox
**Version:** v1.6
**Status:** Specification Document
**Last Updated:** January 14, 2026
**Author:** Michael Yankelev

***

## 1. Overview

### 1.1 Problem Statement

Existing cloud storage providers (Dropbox, Google Drive, OneDrive) offer centralized control of user data, creating risks:

- **Data breach**: Single company compromise exposes all user files.
- **Surveillance**: Servers can read plaintext or derive insights from metadata.
- **Censorship**: Centralized servers can be compelled to delete or restrict access.
- **Data loss**: Single point of failure; redundancy relies on company's infrastructure.

Users demanding privacy have limited options: self-hosted solutions (complex) or niche E2E-encrypted apps (poor UX, still centralized storage backend).

### 1.2 Vision

CipherBox delivers **private cloud storage with decentralized persistence**. Files are encrypted client-side and stored on IPFS (peer-to-peer, immutable, redundant). The server is stateless and zero-knowledge: it never holds plaintext data, keys, or key derivation material. Users control their encryption keys and filesystem hierarchy via IPNS (mutable pointers), while the server provides authentication and IPFS proxying. **All data is portable: users can export their vault's CIDs and decrypt with only their private key and root folder key.**

### 1.3 Product Goals

- **v1 Goals:**
    - Provide personal, private file storage alternative to Dropbox.
    - Seamless authentication (OAuth + Passkeys) without central key custody.
    - Web-based file browser + desktop macOS mount for transparent access.
    - Production-ready encryption (AES-256-GCM, ECDSA key management).
    - Data portability: users can export vault metadata and recover independently.
    - Backend IPFS proxying with transparent volume tracking.
- **Out of Scope for v1:**
    - Billing/payment integration (deferred to v1.1).
    - File/folder sharing (deferred to v3).
    - Collaborative editing (deferred to v4).
    - Mobile apps (deferred to v2).
    - Team/organization accounts (deferred to v3+).
    - Search/indexing (deferred to v2).

***

## 2. User Personas \& Use Cases

### 2.1 Personas

**Privacy-Conscious Developer** (Primary)

- Age: 28-45, works in tech/finance.
- Pain: Worried about centralized cloud storage hosting sensitive code, financial data, or personal files. Values decentralization and cryptographic guarantees.
- Usage: 20-500 GB, mix of documents, code repositories, financial records.
- Platform: macOS + web browser.
- Technical Comfort: High; understands IPFS concepts and encryption.

**Privacy Newbie**

- Age: 30-60, non-technical but privacy-aware.
- Pain: Heard about cloud breaches, wants "safer" storage for photos/documents. Intimidated by self-hosted solutions.
- Usage: 1-50 GB, mostly family photos and personal documents.
- Platform: Web browser primary.
- Technical Comfort: Low; needs simple UX.

**Freelancer/Remote Worker**

- Age: 25-40, geographic mobility.
- Pain: Needs to access files securely from multiple devices and locations. Concerned about local storage and theft.
- Usage: 50-200 GB, mix of client projects, invoices, contracts.
- Platform: macOS mount + web.
- Technical Comfort: Medium.


### 2.2 Key User Journeys

**Journey 1: Onboarding \& First Upload**

```
1. User visits web app.
2. Clicks "Sign Up."
3. Chooses auth method: Google, Apple, GitHub, or Passkey.
4. For Passkey: Browser prompts for biometric/PIN, completes WebAuthn challenge.
5. (Optional) Links additional OAuth providers to same account.
6. Client app derives ECDSA keypair from auth (Web3Auth for OAuth, HKDF from Passkey).
7. User sees vault initialized: empty root folder.
8. Drags file into web UI or opens macOS mount.
9. File encrypted locally, uploaded to CipherBox server, server pins to IPFS.
10. User sees file in tree view with decrypted name.
```

**Journey 2: Folder Organization**

```
1. User creates folder: "Documents/Work/Q1_2026".
2. Client generates IPNS entry for each folder level.
3. Encrypts folder names.
4. Updates parent IPNS entry to reference child.
5. Republishes parent IPNS with ECDSA signature via server.
6. File tree reflects new hierarchy.
```

**Journey 3: File Access via macOS Mount**

```
1. User opens Finder.
2. Navigates to ~/SecureVault/ (mounted FUSE volume).
3. Sees decrypted folder/file names.
4. Double-clicks PDF → opens in Preview (decrypted on-the-fly).
5. Edits document locally, saves → app re-encrypts and uploads new version via server.
6. IPNS entry updated with new CID.
```

**Journey 4: Vault Export \& Portability**

```
1. User navigates to Settings → Export Vault.
2. Client requests export from server (GET /user/export-vault).
3. Server returns JSON containing root IPNS name, all CIDs, encrypted root key.
4. User downloads export.json.
5. User can later decrypt independently using only private key + export file.
6. Complete independence from CipherBox infrastructure achieved.
```


***

## 3. Functional Requirements

### 3.1 Authentication Module

**Responsibility:** Derive cryptographic keypairs, manage user sessions, issue JWTs.

**Requirements:**

1. **Multi-Method Auth**
    - OAuth 2.0 aggregation: Google, Apple, GitHub (via Web3Auth).
    - Passkeys: WebAuthn/FIDO2 (browser native, device-bound, biometric/PIN).
    - Email/password: Optional fallback (hash password with Argon2, no plaintext storage).
2. **Keypair Derivation**
    - For OAuth: Web3Auth generates deterministic ECDSA keypair from JWT + user ID.
    - For Passkeys: HKDF derives deterministic ECDSA keypair from passkey credential ID + server salt.
    - **Requirement:** Same login method always produces same keypair (idempotent).
    - **Consequence:** All auth methods (OAuth, Passkey) → same user pubkey.
3. **Session Management**
    - Issue JWT on successful auth (expires in 24h).
    - JWT contains: user_id, pubkey_hash, linked_providers.
    - **Requirement:** No private keys in JWT or server storage.
4. **Linked Accounts**
    - User can link multiple OAuth providers to one account.
    - User can register multiple Passkeys (one per device).
    - Server stores: user_id → [oauth_provider_1, oauth_provider_2, ...], passkeys: [cred_id_1, cred_id_2, ...]
    - Each provider/passkey login yields **same ECDSA keypair** (deterministic derivation).

**Passkey Authentication Detail (WebAuthn):**

```
Passkey Registration:
1. User clicks "Register Passkey"
2. Browser prompts for device biometric or PIN
3. Client generates WebAuthn credential (stored on device, never leaves device)
4. Server receives: credential_id, public_key_cose, transports
5. Server stores: user_id, credential_id, public_key, device_name, created_at

Passkey Login:
1. User clicks "Sign in with Passkey"
2. Server provides WebAuthn challenge
3. Browser prompts for biometric/PIN
4. Client derives master key: masterKey = HKDF(credential_id, server_salt)
5. Client derives ECDSA privkey from masterKey
6. Client signs WebAuthn challenge with passkey
7. Server verifies signature against stored public_key
8. Server issues JWT with user_id and derived pubkey_hash

Result: No passwords transmitted, device-bound, phishing-resistant.
```

**Acceptance Criteria:**

- [ ] OAuth flow completes in <2s.
- [ ] Passkey registration completes in <3s.
- [ ] Passkey login completes in <3s (biometric prompt + verification).
- [ ] Keypair derivation is deterministic (same user = same pubkey across all auth methods).
- [ ] No private keys logged or stored server-side.
- [ ] No plaintext passwords stored (Argon2 hashing for email/password only).
- [ ] JWT validation passes for all auth methods.
- [ ] Passkey works on devices with WebAuthn support (macOS, iOS, Windows, Android).


### 3.2 Storage Module

**Responsibility:** Manage file uploads, downloads, encryption, IPNS entries, and folder hierarchy.

#### 3.2.1 Client-Side Encryption

**Flow:**

1. **File Upload**
    - User selects file.
    - Client generates random AES-256-GCM key (per file).
    - Client generates random IV (per file, 96-bit for GCM).
    - Client encrypts file blob: `ciphertext = AES-256-GCM(plaintext, key, IV)`.
    - Client encrypts symmetric key: `encryptedKey = ECIES(key, userPublicKey)`.
    - Client uploads ciphertext to CipherBox server (backend acts as IPFS client).
    - Server uploads to IPFS network (via Pinata, Infura, or direct go-ipfs node).
    - Server returns CID to client and tracks data volume in database for audit purposes.
    - **Note:** User can optionally retrieve all CIDs and independently pin via any IPFS service for complete portability.
    - Client updates folder IPNS entry with new file metadata (CID, encrypted key, encrypted name).
    - Client signs IPNS entry with ECDSA private key.
    - Client publishes signed IPNS entry to server (server publishes to IPFS on behalf of client).
2. **File Download**
    - User requests file (web UI or macOS mount).
    - Client resolves IPNS entry (or reads from cache).
    - Client fetches encrypted file from IPFS via CID.
    - Client decrypts symmetric key: `key = ECIES-Decrypt(encryptedKey, userPrivateKey)`.
    - Client decrypts file: `plaintext = AES-256-GCM-Decrypt(ciphertext, key, IV)`.
    - Client presents plaintext to user (or streams to FUSE mount).
3. **Folder Metadata Encryption**
    - Each folder is an IPNS entry containing metadata JSON.
    - Metadata includes: folder name (encrypted), children (folders + files), IPNS references, and **encrypted subfolder/file keys**.
    - **Each folder has a random symmetric key** (not derived from master key).
    - **Root folder key:** stored encrypted on server (via `/my-vault`), decrypted on login.
    - **Subfolder keys:** stored encrypted inside parent folder's metadata.
    - Client encrypts metadata JSON: `encryptedMetadata = AES-256-GCM(metadataJSON, folderKey, IV)`.
    - Client signs and publishes IPNS entry via server.

**Key Management:**

```typescript
// ============ LOGIN FLOW ============
// 1. User logs in (OAuth or Passkey), receives JWT
// 2. Client fetches vault data from unified endpoint
const vaultData = await api.get('/my-vault');
const { ipnsName, rootCid, rootKeyEncrypted } = vaultData;
const rootFolderKey = ECIES_Decrypt(rootKeyEncrypted, userPrivateKey);
// 3. Cache in memory for this session

// ============ TREE TRAVERSAL ============
// Root folder uses rootFolderKey
const rootMetadataJSON = AES256GCM_Decrypt(encryptedRootMetadata, rootFolderKey, iv);
const rootMetadata = JSON.parse(rootMetadataJSON);

// For each child in root:
for (const child of rootMetadata.children) {
  if (child.type === 'folder') {
    // Subfolder key is stored encrypted in parent metadata
    const subfolderKeyEncrypted = child.subfolderKeyEncrypted;
    const subfolderKey = ECIES_Decrypt(subfolderKeyEncrypted, userPrivateKey);
    
    // Decrypt subfolder's metadata with that subfolder's key
    const subfolderMetadataJSON = AES256GCM_Decrypt(
      encryptedSubfolderMetadata,
      subfolderKey,
      subfolder.iv
    );
    // Continue recursively...
  } else if (child.type === 'file') {
    // File key is also stored encrypted in parent metadata
    const fileKeyEncrypted = child.fileKeyEncrypted;
    const fileKey = ECIES_Decrypt(fileKeyEncrypted, userPrivateKey);
    // Use fileKey to decrypt file content from IPFS
  }
}
```

**Encryption Primitives:**

- **AES-256-GCM:** File content + metadata encryption. Libraries: `TweetNaCl.js`, `libsodium.js`, Web Crypto API.
- **ECIES (ECDH + AES):** Key wrapping for file and folder keys. Encrypted with user's ECDSA pubkey.
- **ECDSA (secp256k1):** Signing IPNS entries, derived from auth.
- **WebAuthn/FIDO2:** Device-bound authentication with Passkeys (standards-based, no dependency).


#### 3.2.2 Folder Hierarchy \& IPNS Structure

**IPNS Entry Format:**

Each IPNS entry (folder or root) is a JSON blob:

```json
{
  "version": "1.0",
  "type": "folder",
  "encryptedMetadata": "0xencrypted_json_blob...",
  "iv": "0x...",
  "signature": "0xsignature..."
}
```

**Decrypted metadata JSON:**

```json
{
  "children": [
    {
      "type": "folder",
      "nameEncrypted": "0xabcd...",
      "nameIv": "0x1234...",
      "ipnsName": "k51qzi5uqu5dlvj55qz...",
      "subfolderKeyEncrypted": "0xECIES(subfolderKey, user_pubkey)",
      "created": 1705268100,
      "modified": 1705268100
    },
    {
      "type": "file",
      "nameEncrypted": "0xdef0...",
      "nameIv": "0x5678...",
      "cid": "QmXxxx...",
      "fileKeyEncrypted": "0xECIES(fileKey, user_pubkey)",
      "fileIv": "0x1111...",
      "size": 2048576,
      "created": 1705268100,
      "modified": 1705268100
    }
  ],
  "metadata": {
    "created": 1705268100,
    "modified": 1705268100,
    "owner": "0x..."
  }
}
```

**Root IPNS Entry:**

- Server stores mapping: `user_id → IPNS_name` in `ipns_entries` table.
- Root folder key stored encrypted in `root_folder_keys` table.
- User's root folder resolves via this IPNS name.
- Contains all top-level folders/files.

**Subfolder IPNS Entry:**

- Referenced by parent folder as `ipnsName`.
- Same structure as root.
- Can be resolved independently (for caching/optimization).


#### 3.2.3 Client Traversal

**Pseudocode:**

```typescript
async function fetchFileTree(ipnsName: string, folderKey: Uint8Array) {
  // 1. Resolve IPNS to latest CID
  const cid = await ipfs.name.resolve(ipnsName);
  
  // 2. Fetch encrypted metadata from IPFS
  const wrapper = JSON.parse(await ipfs.cat(cid));
  
  // 3. Decrypt metadata using this folder's key
  const metadataJSON = AES256GCM_Decrypt(
    wrapper.encryptedMetadata,
    folderKey,
    wrapper.iv
  );
  const metadata = JSON.parse(metadataJSON);
  
  // 4. Process children
  const tree = { children: [] };
  
  for (const child of metadata.children) {
    if (child.type === 'folder') {
      // Decrypt folder name
      const folderName = AES256GCM_Decrypt(
        child.nameEncrypted,
        folderKey,
        child.nameIv
      );
      
      // Extract and decrypt subfolder's key
      const subfolderKey = ECIES_Decrypt(
        child.subfolderKeyEncrypted,
        userPrivateKey
      );
      
      // Recursively fetch subfolder
      const childTree = await fetchFileTree(child.ipnsName, subfolderKey);
      tree.children.push({
        type: 'folder',
        name: folderName,
        subtree: childTree
      });
    } else if (child.type === 'file') {
      // Decrypt file name
      const fileName = AES256GCM_Decrypt(
        child.nameEncrypted,
        folderKey,
        child.nameIv
      );
      
      // Extract and decrypt file key
      const fileKey = ECIES_Decrypt(
        child.fileKeyEncrypted,
        userPrivateKey
      );
      
      tree.children.push({
        type: 'file',
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

**Web UI Rendering:**

- Fetch vault data from unified endpoint: `GET /my-vault`.
- Response contains `ipnsName`, `rootCid`, and `rootKeyEncrypted`.
- Decrypt root folder key from server response.
- Call `fetchFileTree(rootIpnsName, rootFolderKey)`.
- Cache decrypted tree in memory with TTL.
- Display folder/file tree with decrypted names.

**macOS Mount:**

- On mount, fetch vault data from `GET /my-vault`.
- Extract `ipnsName` and decrypt `rootKeyEncrypted`.
- Call `fetchFileTree()` to build entire hierarchy.
- Cache in-memory.
- FUSE intercepts file reads: look up CID in cache, fetch from IPFS, decrypt with fileKey, return plaintext.


#### 3.2.4 Write Operations (Upload/Create)

**Create Folder:**

```
1. User names folder "NewFolder".
2. Client generates new random folder key (32 bytes).
3. Client generates new IPNS entry for this folder.
4. Client encrypts folder name: AES256GCM("NewFolder", parentFolderKey).
5. Client encrypts folder key: ECIES(newFolderKey, userPubkey).
6. Client creates empty metadata for new folder.
7. Client encrypts and publishes new IPNS entry via server.
8. Client updates parent folder's metadata:
   - Add new child entry with subfolderKeyEncrypted
9. Client republishes parent IPNS with updated signature via server.
```

**Upload File:**

```
1. User drags file into web UI / mount.
2. Client generates random file key.
3. Client encrypts file: AES256GCM(fileData, fileKey).
4. Client uploads encrypted blob to server.
5. Server uploads to IPFS, tracks bytes, returns CID.
6. Client encrypts file key: ECIES(fileKey, userPubkey).
7. Client encrypts file name: AES256GCM(fileName, parentFolderKey).
8. Client adds file entry to parent folder's metadata.
9. Client republishes parent folder's IPNS via server.
```

**Update File (New Version):**

```
1. User uploads same file again (or modifies local file and re-uploads).
2. Client generates new random file key.
3. Client encrypts and uploads to server → receives new CID.
4. Client updates file entry in folder metadata (same name, new CID, new encrypted key).
5. Client republishes folder IPNS via server.
```

**Rename File/Folder:**

```
1. User renames file from "old.pdf" to "new.pdf".
2. Client updates folder metadata: change encrypted name for that file.
3. Client republishes folder IPNS via server.
4. No change to file's CID or encryption.
```

**Move File:**

```
1. User moves file from "Documents" to "Documents/Work".
2. Client removes file entry from "Documents" IPNS, republishes via server.
3. Client adds file entry to "Documents/Work" IPNS, republishes via server.
4. File CID + encryption unchanged.
```

**Delete File:**

```
1. User deletes file.
2. Client removes file entry from parent folder's metadata.
3. Client republishes parent IPNS via server.
4. **Note:** File CID remains on IPFS unless unpinned (handled by server).
```

**Acceptance Criteria:**

- [ ] Upload <100MB in <5s (chunked if larger).
- [ ] Download <100MB in <5s.
- [ ] Create folder in <1s.
- [ ] Rename/move in <500ms.
- [ ] IPNS republish succeeds in <2s.
- [ ] No plaintext data leaked to IPFS or server.


### 3.3 Key Management Module

**Responsibility:** Derive, store, and protect user's encryption keys.

**Key Hierarchy:**

```
User's Auth (JWT from Web3Auth/OAuth or Passkey WebAuthn)
    ↓
User Master Key: 
  - For OAuth: derived by Web3Auth from auth seed
  - For Passkey: HKDF(passkey_credential_id, server_salt)
    ├─ Folder Metadata Keys: stored encrypted in metadata
    ├─ File Symmetric Keys: random per file, stored encrypted in metadata
    └─ ECDSA Private Key: derived for IPNS signing
```

**Storage:**

- **Private Keys (Secret):** In-memory only on client. Never written to disk unencrypted.
- **Master Key:** Derived at login from auth; held in memory.
- **Encrypted File/Folder Keys:** Stored in IPNS metadata (encrypted with user's ECDSA pubkey).

**Requirement:** User must authenticate each session; no "remember me" with stored keys.

**Recovery:**

- If user loses device, they re-authenticate → keys re-derived from auth.
- IPFS data is immutable; files are always accessible if encryption keys can be re-derived.
- User can export vault (CIDs + encrypted root key) and decrypt independently with their private key.

**Acceptance Criteria:**

- [ ] Keys not persisted to localStorage or disk.
- [ ] Keys cleared on logout or page reload.
- [ ] Auth re-derives same keypair deterministically.
- [ ] Vault export contains all necessary data for independent recovery.


### 3.4 Web UI Module

**Responsibility:** File browser, settings, authentication, vault export.

**Pages:**

1. **Auth Page** (`/login`)
    - Display OAuth buttons (Google, Apple, GitHub).
    - Display "Sign in with Passkey" button.
    - Display "Register Passkey" button for new users.
    - On success, redirect to `/vault`.
2. **Vault Page** (`/vault`)
    - File tree (folders + files) with decrypted names.
    - Breadcrumb navigation: `Root > Documents > Work`.
    - Drag-drop zone for upload.
    - Context menu on files/folders: download, rename, delete, move.
    - Storage usage indicator (optional).
    - Floating "+" button for create folder.
3. **Settings Page** (`/settings`)
    - Display user's linked OAuth providers.
    - "Link Account" button to add more OAuth providers.
    - Manage Passkeys: list registered passkeys, option to remove.
    - Display current pubkey (future use for sharing).
    - **"Export Vault" button:** generates JSON file containing:
        - Root IPNS name
        - All file/folder CIDs
        - Root folder key (encrypted with user's private key)
        - Instructions for independent recovery
    - Logout button.
4. **Download Modal**
    - File selection, download format options (zip for multiple files).

**Tech Stack:**

- **Framework:** React 18.
- **Language:** TypeScript.
- **Encryption:** `libsodium.js` or Web Crypto API.
- **IPFS Client:** `js-ipfs` or `kubo-rpc-client`.
- **UI Library:** Tailwind CSS or similar.
- **State:** React Context + Hooks (or Redux if complex).
- **WebAuthn:** SimpleWebAuthn or @webauthn/browser library.
- **OAuth:** Web3Auth SDK.

**Acceptance Criteria:**

- [ ] Load `/vault` within 2s (with tree cached).
- [ ] Upload file through drag-drop in <5s.
- [ ] Decrypted file names display correctly.
- [ ] Logout clears keys from memory.
- [ ] Passkey registration completes in <3s.
- [ ] Passkey login completes in <3s.
- [ ] Vault export generates valid JSON with all necessary data.


### 3.5 Desktop Module (macOS)

**Responsibility:** Mount encrypted vault as local folder, provide seamless file access.

**Features:**

1. **FUSE Mount**
    - Mount point: `~/SecureVault/` (or user-configurable).
    - Show decrypted folder/file names.
    - File reads: intercept, fetch from IPFS, decrypt, return plaintext.
    - File writes: encrypt, upload to server/IPFS, update IPNS.
    - Directory operations: create folder, rename, delete.
2. **Background Sync**
    - Poll IPNS periodically (e.g., every 30s) for changes.
    - If IPNS updated (e.g., via web UI), refresh local cache.
    - If local file changed, auto-encrypt and re-upload (with user confirmation if large).
3. **Authentication**
    - Support same auth methods as web (OAuth + Passkeys).
    - Passkey works on macOS natively (Touch ID, Face ID).
    - Session-based: user logs in, keys held in memory, cleared on logout.
4. **Settings**
    - Mount point configuration.
    - IPFS endpoint (default: public gateway, can use local node).
    - Sync interval.
    - Login/logout.

**Tech Stack:**

- **Framework:** Tauri (Rust + WebView) or Electron (Node.js + Chromium).
    - *Preference: Tauri for lighter footprint.*
- **FUSE Layer:**
    - macOS: Use `fuse-t` (userland FUSE for macOS) or `macFUSE`.
    - Rust bindings: `fuse-rs` or similar.
- **IPFS Client:** `js-ipfs` or Rust `ipfs` crate.
- **Encryption:** Same as web (libsodium.js or native Rust crypto).
- **WebAuthn:** SimpleWebAuthn for Passkey support.

**Acceptance Criteria:**

- [ ] Mount succeeds in <3s.
- [ ] File read latency <500ms for cached files.
- [ ] File read latency <2s for uncached (first fetch from IPFS).
- [ ] No memory leaks after 1 hour of usage.
- [ ] Sync detects IPNS changes within 30s.
- [ ] Passkey authentication works via native macOS biometric.

***

## 4. Non-Functional Requirements

### 4.1 Security

1. **Encryption Standards**
    - AES-256-GCM for symmetric encryption (NIST-approved, wide support).
    - ECDSA (secp256k1) for key derivation and signing.
    - HKDF-SHA256 for key derivation (for both OAuth master keys and Passkey-derived keys).
    - ECIES (ECDH + AES) for key wrapping.
    - **WebAuthn/FIDO2:** Standards-based, device-bound authentication (phishing-resistant).
2. **Zero-Knowledge Architecture**
    - Server never holds plaintext files or keys.
    - Server stores only: user_id, pubkey_hash (hashed pubkey), IPNS name, passkey credentials (public keys only).
    - No decryption keys on server.
    - Logs must exclude PII and ciphertexts.
3. **Authentication**
    - Web3Auth for OAuth integration (deterministic key derivation).
    - SimpleWebAuthn for Passkey/WebAuthn handling.
    - JWT tokens expire in 24h.
    - Passkey credential IDs never leave the device.
4. **Auditing**
    - Code review before launch (focus on crypto, key handling).
    - Optional: Third-party security audit (recommend for launch).
    - Continuous: Dependency scanning (Snyk, GitHub Dependabot).

### 4.2 Privacy

1. **Metadata Privacy**
    - Folder/file names encrypted.
    - Timestamps visible (acceptable for v1).
    - File sizes visible (inherent to IPFS CID size; acceptable).
    - Access patterns visible at network level (acceptable; mitigate in v2 if needed).
2. **No Tracking**
    - Web UI: no third-party analytics (Google Analytics, Mixpanel, etc.).
    - Optional: Self-hosted analytics (Plausible, Fathom) with opt-in.
    - Desktop app: no usage telemetry without explicit opt-in.
3. **IPFS Privacy**
    - Files pinned via external service (Pinata, etc.).
    - No guarantee that pinning service won't see encrypted file sizes / access patterns.
    - Acceptable for v1; document in privacy policy.
4. **WebAuthn Privacy**
    - Passkey credentials stored locally; never shared with server.
    - Server stores only public key (for verification).
    - Biometric data (fingerprint, face) stays on device; never transmitted.

### 4.3 Performance

1. **Upload/Download**
    - Single file <100MB: <5s (with chunking).
    - Folder listing (decrypt tree): <2s for 1000 files.
    - macOS mount: file read latency <500ms (cached), <2s (uncached).
2. **IPNS Resolution**
    - Resolve IPNS to CID: <2s typical (can be slow if peers offline).
    - Mitigation: cache aggressively (24h TTL).
3. **Scalability**
    - Support users with 100k+ files (via pagination or lazy loading in UI).
    - Support 1TB+ personal vaults (no hard limit; cost-based).

### 4.4 Reliability

1. **IPFS Redundancy**
    - Pin data on multiple IPFS nodes (3+ replicas via pinning service).
    - If one node fails, data remains accessible.
2. **Data Backup**
    - User's IPNS entry: pin on multiple pinning services (optional enhancement).
    - Metadata: versioned (all IPNS entries immutable).
3. **Error Handling**
    - If IPFS unavailable: cache locally, retry with exponential backoff.
    - If IPNS publish fails: queue locally, retry on next sync.
    - Graceful degradation when pinning service unavailable.

### 4.5 Compliance

1. **GDPR**
    - Right to deletion: user can delete files from vault. IPFS CIDs remain on network (immutable) but marked unpinned/archived.
    - Data processing: document that encryption keys are user-held; server has zero knowledge.
    - Privacy policy: detail what data is collected (email, IPNS name hash, passkey public keys).
    - **Data portability:** Users can export all encrypted data + CIDs; supports GDPR right to data portability.
2. **Data Residency**
    - Server can be hosted in EU (for GDPR compliance).
    - IPFS data is decentralized; no residency guarantee. Document in privacy policy.

### 4.6 Observability

1. **Logging**
    - Server logs: auth events (success/failure, no passwords), API calls (no PII), errors.
    - No plaintext data, ciphertexts, or key material in logs.
    - Log retention: 30 days.
2. **Metrics**
    - Successful uploads/downloads per day.
    - IPNS publish success rate.
    - Storage usage distribution.
    - Error rates (IPFS failures, publication failures).
3. **Monitoring**
    - Uptime monitoring: server health checks, IPFS gateway health.
    - Alert on: IPFS unavailability, IPNS publish failures, high error rates.

***

## 5. Technical Architecture

### 5.1 High-Level System Diagram

```
Web Browser / Desktop App
    ├─ Auth: WebAuthn (Passkey) + Web3Auth (OAuth)
    ├─ Encryption: Client-side (AES-256-GCM, ECIES, ECDSA)
    ├─ IPFS: Read-only via public gateway
    └─ API: NestJS Backend

    ↓ (encrypted data only)

NestJS Backend (Zero-Knowledge Server + IPFS Client)
    ├─ Auth: OAuth aggregation + Passkey verification
    ├─ User mgmt: profiles, linked accounts, passkeys
    ├─ Volume Tracking: server uploads to IPFS, tracks bytes
    ├─ IPNS registry: user_id → IPNS_name mapping
    ├─ Root key storage: encrypted per user
    └─ IPFS Client: uploads to pinning service, maintains audit trail

    ↓

IPFS Pinning Service (Pinata, Infura, or similar)
    ├─ Server (as client) uploads encrypted CIDs
    ├─ Server tracks pinned volume for audit purposes
    └─ Data: immutable, redundant, permanent

    ↓ (Future: Billing integration)

Payment Processor (Stripe)
```


### 5.2 Tech Stack

| Tier | Component | Technology | Notes |
| :-- | :-- | :-- | :-- |
| **Web Frontend** | File browser, auth, settings, export | React 18 + TypeScript | Vite for build, Tailwind CSS |
| **Web Crypto** | Encryption, key derivation | libsodium.js or Web Crypto API | AES-256-GCM, ECDSA, HKDF |
| **IPFS Client (Web)** | Read-only (fetch, resolve IPNS) | kubo-rpc-client or js-ipfs | JSON-RPC to public gateway |
| **WebAuthn** | Passkey authentication | SimpleWebAuthn or @webauthn/browser | FIDO2 standard |
| **OAuth** | Social login | Web3Auth SDK | Deterministic key derivation |
| **Desktop App** | macOS native mount | Tauri (Rust) + JavaScript | FUSE mount via fuse-t |
| **Backend Server** | Auth, volume tracking, IPFS proxy | Node.js + NestJS + TypeScript | RESTful API |
| **Database** | User data, volume audit trail | PostgreSQL | Structured queries, ACID |
| **Cache** | Session caching, IPNS lookups | Redis | In-memory fast lookups, TTL |
| **IPFS Client (Backend)** | Upload to pinning service | js-ipfs or Pinata SDK | Server acts as intermediary |

### 5.3 API Endpoints (NestJS Server)

**Authentication:**

```
POST /auth/login
  Body: { method: "google" | "github" | "apple", token: string }
  Response: { jwt: string, pubkey: string, user_id: string }

POST /auth/register-passkey
  Body: { displayName?: string, attestationObject, clientDataJSON }
  Response: { credential_id: "...", pubkey_hash: "..." }

GET /auth/passkey-challenge
  Response: { challenge: "base64_challenge", salt: "base64_salt" }

POST /auth/login-passkey
  Body: { credential_id: "...", assertionObject, clientDataJSON }
  Response: { jwt: string, pubkey: string, user_id: string }

POST /auth/logout
  Response: { success: true }

POST /auth/link-provider
  Body: { provider: "google" | "github" | "apple", token: string }
  Response: { success: true }
```

**User Management:**

```
GET /user/profile
  Response: { user_id, email, pubkey, oauth_providers: [], passkeys: [] }

PUT /user/profile
  Body: { display_name?: string, ... }
  Response: { success: true }

DELETE /user/passkey/{credential_id}
  Response: { success: true }

GET /user/export-vault
  Authorization: Bearer {jwt}
  Response: { 
    vaultExport: {
      rootIpnsName: "k51...",
      rootKeyEncrypted: "0xECIES(...)",
      allCids: ["QmXxxx...", "QmYyyy..."],
      createdAt: timestamp,
      instructions: "To recover: decrypt rootKeyEncrypted with your private key, resolve rootIpnsName, fetch all metadata..."
    }
  }
```

**Vault Management:**

```
GET /my-vault
  Authorization: Bearer {jwt}
  Response: { 
    ipnsName: "k51qzi5uqu5dlvj55...",
    rootCid: "QmXxxx...",
    rootKeyEncrypted: "0xECIES(...)"
  }

POST /vault/publish-ipns
  Authorization: Bearer {jwt}
  Body: { signedEntry: {...}, ipnsName: "k51..." }
  Response: { success: true, cid: "QmXxxx..." }
```

**File Upload:**

```
POST /vault/upload
  Authorization: Bearer {jwt}
  Body: { encryptedFile: File, filename: string }
  Response: { cid: "QmXxxx...", size: 1024 }
```


### 5.4 Database Schema

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  pubkey_hash VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE auth_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(50),
  provider_id VARCHAR(255),
  linked_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, provider, provider_id)
);

CREATE TABLE passkeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  credential_id BYTEA UNIQUE NOT NULL,
  public_key BYTEA NOT NULL,
  sign_count INTEGER DEFAULT 0,
  device_name VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP
);

CREATE TABLE ipns_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  ipns_name VARCHAR(255) UNIQUE NOT NULL,
  root_cid VARCHAR(255),
  last_published TIMESTAMP,
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE root_folder_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
  root_key_encrypted BYTEA NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE pinned_cids (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  cid VARCHAR(255) NOT NULL,
  size_bytes BIGINT,
  pinned_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, cid)
);

CREATE TABLE volume_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  upload_id VARCHAR(255) UNIQUE,
  bytes_uploaded BIGINT NOT NULL,
  cid VARCHAR(255) NOT NULL,
  filename VARCHAR(255),
  uploaded_at TIMESTAMP DEFAULT NOW()
);
```


***

## 6. Data Flow Examples

### 6.1 Upload File (End-to-End)

```
User Action: Drag file "budget.xlsx" into web UI under /Documents

1. Web Client (React)
   - User is logged in; has rootFolderKey in memory
   - Fetch "Documents" folder metadata from IPFS cache (or resolve IPNS)
   - Decrypt "Documents" metadata using its folderKey

2. Client Crypto
   - Generate random file key (32 bytes)
   - Generate random IV (12 bytes)
   - AES-256-GCM encrypt file: ciphertext
   - Encrypt file key: fileKeyEncrypted = ECIES(fileKey, userPubkey)
   - Encrypt file name: nameEncrypted = AES-256-GCM("budget.xlsx", documentsFolderKey)

3. Client → Server (Upload via proxy)
   - POST /vault/upload { encryptedFile, filename }
   - Server uploads encrypted blob to IPFS pinning service
   - Server inserts into volume_audit: user_id, bytes, cid, filename
   - Response: { cid: "QmBudget...", size: 2048576 }

4. Client → IPNS (Update Documents folder)
   - Decrypt metadata using documentsFolderKey
   - Add file entry: { nameEncrypted, cid, fileKeyEncrypted, size, timestamp }
   - Re-encrypt metadata
   - Sign with ECDSA private key
   - POST /vault/publish-ipns { signedEntry, ipnsName }
   - Server publishes to IPFS on behalf of client

5. Web UI
   - Refresh file tree
   - Display "budget.xlsx" under "Documents"
   - Show success notification

Time: ~3-5 seconds
```


### 6.2 Download File (End-to-End)

```
User Action: Click file "budget.xlsx" in web UI, click Download

1. Web Client
   - Fetch "Documents" IPNS (cached)
   - Decrypt metadata using documentsFolderKey
   - Find file entry: extract cid, fileKeyEncrypted

2. Client Crypto
   - Decrypt file key: fileKey = ECIES_Decrypt(fileKeyEncrypted, userPrivateKey)
   - Fetch encrypted file from IPFS via CID
   - Stream: plaintext = AES-256-GCM-Decrypt(ciphertext, fileKey, iv)

3. Browser Download
   - Create blob from plaintext
   - Trigger download: browser saves as "budget.xlsx"

4. Cleanup
   - Clear plaintext from memory
   - Optionally: cache metadata with TTL

Time: <2 seconds (if IPFS cache warm)
```


### 6.3 Vault Export \& Portability

```
User Action: User navigates to Settings → Export Vault

1. Client → Server
   - GET /user/export-vault
   - Server returns:
     {
       rootIpnsName: "k51qzi5uqu5dlvj55...",
       rootKeyEncrypted: "0xECIES(rootFolderKey, userPubkey)",
       allCids: ["QmFile1...", "QmFile2...", "QmFolder1..."],
       createdAt: 1705268100,
       instructions: "..."
     }

2. Client Crypto
   - Verify all CIDs are resolvable (optional pre-download check)
   - Generate JSON export file

3. Browser Download
   - User downloads export.json
   - File contains everything needed for independent recovery

4. Future Recovery (Independent or Different Provider)
   - User has: private_key, export.json
   - User decrypts root_key: rootFolderKey = ECIES_Decrypt(rootKeyEncrypted, private_key)
   - User resolves root IPNS via any IPFS gateway
   - User fetches all folder/file metadata from IPFS using CIDs
   - User decrypts all metadata using rootFolderKey (and extracted subfolderKeys)
   - User can now access all encrypted files without CipherBox service

Time: Export generation <1s; recovery completeness verified
```


### 6.4 Passkey Login \& Key Setup

```
User Action: User logs in with Passkey

1. Web Client → User selects "Sign in with Passkey"
   - Browser prompts for biometric (Touch ID, Face ID) or PIN
   - User completes authentication

2. Client Crypto
   - Fetch WebAuthn challenge from GET /auth/passkey-challenge
   - Browser completes WebAuthn assertion
   - Client receives: credential_id, signatureData, clientDataJSON
   - Client derives master key: masterKey = HKDF(credential_id, server_salt)
   - Client derives ECDSA privkey from masterKey

3. Client → Server
   - POST /auth/login-passkey { credential_id, assertionObject, clientDataJSON }
   - Server verifies WebAuthn signature against stored passkey public_key
   - Server issues JWT with user_id, pubkey_hash, providers

4. Client Stores Keys in Memory & Fetches Vault Data
   - Call GET /my-vault
   - Receive: { ipnsName, rootCid, rootKeyEncrypted }
   - Decrypt: rootFolderKey = ECIES_Decrypt(rootKeyEncrypted, userPrivateKey)
   - Store in memory for session

5. Client Fetches Tree
   - Resolve IPNS to CID
   - Fetch encrypted metadata from IPFS
   - Decrypt using rootFolderKey
   - Recursively decrypt tree
   - Build in-memory file tree

6. Web UI
   - Display file browser with decrypted names
   - User can upload, download, manage files

Time: ~2-3 seconds (depends on IPFS network)
```


***

## 7. Roadmap

### v1 (Q1 2026) - Core Foundation

- [x] OAuth authentication (Google, Apple, GitHub)
- [x] Passkey authentication (WebAuthn)
- [x] Client-side encryption (AES-256-GCM, ECIES, ECDSA)
- [x] Web UI file browser (upload, download, rename, delete, move)
- [x] macOS FUSE mount
- [x] Server as IPFS proxy with volume audit trail
- [x] Zero-knowledge server
- [x] Vault export for portability


### v1.1 (Q1 2026) - Billing Integration

- [ ] Stripe payment integration
- [ ] Usage tracking and billing dashboard
- [ ] Free tier + paid tier model
- [ ] Invoice generation and payment history


### v2 (Q2-Q3 2026) - Essential Features

- [ ] Mobile apps (iOS + Android)
- [ ] Search functionality (encrypted client-side search)
- [ ] Version history UI (restore, compare versions)
- [ ] Offline sync for desktop app


### v3 (Q4 2026 - Q1 2027) - Sharing Foundation

- [ ] Read-only folder sharing (shareable links with encryption)
- [ ] Team vaults (organization accounts, team billing)
- [ ] Granular access control per user


### v4+ (Future)

- [ ] Real-time collaborative editing
- [ ] Local IPFS node integration
- [ ] Encryption key rotation workflows

***

## 8. Appendix

### 8.1 Glossary

- **IPFS:** InterPlanetary File System. Peer-to-peer, content-addressed storage network.
- **IPNS:** IPFS Name System. Mutable pointers to immutable IPFS content (CIDs).
- **CID:** Content Identifier. Hash of file content, used as immutable reference.
- **FUSE:** Filesystem in Userspace. macOS/Linux kernel module for user-space filesystem implementation.
- **E2E Encryption:** End-to-End. Data encrypted on client; server never holds plaintext.
- **Zero-Knowledge:** Server has no knowledge of user data, even encrypted.
- **Portability:** Ability to export encrypted vault data + CIDs and recover independently without CipherBox.
- **Volume Audit:** Server records all uploaded bytes in database for transparency and future billing integration.


### 8.2 References

- Web3Auth: https://web3auth.io/
- SimpleWebAuthn: https://simplewebauthn.dev/
- WebAuthn Spec: https://www.w3.org/TR/webauthn-2/
- IPFS Docs: https://docs.ipfs.tech/
- NestJS: https://docs.nestjs.com/
- libsodium.js: https://github.com/jedisct1/libsodium.js
- kubo-rpc-client: https://github.com/ipfs/js-kubo-rpc-client
- Tauri: https://tauri.app/
- Pinata: https://www.pinata.cloud/
- Stripe API: https://stripe.com/docs/api

***

**Document Version:** 1.6
**Last Updated:** January 14, 2026
**Status:** Refinement of v1 spec

**Key Changes in v1.6**

- Renamed to CipherBox

**Key Changes in v1.5:**

- ✅ Consolidated `/vault/root-key` + `/vault/root-ipns` into single `GET /my-vault` endpoint
- ✅ Updated all code examples, flows, and API documentation to reflect unified endpoint
- ✅ Unified response structure contains: `ipnsName`, `rootCid`, and `rootKeyEncrypted`
- ✅ Reduces API calls by 50% during login and mount initialization

**Key v1 Focus:**

- Core functionality: auth, encryption, file management, portability
- Zero-knowledge architecture proven
- Server as IPFS proxy with audit trail
- Billing deferred to v1.1 (can be added separately)
- Sharing deferred to v3 (foundation ready for future planning)
<span style="display:none">[^1]</span>

<div align="center">⁂</div>

[^1]: image.jpg

