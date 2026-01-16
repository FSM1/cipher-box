# CipherBox - Product Requirements Document

**Product Name:** CipherBox  
**Status:** Specification Document  
**Created:** January 14, 2026  
**Last Updated:** January 16, 2026  

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
- ✓ Multi-method authentication (Email/Password, OAuth, Magic Link, External Wallet) without central key custody
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
2. User is redirected to Web3Auth customized login screen
3. User chooses auth method: Email/Password, Google, Magic Link, or External Wallet
4. Web3Auth handles authentication:
   - For OAuth: Standard OAuth flow with selected provider
   - For Email/Password: Web3Auth verifies credentials
   - For External Wallet: User signs message with existing wallet (MetaMask, etc.)
   - OAuth token is provided to Web3Auth backend for verification
5. Web3Auth key derivation:
   - Each Web3Auth node retrieves its part of the user key
   - Key parts are sent to the client and reconstructed in memory
   - ECDSA keypair (secp256k1) is now available client-side
6. Client initiates auth with CipherBox backend:
   - Option A (JWT): Client calls POST /auth/login with Web3Auth ID token
   - Option B (SIWE): Client fetches nonce from GET /auth/nonce,
     signs message with private key, calls POST /auth/login with signature
7. CipherBox backend validates authentication:
   - For JWT: Verifies Web3Auth ID token signature via JWKS endpoint
   - For SIWE: Validates signature matches claimed pubkey and nonce
8. Backend issues CipherBox access token and refresh token
9. Client queries: GET /my-vault (using CipherBox access token)
10. Server responds: 403 Vault Not Initialized
11. Client generates random 256-bit root folder key
12. Client encrypts root key: ECIES(rootKey, userPublicKey)
13. Client sends: POST /my-vault/initialize with encrypted key
14. Server stores in Vaults table, marks initialized
15. User sees empty vault, ready to upload
16. User drags file into web UI
17. File encrypted client-side, uploaded to IPFS, IPNS entry updated
18. User sees file in decrypted tree view
```

#### Journey 2: Multi-device File Access

```
1. User has uploaded files via web app on laptop
2. Opens CipherBox web UI on phone
3. User is redirected to Web3Auth login screen
4. Logs in with any linked auth method (same Web3Auth group → same ECDSA key)
5. Web3Auth derives same keypair (group connections ensure same key across providers)
6. Client authenticates with CipherBox backend (JWT or SIWE flow)
7. GET /my-vault returns same vault data (same IPNS entry, same encrypted root key)
8. Client decrypts same root key (same private key → can decrypt)
9. Polls IPNS for folder metadata
10. Sees all files uploaded from laptop
11. Downloads file: fetches from IPFS, decrypts with file key from metadata
12. All without any server-side key sharing or sync infrastructure
```

#### Journey 3: Desktop Mount & Seamless Access

```
1. User installs CipherBox desktop app (macOS/Linux/Windows)
2. App opens Web3Auth login flow (embedded browser or system browser)
3. User logs in with any linked auth method
4. Web3Auth derives same ECDSA keypair (group connections ensure consistency)
5. App authenticates with CipherBox backend (JWT or SIWE flow)
6. FUSE mount created at ~/CipherVault
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
1. User signed up with Google (pubKey A generated via Web3Auth group)
2. Later, user wants to add email/password to same account
3. User navigates to Settings → Linked Accounts
4. Clicks "Add Email + Password"
5. User is redirected to Web3Auth account linking flow
6. Enters email address + new password
7. Web3Auth verifies email ownership and links to existing group
8. Group connection in Web3Auth now includes both Google and email/password
9. User can now login with either:
    - Google OAuth
    - Email + password
10. Both derive same ECDSA pubkey (Web3Auth group connections ensure same key)
11. Both can decrypt same vault (same root key, same IPNS entry)
12. Account seamlessly linked via Web3Auth, vault access unchanged

Note: Account aggregation is handled entirely by Web3Auth group connections.
CipherBox backend only stores the user's public key and validates identity
via Web3Auth ID tokens or SIWE signatures.
```

---

## 3. Functional Requirements

### 3.1 Authentication Module

**Responsibility:** Support 4 auth methods via Web3Auth, derive deterministic ECDSA keypairs, authenticate with CipherBox backend.

#### 3.1.1 Multi-Method Authentication

**Authentication Architecture:**

CipherBox uses a two-phase authentication approach:
1. **Phase 1 (Web3Auth):** User authenticates with Web3Auth to derive ECDSA keypair
2. **Phase 2 (CipherBox Backend):** User authenticates with CipherBox to obtain access/refresh tokens

**Phase 1: Web3Auth Authentication & Key Derivation**

**Supported Methods (v1) via Web3Auth:**
1. **Email + Password**
   - User enters email + password on Web3Auth login screen
   - Web3Auth verifies credentials
   - Key derivation proceeds

2. **OAuth 2.0 (Google, Apple, GitHub)**
   - Standard OAuth flow via Web3Auth
   - User consents to share profile with Web3Auth
   - Key derivation proceeds

3. **Magic Link (Passwordless Email)**
   - User enters email on Web3Auth login screen
   - Web3Auth sends magic link
   - User clicks link, key derivation proceeds

4. **External Wallet (Trustless Auth)**
   - User connects existing wallet (MetaMask, WalletConnect, etc.)
   - User signs authentication message with wallet private key
   - Web3Auth verifies signature and proceeds with key derivation
   - Fully trustless: no credentials stored, identity proven via signature

**Passkeys as MFA (Future):**
Web3Auth supports passkeys as a multi-factor authentication (MFA) method. In future versions, users will be able to add passkeys as an additional security layer on top of their primary authentication method.

**Web3Auth Group Connections:**
Multiple auth methods can be linked to the same identity using Web3Auth's group connections feature. This is configured in the Web3Auth dashboard and ensures:
- Same ECDSA keypair derived regardless of which linked method is used
- Account linking handled entirely by Web3Auth (no CipherBox backend logic needed)
- User can log in with Google, then later with email, and access same vault

Configuration example:
```typescript
const modalConfig = {
  connectors: {
    [WALLET_CONNECTORS.AUTH]: {
      loginMethods: {
        google: {
          authConnectionId: 'w3a-google',
          groupedAuthConnectionId: 'cipherbox-aggregate',  // Group ID
        },
        email_passwordless: {
          authConnectionId: 'w3a-email-passwordless',
          groupedAuthConnectionId: 'cipherbox-aggregate',  // Same group
        },
      },
    },
    [WALLET_CONNECTORS.WALLET_CONNECT_V2]: {
      // External wallet connections can also be grouped
    },
  },
};
```

**Phase 2: CipherBox Backend Authentication**

After Web3Auth key derivation, client authenticates with CipherBox backend using one of two methods:

**Option A: Web3Auth ID Token (JWT)**
- Client obtains ID token from Web3Auth via `getIdentityToken()`
- Client sends ID token to CipherBox backend
- Backend verifies token via Web3Auth JWKS endpoint (`https://api-auth.web3auth.io/jwks`)
- Backend extracts wallet public key from token claims
- Backend issues CipherBox access token and refresh token

**Option B: SIWE-like Signature Flow**
- Client requests nonce from CipherBox backend: `GET /auth/nonce`
- Client constructs message: `{pubkey, nonce, timestamp, domain}`
- Client signs message with ECDSA private key (derived from Web3Auth)
- Client sends signature + message to backend: `POST /auth/login`
- Backend verifies signature matches claimed pubkey
- Backend verifies nonce is valid and unused
- Backend issues CipherBox access token and refresh token

**Key Property:** Same ECDSA keypair is derived regardless of auth method (via Web3Auth group connections).

#### 3.1.2 Key Derivation via Web3Auth Network

**Process:**
```
1. User initiates login on CipherBox client
   Client redirects to Web3Auth customized login screen

2. User selects auth method and completes authentication
   - OAuth providers: User completes OAuth flow, token sent to Web3Auth
   - Email/Password: Web3Auth verifies credentials
   - External Wallet: User signs message with wallet, signature verified
   - Magic Link: User clicks email link

3. Web3Auth backend receives and verifies OAuth token / credentials
   - Each Web3Auth node independently verifies the authentication
   - Uses configured group connection to determine key derivation

4. Web3Auth nodes share ECDSA private key material
   - Each node retrieves its share of the user key
   - Uses Shamir Secret Sharing (threshold cryptography)
   - Requires honest majority of nodes

5. Client reconstructs ECDSA private key in memory
   - Key parts sent to client and combined
   - Private key never exists on Web3Auth servers in complete form
   - Private key held only in client RAM for this session

6. Client derives public key from private key
   - ECDSA pubkey = EC_point(private_key)
   - Curve: secp256k1
```

**Group Connections & Determinism Guarantee:**
- Web3Auth group connections ensure same keypair across linked auth methods
- All auth methods in the same group derive identical ECDSA keypair
- User can log in with Google, later with email, and get same key
- Account linking is configured in Web3Auth dashboard (not CipherBox backend)
- Determinism verified: same user + any grouped auth method → same keypair

**Web3Auth ID Token:**
After key derivation, client can obtain an ID token from Web3Auth:
```typescript
const { getIdentityToken } = useIdentityToken();
const idToken = await getIdentityToken();
// Token contains: iss, aud, sub, wallets[{public_key, curve, type}], iat, exp
```

This ID token can be used to authenticate with the CipherBox backend.

**Acceptance Criteria:**
- [ ] Auth latency <3s (Web3Auth login + key derivation)
- [ ] No private keys transmitted over network in complete form
- [ ] No private keys stored on server
- [ ] No private keys written to logs
- [ ] Determinism verified (group connections → same keypair across methods)

#### 3.1.3 Session Management

**Token Architecture:**

CipherBox uses two separate token systems:

1. **Web3Auth ID Token** (for CipherBox backend authentication)
   - **Issued:** By Web3Auth after successful login
   - **Contains:** iss, aud, sub, wallets (with public keys), iat, exp
   - **Purpose:** Authenticate user identity to CipherBox backend
   - **Verification:** Via Web3Auth JWKS endpoint

2. **CipherBox Access/Refresh Tokens** (for API access)
   - **Access Token:**
     - **Issued:** After CipherBox backend validates identity (JWT or SIWE)
     - **Contains:** userId, pubkey, iat, exp
     - **Expiration:** 15 minutes (short-lived for security)
     - **Storage:** In client memory only
   - **Refresh Token:**
     - **Issued:** Alongside access token
     - **Expiration:** 7 days
     - **Storage:** Secure HTTP-only cookie or encrypted local storage
     - **Purpose:** Obtain new access tokens without re-authentication

**Session Lifecycle:**
```
1. User initiates login, redirected to Web3Auth
2. User completes auth (OAuth, email/pass, magic link, or external wallet)
3. Web3Auth derives ECDSA keypair, reconstructed in client memory
4. Client authenticates with CipherBox backend:
   Option A: POST /auth/login with Web3Auth ID token
   Option B: GET /auth/nonce, then POST /auth/login with SIWE signature
5. CipherBox backend validates identity
6. Backend issues access token (15min) + refresh token (7 days)
7. Client fetches GET /my-vault (uses access token as Authorization header)
8. Server validates access token (checks expiration, signature)
9. Server returns vault data
10. Client decrypts root key with derived ECDSA private key
11. Session active: client has root key in memory, ready for file ops
12. On access token expiration:
    - Client uses refresh token to obtain new access token
    - No re-authentication with Web3Auth needed
13. On logout or refresh token expiration:
    - All tokens cleared
    - Root key and ECDSA private key discarded from memory
    - Must re-authenticate via Web3Auth to continue
```

**Logout Behavior:**
- Clear CipherBox access and refresh tokens
- Clear root folder key from memory
- Clear ECDSA private key from memory
- Clear any cached metadata
- Invalidate refresh token on server (if stored)
- Redirect to login page

**Acceptance Criteria:**
- [ ] Access token expiration enforced (15 min)
- [ ] Refresh token expiration enforced (7 days)
- [ ] No access tokens persisted to disk/localStorage
- [ ] Logout clears all sensitive data
- [ ] Refresh token rotation implemented (new refresh token on each use)
- [ ] Session validation on every protected API call

#### 3.1.4 Account Linking (via Web3Auth Group Connections)

**Architecture Change:**

Account linking is now handled entirely by Web3Auth's group connections feature. CipherBox backend no longer maintains auth provider mappings or handles account aggregation logic.

**How Group Connections Work:**

```
1. Developer configures group connections in Web3Auth dashboard
2. Multiple auth methods (Google, email, external wallet) are added to a "group"
3. All auth methods in the same group derive the same ECDSA keypair
4. Web3Auth handles the identity aggregation automatically
```

**Manual Linking (User Initiates via Web3Auth):**

```
Precondition: User has existing account (e.g., signed up with Google)

1. User logs in with Google via Web3Auth
2. User navigates to Settings → Linked Accounts in CipherBox
3. User clicks "Add Email + Password"
4. CipherBox redirects to Web3Auth account linking flow
5. User enters email + desired password in Web3Auth UI
6. Web3Auth verifies email ownership (sends verification email)
7. User clicks verification link
8. Web3Auth links email credential to existing group identity
9. User can now log in with either:
   - Google OAuth → same keypair
   - Email + password → same keypair
10. Both methods → same ECDSA pubkey (Web3Auth ensures this)
11. Both methods → same vault access

Note: CipherBox backend only stores the user's public key.
No auth provider mapping needed on CipherBox side.
```

**Automatic Aggregation:**

```
Scenario: User signs up with Google as alice@gmail.com
Later: User tries to sign in with email alice@gmail.com + password

Web3Auth logic (configured via group connections):
1. User attempts email+password login
2. Web3Auth recognizes email is part of an existing group
3. Web3Auth prompts user to link accounts or creates linked identity
4. Same keypair derived regardless of auth method used

CipherBox backend behavior:
1. Receives Web3Auth ID token or SIWE signature
2. Extracts public key from token/signature
3. Looks up user by public key (not by email or provider)
4. Returns vault data for that public key

No duplicate accounts possible - identity is tied to keypair, not email.
```

**Benefits of Web3Auth Group Connections:**

```
- CipherBox backend is simpler (no auth provider mapping)
- Account linking UX handled by Web3Auth (battle-tested)
- Conflict resolution handled by Web3Auth
- Single source of truth for identity (the ECDSA keypair)
- Users identified by public key, not email
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
User Authentication (via Web3Auth - Email/Pass, OAuth, Magic Link, or External Wallet)
    ↓
Web3Auth verifies credentials and group connection
    ↓
Web3Auth nodes derive ECDSA Keypair (secp256k1)
    │
    ├─ ECDSA Private Key (secp256k1)
    │  ├─ Held ONLY in client memory
    │  ├─ Never transmitted in complete form
    │  ├─ Never persisted to disk
    │  ├─ Used for:
    │  │  ├─ ECIES decryption (of folder/file keys)
    │  │  ├─ IPNS entry signing
    │  │  └─ SIWE signature (for CipherBox backend auth)
    │  └─ Discarded on logout
    │
    └─ ECDSA Public Key (secp256k1)
       ├─ Included in Web3Auth ID token (wallets claim)
       ├─ Stored in Vaults table on CipherBox server
       ├─ Used by CipherBox backend to:
       │  ├─ Identify user (pubkey is primary identifier)
       │  ├─ Validate SIWE signatures
       │  └─ Display in user settings
       └─ Used by client to:
          └─ Encrypt all data keys (ECIES)

CipherBox Backend Authentication:
    ↓
Client authenticates via JWT (Web3Auth ID token) or SIWE signature
    ↓
CipherBox Backend issues Access Token + Refresh Token
    ├─ Access Token (15 min expiry)
    │  ├─ Contains: userId, pubkey, iat, exp
    │  ├─ Used for all API calls
    │  └─ Stored in client memory only
    └─ Refresh Token (7 day expiry)
       ├─ Used to obtain new access tokens
       └─ Stored securely (HTTP-only cookie or encrypted storage)

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
- [ Continue with Web3Auth ] button (primary action)

On click:
- User redirected to Web3Auth customized login modal
- Web3Auth handles auth method selection:
  [ Sign in with Google ]
  [ Sign in with Apple  ]
  [ Sign in with GitHub ]
  [ Sign in with Email  ]
  [ Connect Wallet      ]
  [ Magic Link          ]

- Web3Auth handles:
  - Credential verification
  - Key derivation
  - Account linking (via group connections)

- On successful Web3Auth login:
  - Client has ECDSA keypair in memory
  - Client authenticates with CipherBox backend
  - User redirected to /vault

Alternatively (embedded Web3Auth modal):
- Web3Auth modal can be embedded directly in page
- Same flow, but no redirect to separate domain
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
   - Display current auth methods (managed by Web3Auth)
   - List all linked providers from Web3Auth group:
     * Google (alice@gmail.com)
     * Email + Password (alice@gmail.com)
   - "Link Another Account" button
     - Opens Web3Auth account linking flow
     - User can add Google, email/password, external wallet, etc.
     - Web3Auth handles linking to existing group identity
   - Note: Unlinking is handled via Web3Auth dashboard (advanced users)

2. Security
   - Display public key (for reference, verification)
   - Display user ID (for reference)
   - Active sessions (if multi-session tracking implemented)

3. Data & Privacy
   - [ Export Vault ] button
     - Triggers download of vault.json (CIDs + encrypted root key)
     - Includes recovery instructions

4. Danger Zone
   - [ Delete Account ] button
     - Confirm dialog: "Permanently delete your account and vault?"
     - Lists consequences (immediate deletion)
     - [ Cancel ] [ Delete ]

5. Session
   - [ Logout ] button
   - Session info: "Signed in via Google" (current auth method)
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
- **Web3Auth:** @web3auth/modal for authentication and key derivation
- **SIWE (optional):** ethers.js or viem for signature-based auth
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
3. App opens Web3Auth login flow (embedded browser or system browser)
4. User completes authentication via Web3Auth
5. Web3Auth derives ECDSA keypair, reconstructed in memory
6. App authenticates with CipherBox backend (JWT or SIWE)
7. Backend issues access token + refresh token
8. Refresh token stored securely (OS keychain)
9. Access token stored in memory
10. FUSE mount activates
11. App runs in system tray
```
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
            └──────────┬──────────┘
                      │
           ┌──────────┴──────────┐
           │                     │
           ▼                     ▼
    ┌──────────────┐      ┌─────────────────┐
    │  Web3Auth      │      │  CipherBox      │
    │  Network       │      │  Backend        │
    │  (External)    │      │  (Node.js +     │
    │                │      │   NestJS)       │
    │ - Auth UI      │      │                 │
    │ - OAuth        │      │ - JWT/SIWE      │
    │ - Key Share    │      │   validation    │
    │   Derivation   │      │ - Access/Refresh│
    │ - Group        │      │   tokens        │
    │   Connections  │      │ - IPNS proxy    │
    │ - ID Token     │      │ - Vault mgmt    │
    └──────────────┘      └────────┬────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
            ┌────────────────┐  ┌──────────┐  ┌─────────┐
            │  PostgreSQL    │  │ Pinata/  │  │ IPFS    │
            │  Database      │  │ Infura   │  │ Network │
            │                │  │ (Pinning │  │ (P2P    │
            │ - Users        │  │ Service) │  │ Storage)│
            │   (by pubkey)  │  │          │  │         │
            │ - Vaults       │  │ Pins     │  │ Immut.  │
            │ - Refresh      │  │ encrypted│  │ Content │
            │   Tokens       │  │ data     │  │         │
            │ - Auth Nonces  │  │          │  │         │
            │ - Audit Trail  │  │          │  │         │
            └────────────────┘  └──────────┘  └─────────┘
```

**Authentication Flow:**
```
1. Client → Web3Auth: User authenticates (OAuth, email, external wallet, etc.)
2. Web3Auth: Verifies credentials, derives ECDSA keypair via group connections
3. Client: Receives keypair + Web3Auth ID token
4. Client → CipherBox Backend: Authenticates via JWT or SIWE signature
5. CipherBox Backend: Validates identity, issues access/refresh tokens
6. Client → CipherBox Backend: Uses access token for all API calls
```

### 5.2 Tech Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Frontend** | React 18 + TypeScript | Modern, popular, good for encryption UI |
| **Web Crypto** | Web Crypto API | Native browser, no external crypto dependency |
| **IPFS Client (Web)** | kubo-rpc-client | JSON-RPC to IPFS gateway, simple |
| **Web3Auth SDK** | @web3auth/modal | Authentication, key derivation, group connections |
| **SIWE (optional)** | ethers.js or viem | SIWE-style signature generation |
| **Desktop (macOS)** | Tauri or Electron + Swift | Light footprint, native FUSE support |
| **Desktop (Linux)** | Tauri or Electron + Rust | FUSE support, good performance |
| **Desktop (Windows)** | Electron or C# | WinFSP for FUSE equivalent |
| **Backend Server** | Node.js + NestJS + TypeScript | Type-safe, scalable, same language as frontend |
| **JWT Verification** | jose | Verify Web3Auth ID tokens via JWKS |
| **Database** | PostgreSQL | ACID, structured data, audit trail |
| **Cache** | Redis (optional) | Fast token lookups, nonce storage |
| **IPFS Backend** | Pinata API or go-ipfs | Pinata for MVP simplicity, go-ipfs for control |
| **Deployment** | Docker + Kubernetes (future) | Containerization, horizontal scaling |

### 5.3 API Endpoints (NestJS Backend)

**Base URL:** `https://api.cipherbox.io`

#### Authentication Endpoints

```
GET /auth/nonce
  Response: { nonce, expiresAt }
  Purpose: Get a nonce for SIWE-style signature authentication

POST /auth/login
  Body (Option A - Web3Auth JWT): { idToken, appPubKey }
  Body (Option B - SIWE): { message, signature, pubkey }
  Response: { accessToken, refreshToken, userId, pubkey }
  
  JWT Verification:
    - Verify token via Web3Auth JWKS (https://api-auth.web3auth.io/jwks)
    - Check iss = "https://api-auth.web3auth.io"
    - Check aud = CipherBox project client ID
    - Extract pubkey from wallets claim
    - Find or create user by pubkey
  
  SIWE Verification:
    - Verify nonce is valid and unused
    - Verify signature matches claimed pubkey
    - Verify message format and timestamp
    - Find or create user by pubkey

POST /auth/refresh
  Body: { refreshToken }
  Response: { accessToken, refreshToken }
  Purpose: Exchange refresh token for new access + refresh token pair

POST /auth/logout
  Authorization: Bearer accessToken
  Body: { refreshToken }
  Response: { status: "logged_out" }
  Purpose: Invalidate refresh token on server

GET /auth/linked-accounts
  Authorization: Bearer accessToken
  Response: { providers: ["google", "email", ...] }
  Note: Retrieved from Web3Auth, not CipherBox database
```

#### Vault Management Endpoints

```
GET /my-vault
  Authorization: Bearer accessToken
  Response: { vaultId, ownerPublicKey, rootFolderEncryptedEncryptionKey, initializedAt }

POST /my-vault/initialize
  Authorization: Bearer accessToken
  Body: { publicKey, encryptedRootFolderKey }
  Response: { vaultId, status: "initialized" }

POST /vault/upload
  Authorization: Bearer accessToken
  Body: FormData { encryptedFile: File, iv: string }
  Response: { cid, size, uploadedAt }

POST /vault/publish-ipns
  Authorization: Bearer accessToken
  Body: { ipnsName, signedEntry: JSON }
  Response: { success, cid }
```

#### User & Settings Endpoints

```
GET /user/profile
  Authorization: Bearer accessToken
  Response: { userId, pubkey, linkedProviders: [] }
  Note: linkedProviders retrieved from Web3Auth group connection info

GET /user/export-vault
  Authorization: Bearer accessToken
  Response: { vaultExport: { rootIpnsName, rootKeyEncrypted, allCids, instructions } }

DELETE /user/account
  Authorization: Bearer accessToken
  Body: { confirmDelete: true }
  Response: { deleted: true }
```

### 5.4 Database Schema

```sql
-- Users table (simplified - identified by public key)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pubkey BYTEA UNIQUE NOT NULL,  -- ECDSA public key (primary identifier)
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Note: auth_providers table is NO LONGER NEEDED
-- Authentication and account linking is handled entirely by Web3Auth
-- Users are identified by their ECDSA public key, not email or provider IDs

-- Note: passkeys table is NO LONGER NEEDED
-- Passkey MFA will be handled by Web3Auth in future versions

-- Refresh tokens (for session management)
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL,  -- SHA256 hash of refresh token
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  revoked_at TIMESTAMP,  -- Set when token is revoked
  UNIQUE(token_hash)
);

-- Auth nonces (for SIWE-style authentication)
CREATE TABLE auth_nonces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce VARCHAR(64) UNIQUE NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,  -- Set when nonce is consumed
  created_at TIMESTAMP DEFAULT NOW()
);

-- User vaults
CREATE TABLE vaults (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  owner_pubkey BYTEA NOT NULL,  -- ECDSA public key (denormalized for quick lookup)
  root_folder_owner_encrypted_key BYTEA NOT NULL,  -- ECIES(rootKey, pubkey)
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

**Input:** User authentication via Web3Auth (any supported method)
**Output:** ECDSA keypair (secp256k1) guaranteed deterministic across all linked auth methods

**Step 1: Web3Auth Authentication**

```
User initiates login on CipherBox client

1. Client redirects to Web3Auth customized login screen
2. User selects auth method (Google, email/password, external wallet, magic link)
3. User completes authentication with selected provider
4. Web3Auth receives OAuth token or verifies credentials
5. Web3Auth identifies user's group connection:
   - Checks if auth method is part of a configured group
   - Determines group ID (e.g., "cipherbox-aggregate")
6. Web3Auth nodes derive key shares based on group identity
7. Key shares sent to client, combined into ECDSA keypair
8. Web3Auth issues ID token containing:
   {
     "iss": "https://api-auth.web3auth.io",
     "aud": "cipherbox-project-client-id",
     "sub": "unique-user-identifier",
     "wallets": [
       {
         "type": "web3auth_app_key",
         "public_key": "0x04abc...",
         "curve": "secp256k1"
       }
     ],
     "iat": current_timestamp,
     "exp": current_timestamp + 3600
   }
```

**Step 2: CipherBox Backend Authentication**

```
Client has ECDSA keypair in memory and Web3Auth ID token

Option A - JWT Authentication:
1. Client obtains ID token from Web3Auth: getIdentityToken()
2. Client sends to CipherBox backend:
   POST /auth/login
   {
     "idToken": "eyJhbGciOiJFUzI1NiIs...",
     "appPubKey": "0x04abc..."  // Public key to verify
   }
3. Backend verifies ID token:
   - Fetches JWKS from https://api-auth.web3auth.io/jwks
   - Verifies JWT signature (ES256)
   - Checks iss = "https://api-auth.web3auth.io"
   - Checks aud = CipherBox project client ID
   - Checks exp > current time
   - Extracts wallets array, finds web3auth_app_key
   - Verifies appPubKey matches wallet public_key
4. Backend finds or creates user by pubkey
5. Backend issues CipherBox tokens:
   {
     "accessToken": "eyJhbGciOiJSUzI1NiIs...",
     "refreshToken": "abc123...",
     "userId": "uuid",
     "pubkey": "0x04abc..."
   }

Option B - SIWE-style Signature Authentication:
1. Client requests nonce:
   GET /auth/nonce
   Response: { "nonce": "abc123", "expiresAt": "..." }
2. Client constructs message:
   message = {
     "domain": "cipherbox.io",
     "pubkey": "0x04abc...",
     "nonce": "abc123",
     "timestamp": current_timestamp,
     "statement": "Sign in to CipherBox"
   }
3. Client signs message with ECDSA private key:
   signature = ECDSA_sign(keccak256(message), privateKey)
4. Client sends to CipherBox backend:
   POST /auth/login
   {
     "message": message,
     "signature": "0xdef789...",
     "pubkey": "0x04abc..."
   }
5. Backend verifies:
   - Nonce exists and not expired/used
   - Recovers pubkey from signature
   - Verifies recovered pubkey matches claimed pubkey
   - Marks nonce as used
6. Backend finds or creates user by pubkey
7. Backend issues CipherBox tokens (same as Option A)
```

**Determinism Guarantee (via Web3Auth Group Connections):**

```
Theorem: Same user with linked auth methods → Same ECDSA keypair

Proof:
- Web3Auth group connections configured in dashboard
- All auth methods in group "cipherbox-aggregate" linked
- Group identity determines key derivation input
- Same group identity → same key shares → same keypair

Example:
- User signs up with Google (email: alice@gmail.com)
- Google auth in group "cipherbox-aggregate"
- Web3Auth derives keypair A

- User later adds email/password (alice@gmail.com)
- Email auth added to same group "cipherbox-aggregate"
- Web3Auth links to same identity

- User logs in with email/password
- Email auth in group "cipherbox-aggregate"
- Web3Auth derives keypair A (same!)

✓ Same keypair across methods
✓ Account linking handled by Web3Auth (not CipherBox backend)
✓ Users identified by pubkey (not email)
```

#### Test Vectors

**Test Vector 1: Google Signup + Email Login Consistency**

```
Scenario: User signs up with Google, later logs in with linked email

Signup with Google:
  OAuth: Google returns alice@gmail.com
  Web3Auth: Group "cipherbox-aggregate" → derive keypair
  Result: ECDSA_privkey_1 → ECDSA_pubkey_1
  
  Client authenticates with CipherBox:
  POST /auth/login { idToken: "...", appPubKey: "0xpubkey1" }
  Backend: Creates user with pubkey_1, returns tokens
  
  Client initializes vault:
  POST /my-vault/initialize { publicKey: "0xpubkey1", encryptedRootFolderKey: "..." }

Add email/password (via Web3Auth account linking):
  User clicks "Add Email" in CipherBox settings
  Redirected to Web3Auth linking flow
  Enters alice@gmail.com + password
  Web3Auth links to existing group identity

Login with email (1 day later):
  User enters alice@gmail.com + password
  Web3Auth: Same group "cipherbox-aggregate" → derive keypair
  Result: ECDSA_privkey_1 (same!) → ECDSA_pubkey_1 (same!)
  
  Client authenticates with CipherBox:
  POST /auth/login { idToken: "...", appPubKey: "0xpubkey1" }
  Backend: Finds existing user by pubkey_1, returns tokens
  
  GET /my-vault returns same vault (same pubkey)
  Client decrypts root key with privkey_1

Result: ✓ Same keypair, same vault access across auth methods
```

**Test Vector 2: SIWE-style Authentication**

```
Scenario: User logs in using signature instead of JWT

User completes Web3Auth login:
  ECDSA_privkey_1, ECDSA_pubkey_1 in memory

Client requests nonce:
  GET /auth/nonce
  Response: { nonce: "abc123", expiresAt: "2026-01-15T05:00:00Z" }

Client constructs and signs message:
  message = {
    domain: "cipherbox.io",
    pubkey: "0x04pubkey1...",
    nonce: "abc123",
    timestamp: 1705298400,
    statement: "Sign in to CipherBox"
  }
  signature = ECDSA_sign(keccak256(JSON.stringify(message)), privkey_1)

Client sends authentication request:
  POST /auth/login
  {
    message: message,
    signature: "0xsignature...",
    pubkey: "0x04pubkey1..."
  }

Backend verification:
  1. Find nonce "abc123" in auth_nonces table
  2. Verify not expired and not used
  3. Recover pubkey: recovered = ecrecover(keccak256(message), signature)
  4. Verify: recovered == "0x04pubkey1..."
  5. Mark nonce as used
  6. Find or create user by pubkey
  7. Issue access token + refresh token

Result: ✓ User authenticated without exposing Web3Auth ID token
```

**Test Vector 3: Token Refresh Flow**

```
Scenario: Access token expires, client refreshes

T0: User logged in, has access token (expires T0+15min) + refresh token
T+14min: Access token still valid, API calls succeed
T+16min: Access token expired

Client detects 401 response:
  GET /my-vault
  Response: 401 { error: "Token expired" }

Client refreshes tokens:
  POST /auth/refresh
  { refreshToken: "abc123..." }
  
  Response: {
    accessToken: "new_access_token",
    refreshToken: "new_refresh_token"  // Rotation
  }

Client retries with new access token:
  GET /my-vault
  Authorization: Bearer new_access_token
  Response: 200 { vaultId: "...", ... }

Result: ✓ Session continues without re-authentication via Web3Auth
```

---

## 6. Data Flows & Examples

### 6.1 Complete Auth Flow (Web3Auth + CipherBox Backend)

```
User navigates to CipherBox.com

1. Frontend:
   User clicks "Sign In" or "Sign Up"
   Frontend redirects to Web3Auth customized login screen

2. Web3Auth Login Screen:
   User sees options: Google, Email, External Wallet, Magic Link
   User selects Google and completes OAuth flow

3. Web3Auth Backend:
   Receives OAuth token from Google
   Verifies token with Google
   Identifies group connection "cipherbox-aggregate"
   Instructs nodes to derive key shares

4. Web3Auth Nodes (Distributed):
   Each node derives its share of ECDSA private key
   Shares sent to client (encrypted)

5. Frontend (Client):
   Receives key shares from Web3Auth nodes
   Reconstructs ECDSA private key in RAM:
     privateKey = combineShares(share1, share2, share3, ...)
   Derives public key:
     publicKey = EC_multiply(privateKey, G)
   Obtains Web3Auth ID token:
     idToken = await getIdentityToken()

6. Frontend → CipherBox Backend (Authentication):
   POST /auth/login
   Body: {
     idToken: "eyJhbGciOiJFUzI1NiIs...",
     appPubKey: "0x04abc123..."
   }

7. CipherBox Backend:
   a) Fetch JWKS from Web3Auth:
      GET https://api-auth.web3auth.io/jwks
   b) Verify JWT signature (ES256) using JWKS
   c) Validate claims:
      - iss == "https://api-auth.web3auth.io"
      - aud == CIPHERBOX_PROJECT_CLIENT_ID
      - exp > now
      - iat < now
   d) Extract wallets array from payload
   e) Find wallet with type "web3auth_app_key"
   f) Verify appPubKey matches wallet.public_key
   g) Find user by pubkey or create new user:
      SELECT * FROM users WHERE pubkey = $1
      If not found: INSERT INTO users (pubkey) VALUES ($1)
   h) Generate access token (15 min expiry):
      accessToken = JWT_sign({ userId, pubkey, iat, exp }, backendPrivateKey)
   i) Generate refresh token (Same expiry as the Web3Auth ID Token):
      refreshToken = secureRandomBytes(32)
      INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES ($userId, SHA256(refreshToken), now + 7 days)

8. CipherBox Backend → Frontend:
   Response: {
     accessToken: "eyJhbGciOiJSUzI1NiIs...",
     refreshToken: "abc123...",
     userId: "uuid-here",
     pubkey: "0x04abc123..."
   }

9. Frontend:
   Stores accessToken in memory
   Stores refreshToken securely (HTTP-only cookie or encrypted storage)
   Calls GET /my-vault with accessToken:
   Header: Authorization: Bearer <accessToken>

10. CipherBox Backend:
    Verifies accessToken (signature, expiration)
    Finds user's vault in Vaults table by userId
    Returns:
    {
      vaultId: "uuid",
      ownerPublicKey: "0x04abc123...",
      rootFolderEncryptedEncryptionKey: "0x..." (encrypted with pubkey)
    }
    OR if no vault: 403 Vault Not Initialized

11. Frontend (if vault not initialized):
    Generate random 256-bit root folder key
    Encrypt with user's public key:
      encryptedRootKey = ECIES_Encrypt(rootFolderKey, publicKey)
    POST /my-vault/initialize {
      publicKey: "0x04abc123...",
      encryptedRootFolderKey: encryptedRootKey
    }

12. Frontend (vault initialized):
    Decrypt root folder key:
      rootFolderKey = ECIES_Decrypt(
        rootFolderEncryptedEncryptionKey,
        ECDSA_privateKey
      )
    Store rootFolderKey in memory (session-only)

13. Frontend:
    User now authenticated
    Redirect to /vault page
    Display file browser (initially empty or cached)

Alternative: SIWE-style Authentication (Step 6-8)

6a. Frontend → CipherBox Backend (Get Nonce):
    GET /auth/nonce
    Response: { nonce: "xyz789", expiresAt: "..." }

6b. Frontend (Sign Message):
    message = {
      domain: "cipherbox.io",
      pubkey: "0x04abc123...",
      nonce: "xyz789",
      timestamp: Date.now(),
      statement: "Sign in to CipherBox"
    }
    signature = ECDSA_sign(keccak256(JSON.stringify(message)), privateKey)

6c. Frontend → CipherBox Backend (Authenticate):
    POST /auth/login
    Body: {
      message: message,
      signature: "0xsig...",
      pubkey: "0x04abc123..."
    }

7a. CipherBox Backend (SIWE Verification):
    a) Find nonce in auth_nonces table
    b) Verify nonce not expired and not used
    c) Recover pubkey from signature:
       recoveredPubkey = ecrecover(keccak256(message), signature)
    d) Verify recoveredPubkey == claimed pubkey
    e) Mark nonce as used
    f) Continue from step 7g (find/create user by pubkey)
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
- ✓ Multi-method auth (Email/Pass, OAuth, Magic Link, External Wallet)
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

- **ECDSA:** Elliptic Curve Digital Signature Algorithm. Used for signing IPNS entries and identity verification.
- **ECIES:** Elliptic Curve Integrated Encryption Scheme. Used for key wrapping (asymmetric encryption of symmetric keys).
- **AES-256-GCM:** Advanced Encryption Standard (256-bit key) with Galois/Counter Mode (authenticated encryption).
- **IPFS:** InterPlanetary File System. Peer-to-peer, content-addressed distributed storage network.
- **IPNS:** IPFS Name System. Mutable pointers to immutable IPFS content (CIDs).
- **CID:** Content Identifier. Hash of file content, used as immutable reference on IPFS.
- **FUSE:** Filesystem in Userspace. Kernel module allowing user-space filesystem implementation.
- **E2E Encryption:** End-to-End. Data encrypted on client; server never holds plaintext.
- **Zero-Knowledge:** Server has no knowledge of user data or encryption keys (cryptographic guarantee).
- **Web3Auth:** Distributed key derivation and authentication service. Provides deterministic ECDSA keypair via threshold cryptography.
- **Web3Auth Group Connections:** Feature that links multiple auth methods (Google, email, external wallet) to derive the same ECDSA keypair, enabling seamless account aggregation.
- **Web3Auth ID Token:** JWT issued by Web3Auth containing user identity claims and wallet public keys, used to authenticate with backend services.
- **WebAuthn/FIDO2:** Standards for phishing-resistant authentication via device-bound credentials (Passkeys). Used as MFA in Web3Auth, not primary authentication.
- **External Wallet Auth:** Trustless authentication method where user signs a message with an existing cryptocurrency wallet (MetaMask, WalletConnect, etc.) to prove identity.
- **JWT:** JSON Web Token. Signed credential containing identity claims.
- **SIWE:** Sign-In with Ethereum (or similar). Authentication method where user signs a message with their private key to prove ownership.
- **Access Token:** Short-lived JWT (15 min) issued by CipherBox backend for API authorization.
- **Refresh Token:** Long-lived token (7 days) used to obtain new access tokens without re-authentication.
- **JWKS:** JSON Web Key Set. Endpoint providing public keys for JWT signature verification.

### 8.2 Security Considerations

**Threat Model:**

- **Server Compromise:** Attacker gains access to CipherBox database and code.
  - Impact: Attacker has encrypted root keys, user pubkeys, refresh token hashes.
  - Cannot decrypt: All data encrypted with user's private key (only in client memory).
  - Cannot impersonate: Refresh tokens are hashed; attacker cannot derive valid tokens.
  - Mitigation: Private keys never stored on server. Users identified by pubkey, not credentials.

- **Web3Auth Compromise:** Attacker compromises Web3Auth infrastructure.
  - Impact: Could potentially derive user keypairs (requires compromising threshold of nodes).
  - Mitigation: Web3Auth uses threshold cryptography; no single point of failure.
  - Defense-in-depth: CipherBox backend validates identity independently via SIWE signatures.

- **Network Interception:** Attacker intercepts HTTPS traffic.
  - Impact: Attacker can observe ciphertexts (but not keys or plaintext).
  - Cannot decrypt: Ciphertexts encrypted with user's public key (asymmetric).
  - Mitigation: HTTPS enforced, certificate pinning (future).

- **Client Compromise:** Attacker gains control of user's device.
  - Impact: Attacker can access private key in RAM during session.
  - Mitigation: Limited exposure during session, keys discarded on logout.
  - Defense-in-depth: External wallet auth requires wallet approval; MFA (passkeys) adds extra layer.

- **Weak Password:** User chooses weak password for email/password auth.
  - Impact: Attacker can brute-force password via Web3Auth.
  - Mitigation: Web3Auth can enforce password policies. Key derivation is rate-limited.
  - Future: Enforce minimum entropy (zxcvbn or similar) in Web3Auth config.

- **Refresh Token Theft:** Attacker steals refresh token from client storage.
  - Impact: Attacker can obtain new access tokens, impersonate user.
  - Mitigation: Refresh token rotation (new token on each use), secure storage (HTTP-only cookie).
  - Defense-in-depth: Short access token expiry (15 min) limits exposure window.

**Best Practices:**

- Use strong, unique passwords (or external wallet for trustless auth).
- Backup vault export and store securely.
- Don't share recovery key with anyone.
- Keep software updated (app + OS).
- Use device lock (biometric, PIN) for physical security.
- Prefer SIWE authentication for maximum security (no reliance on Web3Auth ID tokens).

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

A: Yes. The server holds encrypted data only. Your encryption keys are never stored on the server; they're generated by Web3Auth and held only in your device's memory. Even if an attacker compromises the CipherBox server, they cannot decrypt your files without your private key.

**Q: How is my private key kept safe?**

A: Your private key is generated by Web3Auth's distributed network using threshold cryptography. The complete key is reconstructed only in your device's memory during your session. It's never transmitted in complete form, stored on disk, or logged. On logout or session expiration, the key is discarded.

**Q: Can CipherBox employees see my files?**

A: No. CipherBox never has your encryption keys or plaintext files. We cannot decrypt your data even if we wanted to. This is enforced by the cryptography, not just policy. We identify you by your public key, not by credentials.

**Q: How does account linking work with multiple auth methods?**

A: CipherBox uses Web3Auth's group connections feature. When you sign up with Google and later add email/password, both auth methods are linked in Web3Auth's system to derive the same ECDSA keypair. This means you get the same private key regardless of how you log in, giving you access to the same vault.

**Q: What if I forget my password?**

A: If you use email/password, you can reset your password through Web3Auth's recovery flow. Because Web3Auth handles password verification and key derivation, resetting your password will still give you access to the same keypair (and thus your vault) as long as the email is linked to your Web3Auth group.

**Q: What if I lose my device?**

A: You can log in using an alternate auth method linked to your Web3Auth group (email/password, OAuth, or external wallet). Once logged in via Web3Auth, your vault access is preserved because all linked methods derive the same keypair.

**Q: Can I recover my vault if I lose access to all auth methods?**

A: If you lose access to all auth methods linked to your Web3Auth group, and you don't have a vault export with your private key, your vault cannot be recovered. This is the security/convenience tradeoff of zero-knowledge architecture. We recommend exporting your vault regularly and storing the backup securely.

**Q: What's the difference between JWT and SIWE authentication with CipherBox backend?**

A: Both achieve the same result (authenticating with CipherBox to get access tokens). JWT authentication uses the Web3Auth ID token - simpler but relies on Web3Auth's token signing. SIWE authentication uses your private key to sign a message - more control and doesn't rely on Web3Auth tokens, but requires an extra step. Both are secure; choose based on your preference.

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

- **Author:** Michael Yankelev
- **Reviewed:** Michael Yankelev
- **Approved:** TBC
- **Status:** IN REVIEW

---

**End of CipherBox PRD**

