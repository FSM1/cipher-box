# CipherBox AI Agent Instructions

## Version Management

**Current Documentation Version:** 1.8.0

### Version Bump Rule

When modifying any documentation file in `Documentation/`, you MUST:

1. Increment the patch version (e.g., 1.7.0 → 1.7.1) for minor updates
2. Increment the minor version (e.g., 1.7.0 → 1.8.0) for new sections or significant changes
3. Update the `version` field in the YAML frontmatter of the modified file
4. Update the `last_updated` field to the current date
5. Update this file's "Current Documentation Version" to match
6. Update `claude.md` "Current Version" to match

---

## Project Overview

**CipherBox** is a **technology demonstrator** for privacy-first, zero-knowledge encrypted cloud storage using IPFS/IPNS for decentralized persistence and Web3Auth for deterministic key derivation.

**Purpose:** This is not a commercial product. It demonstrates novel applications of cryptography and decentralized systems.

**Core Principle:** The server NEVER sees plaintext data or unencrypted keys. All encryption/decryption happens client-side.

## Documentation Structure

| Document                                                                | Purpose                                    |
| ----------------------------------------------------------------------- | ------------------------------------------ |
| [PRD.md](../Documentation/PRD.md)                                       | Product requirements, user journeys, scope |
| [TECHNICAL_ARCHITECTURE.md](../Documentation/TECHNICAL_ARCHITECTURE.md) | Encryption, key hierarchy, system design   |
| [API_SPECIFICATION.md](../Documentation/API_SPECIFICATION.md)           | Backend endpoints, database schema         |
| [DATA_FLOWS.md](../Documentation/DATA_FLOWS.md)                         | Sequence diagrams, test vectors            |
| [CLIENT_SPECIFICATION.md](../Documentation/CLIENT_SPECIFICATION.md)     | Web UI, desktop app specs                  |

---

## Critical Architecture Patterns

### Two-Phase Authentication Model

CipherBox uses a **mandatory two-phase auth flow** that must be understood before implementing any auth-related features:

1. **Phase 1 (Web3Auth):** User authenticates → Web3Auth derives ECDSA secp256k1 keypair via threshold cryptography
2. **Phase 2 (CipherBox Backend):** Client authenticates with backend using either:
   - **Option A:** Web3Auth ID token (JWT) validated via JWKS endpoint
   - **Option B:** SIWE-like signature flow (nonce-based)

**Key Insight:** The ECDSA keypair from Phase 1 is the user's identity. Web3Auth's "group connections" feature ensures that Google OAuth, email/password, magic links, and external wallet auth all derive the **same keypair** for the same user.

### Zero-Knowledge Key Hierarchy

```
User Auth → Web3Auth → ECDSA Private Key (client RAM only, never transmitted)
                    ├─ Used for ECIES decryption of all data keys
                    ├─ Used for IPNS entry signing
                    └─ Destroyed on logout

ECDSA Public Key (stored on server, identifies user)
    └─ Used to encrypt (ECIES):
        ├─ Root Folder Key (AES-256, stored encrypted on server)
        ├─ Subfolder Keys (AES-256, stored encrypted in parent IPNS metadata)
        └─ File Keys (AES-256, stored encrypted in folder IPNS metadata)
```

**Critical Rule:** Never log, persist to disk, or transmit the ECDSA private key. It exists ONLY in client memory during the session.

### Per-Folder IPNS Architecture

Each folder has its own IPNS entry containing encrypted metadata. This design enables future per-folder sharing (v2+).

**Folder Metadata Structure:**

```typescript
interface DecryptedFolderMetadata {
  children: Array<{
    type: "file" | "folder";
    nameEncrypted: string; // AES-256-GCM(name, folderKey)
    nameIv: string;
    cid?: string; // For files: IPFS CID
    ipnsName?: string; // For folders: IPNS name
    fileKeyEncrypted?: string; // ECIES(fileKey, userPubkey)
    subfolderKeyEncrypted?: string; // ECIES(folderKey, userPubkey)
    size?: number;
    created: number;
    modified: number;
  }>;
}
```

**When modifying files/folders:** Always re-encrypt and republish the containing folder's IPNS entry.

## Technology Stack & Standards

### Encryption Primitives (Non-Negotiable)

| Algorithm           | Use Case                            | Implementation                |
| ------------------- | ----------------------------------- | ----------------------------- |
| **AES-256-GCM**     | File content + metadata encryption  | Web Crypto API / libsodium.js |
| **ECIES secp256k1** | Key wrapping (files, folders)       | ethers.js / libsodium.js      |
| **ECDSA secp256k1** | IPNS signing, user identity         | Web3Auth / ethers.js          |
| **HKDF-SHA256**     | Key derivation                      | Web Crypto API                |
| **Argon2**          | Password hashing (server-side only) | argon2-browser                |

**Never use:** Custom crypto, CBC mode, ECB mode, MD5, SHA1

### Target Tech Stack (v1.0)

- **Frontend:** React 18 + TypeScript + Tailwind CSS
- **Backend:** Node.js + NestJS + TypeScript
- **Database:** PostgreSQL (users, vaults, audit trail)
- **Storage:** IPFS via Pinata API
- **Auth:** Web3Auth Modal SDK (@web3auth/modal)
- **Desktop:** Tauri/Electron + FUSE (macFUSE/FUSE3/WinFSP)

## Development Patterns

### File Upload Flow (Reference Implementation)

```typescript
// 1. Generate random file key
const fileKey = crypto.getRandomValues(new Uint8Array(32));
const fileIV = crypto.getRandomValues(new Uint8Array(12)); // GCM uses 96-bit IV

// 2. Encrypt file content
const encryptedFile = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv: fileIV },
  await crypto.subtle.importKey("raw", fileKey, "AES-GCM", false, ["encrypt"]),
  fileContent
);

// 3. Wrap file key with user's public key (ECIES)
const encryptedFileKey = await eciesEncrypt(fileKey, userPublicKey);

// 4. Upload encrypted file to backend → Pinata → get CID
const { cid } = await api.post("/vault/upload", {
  encryptedFile: new Blob([encryptedFile]),
  fileName: file.name, // plaintext OK for server audit
  iv: bytesToHex(fileIV),
});

// 5. Add to folder metadata (all encrypted)
const fileEntry = {
  type: "file",
  nameEncrypted: await aesEncrypt(file.name, folderKey),
  nameIv: crypto.getRandomValues(new Uint8Array(12)),
  cid,
  fileKeyEncrypted: encryptedFileKey,
  fileIv: bytesToHex(fileIV),
  size: file.size,
  created: Date.now(),
  modified: Date.now(),
};

// 6. Re-encrypt folder metadata and republish IPNS
await republishFolderIPNS(folderId, updatedMetadata);
```

### IPNS Publishing Pattern

Every write operation (create/rename/move/delete) must:

1. Update the in-memory folder metadata
2. Re-encrypt the entire metadata JSON with the folder key
3. Sign the encrypted metadata with ECDSA private key
4. Call `POST /vault/publish-ipns` with signed entry

**Performance Note:** IPNS publishing is the bottleneck (~2s). Batch operations when possible (e.g., multi-file upload should publish once at the end).

### Session Token Management

```typescript
// Access tokens (15min, memory only)
const accessToken = response.data.accessToken;
// Store in: React context / Zustand / Redux (never localStorage)

// Refresh tokens (7 days, secure storage)
const refreshToken = response.data.refreshToken;
// Store in: HTTP-only cookie (preferred) OR encrypted localStorage

// Token refresh pattern
if (error.response?.status === 401) {
  const newAccessToken = await refreshAccessToken();
  // Retry original request with new token
}
```

## Common Pitfalls & Anti-Patterns

### ❌ Never Do This

1. **Storing keys in plaintext localStorage**

   ```typescript
   // WRONG
   localStorage.setItem("privateKey", privateKeyHex);
   ```

2. **Logging sensitive data**

   ```typescript
   // WRONG
   console.log("User private key:", privateKey);
   console.log("Decrypted file:", fileContent);
   ```

3. **Sending plaintext to server**

   ```typescript
   // WRONG
   await api.post("/vault/upload", { fileContent: file });
   ```

4. **Using sync crypto in main thread**
   ```typescript
   // WRONG (blocks UI for large files)
   const encrypted = aesEncryptSync(largeFile, key);
   ```

### ✅ Correct Patterns

1. **Store keys in memory, clear on logout**

   ```typescript
   // React context for session-scoped state
   const [ecdsaPrivateKey, setEcdsaPrivateKey] = useState<Uint8Array | null>(
     null
   );

   const logout = () => {
     setEcdsaPrivateKey(null); // Cleared from memory
     // No disk persistence
   };
   ```

2. **Use Web Workers for large file encryption**

   ```typescript
   const worker = new Worker("./crypto-worker.js");
   worker.postMessage({ fileData, key });
   worker.onmessage = (e) => {
     const encrypted = e.data;
   };
   ```

3. **Always validate IPNS signatures client-side**
   ```typescript
   const messageHash = await sha256(signedEntry.encryptedMetadata);
   const isValid = await ecdsaVerify(
     messageHash,
     signedEntry.signature,
     userPubkey
   );
   if (!isValid) throw new Error("Metadata tampering detected");
   ```

## MVP Scope Boundaries (v1.0)

### ✅ In Scope

- Multi-method auth (email/pass, OAuth, magic link, external wallet)
- File upload/download (E2E encrypted)
- Folder operations (create/rename/move/delete)
- Web UI (React)
- Desktop mount (macOS FUSE only for v1.0)
- Multi-device sync (IPNS polling, ~30s latency)
- Vault export (data portability)

### ❌ Out of Scope (defer to v1.1+)

- Billing/payments
- File versioning
- Folder sharing
- Search/indexing
- Mobile apps
- Linux/Windows desktop (v1.1)

**When users request out-of-scope features:** Acknowledge the value, but clarify they're post-MVP. Suggest workarounds if applicable.

## Testing Requirements

### Security Test Checklist

- [ ] Private key never logged (search logs for "privateKey", "ecdsa", "0x04")
- [ ] Private key never in localStorage/sessionStorage
- [ ] All file uploads: server receives ciphertext only
- [ ] All folder names: encrypted in IPNS metadata
- [ ] IPNS signature verification passes
- [ ] Wrong private key cannot decrypt vault

### Performance Benchmarks (P95)

- Auth flow: <3s
- File upload (<100MB): <5s
- File download (<100MB): <5s
- IPNS publish: <2s
- Folder create: <1s
- Multi-device sync latency: <30s

## Key Files & Documentation

- [00_START_HERE.md](../00_START_HERE.md) - Project overview, quick reference
- [README.md](../README.md) - Architecture summary, tech stack
- [IMPLEMENTATION_ROADMAP.md](../IMPLEMENTATION_ROADMAP.md) - 12-week development timeline
- [Documentation/PRD.md](../Documentation/PRD.md) - Product requirements, user journeys, scope
- [Documentation/TECHNICAL_ARCHITECTURE.md](../Documentation/TECHNICAL_ARCHITECTURE.md) - Encryption, key hierarchy, system design
- [Documentation/API_SPECIFICATION.md](../Documentation/API_SPECIFICATION.md) - Backend endpoints, database schema
- [Documentation/DATA_FLOWS.md](../Documentation/DATA_FLOWS.md) - Sequence diagrams, test vectors
- [Documentation/CLIENT_SPECIFICATION.md](../Documentation/CLIENT_SPECIFICATION.md) - Web UI, desktop app specs

**For detailed crypto flows:** See TECHNICAL_ARCHITECTURE.md (key hierarchy, encryption primitives) and DATA_FLOWS.md (sequence diagrams, test vectors)

## API Conventions (When Backend Exists)

### Expected Endpoints

- `POST /auth/login` - Authenticate with Web3Auth ID token or SIWE signature
- `GET /auth/nonce` - Get nonce for SIWE flow
- `POST /auth/refresh` - Refresh access token
- `GET /my-vault` - Get encrypted root key + IPNS name
- `POST /my-vault/initialize` - Create vault (first-time setup)
- `POST /vault/upload` - Upload encrypted file → IPFS → return CID
- `POST /vault/publish-ipns` - Publish signed IPNS entry
- `POST /vault/export` - Generate vault export JSON

### Response Patterns

```typescript
// Success
{ success: true, data: { cid: "QmXxxx..." } }

// Error
{ success: false, error: { code: "VAULT_NOT_INITIALIZED", message: "..." } }
```

## Web3Auth Integration Notes

### Group Connections Setup (Dashboard)

Configure in Web3Auth dashboard to link multiple auth methods:

```
cipherbox-aggregate (group ID)
  ├─ google (Google OAuth)
  ├─ email_passwordless (Magic Link)
  ├─ auth0 (Email/Password via Auth0)
  └─ external_wallets (MetaMask, WalletConnect)
```

### Client Integration

```typescript
import { Web3Auth } from "@web3auth/modal";

const web3auth = new Web3Auth({
  clientId: "YOUR_CLIENT_ID",
  web3AuthNetwork: "sapphire_mainnet", // or testnet
  chainConfig: {
    chainNamespace: "eip155",
    chainId: "0x1", // Ethereum mainnet (or any chain)
  },
});

await web3auth.initModal();
const web3authProvider = await web3auth.connect();

// Get private key (use sparingly, clear from memory ASAP)
const privateKey = await web3authProvider.request({
  method: "eth_private_key",
});

// Get ID token for CipherBox backend auth
const { idToken } = await web3auth.authenticateUser();
```

## Questions to Ask When Unclear

1. **Auth-related:** "Does this require Phase 1 (Web3Auth) or Phase 2 (CipherBox backend) authentication?"
2. **Encryption:** "Should this data be encrypted client-side before transmission?"
3. **Keys:** "Which key in the hierarchy (ECDSA private, root folder, subfolder, file) should be used here?"
4. **IPNS:** "Does this operation require republishing an IPNS entry?"
5. **Scope:** "Is this feature in v1.0 MVP scope, or should it be deferred to v1.1+?"

## Final Note

This project prioritizes **cryptographic correctness over convenience**. When in doubt, err on the side of more encryption, more validation, and stricter security. The target user (cypherpunks, crypto enthusiasts) values privacy guarantees more than UX polish.

**For detailed guidance:** Refer to [PRD.md](../Documentation/PRD.md) for product scope, [TECHNICAL_ARCHITECTURE.md](../Documentation/TECHNICAL_ARCHITECTURE.md) for crypto and system design, and [DATA_FLOWS.md](../Documentation/DATA_FLOWS.md) for test vectors and sequence diagrams.
