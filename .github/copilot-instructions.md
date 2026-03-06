# CipherBox AI Agent Instructions

## Project Overview

**CipherBox** is a **technology demonstrator** for privacy-first, zero-knowledge encrypted cloud storage using IPFS/IPNS for decentralized persistence and Web3Auth for deterministic key derivation.

**Purpose:** This is not a commercial product. It demonstrates novel applications of cryptography and decentralized systems.

**Core Principle:** The server NEVER sees plaintext data or unencrypted keys. All encryption/decryption happens client-side.

## Documentation

| Document                                                                      | Purpose                                                        |
| :---------------------------------------------------------------------------- | :------------------------------------------------------------- |
| [README.md](../README.md)                                                     | Project overview, features, tech stack                         |
| [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)                               | Encryption hierarchy, key derivation, data flows, threat model |
| [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md)                                 | Local setup, running, testing                                  |
| [docs/AUTHENTICATION_ARCHITECTURE.md](../docs/AUTHENTICATION_ARCHITECTURE.md) | Auth flow details                                              |
| [docs/METADATA_SCHEMAS.md](../docs/METADATA_SCHEMAS.md)                       | All metadata object schemas with field tables                  |
| [docs/VAULT_EXPORT_FORMAT.md](../docs/VAULT_EXPORT_FORMAT.md)                 | Export/recovery data format                                    |
| [docs/DATABASE_EVOLUTION_PROTOCOL.md](../docs/DATABASE_EVOLUTION_PROTOCOL.md) | Migration discipline                                           |

---

## Critical Architecture Patterns

### Two-Phase Authentication Model

CipherBox uses a **mandatory two-phase auth flow**:

1. **Phase 1 (Web3Auth MPC Core Kit):** User authenticates via email OTP, Google OAuth, magic link, or external wallet. Web3Auth derives an ECDSA secp256k1 keypair via MPC threshold cryptography. MFA is handled via device factors.
2. **Phase 2 (CipherBox Backend):** Client authenticates with the backend using a Web3Auth ID token (JWT) validated via JWKS. The backend issues its own access/refresh token pair.

**Key Insight:** The ECDSA keypair from Phase 1 is the user's identity. Web3Auth ensures the same user always derives the same keypair regardless of auth method (when methods resolve to the same CipherBox `userId`).

See [docs/AUTHENTICATION_ARCHITECTURE.md](../docs/AUTHENTICATION_ARCHITECTURE.md) for full details.

### Zero-Knowledge Key Hierarchy

```text
User Auth → Web3Auth MPC Core Kit → ECDSA Private Key (client RAM only, never transmitted)
                    ├─ Used for ECIES decryption of all data keys
                    ├─ Used to derive IPNS signing keys (Ed25519, HKDF)
                    └─ Destroyed on logout

ECDSA Public Key (stored on server, identifies user)
    └─ Used to encrypt (ECIES):
        ├─ Root Folder Key (random AES-256, stored encrypted on server)
        ├─ Subfolder Keys (random AES-256, stored encrypted in parent folder metadata)
        └─ File Keys (random AES-256, stored encrypted in per-file metadata)

IPNS Keypairs (Ed25519, HKDF-derived from private key)
    ├─ Vault IPNS (root folder metadata pointer)
    ├─ Device Registry IPNS
    └─ Per-file IPNS (file metadata pointer)
```

**Critical Rule:** Never log, persist to disk, or transmit the ECDSA private key. It exists ONLY in client memory during the session.

### v2 Folder Metadata with FilePointers

Each folder has its own IPNS entry. Files use a v2 `FilePointer` schema — the folder stores a slim reference, and per-file crypto material lives in a dedicated IPNS record.

See [docs/METADATA_SCHEMAS.md](../docs/METADATA_SCHEMAS.md) for the full schema reference including `FolderMetadata`, `FilePointer`, `FileMetadata`, and all other metadata objects.

## Technology Stack

| Component          | Technology                                       |
| :----------------- | :----------------------------------------------- |
| **Frontend**       | React 18 + TypeScript + Tailwind CSS             |
| **Backend**        | Node.js + NestJS + TypeScript                    |
| **Database**       | PostgreSQL 16                                    |
| **Job Queue**      | BullMQ + Redis                                   |
| **Key Derivation** | Web3Auth MPC Core Kit (`@web3auth/mpc-core-kit`) |
| **Storage**        | IPFS via Kubo                                    |
| **Desktop**        | Tauri v2 + FUSE-T (macOS, SMB backend)           |
| **TEE**            | Phala Cloud (IPNS republishing)                  |
| **Crypto**         | Web Crypto API (AES-256-GCM, ECIES secp256k1)    |

### Encryption Primitives (Non-Negotiable)

| Algorithm           | Use Case                            | Implementation |
| ------------------- | ----------------------------------- | -------------- |
| **AES-256-GCM**     | File content + metadata encryption  | Web Crypto API |
| **AES-256-CTR**     | Streaming encryption (large files)  | Web Crypto API |
| **ECIES secp256k1** | Key wrapping (files, folders, IPNS) | eciesjs        |
| **HKDF-SHA256**     | IPNS keypair derivation             | Web Crypto API |
| **Ed25519**         | IPNS record signing                 | @noble/ed25519 |

**Never use:** Custom crypto, CBC mode, ECB mode, MD5, SHA1

## API Endpoints (Actual Implementation)

| Endpoint                          | Method | Purpose                                     |
| :-------------------------------- | :----- | :------------------------------------------ |
| `/auth/identity/google`           | POST   | Google OAuth authentication                 |
| `/auth/identity/email/send-otp`   | POST   | Send email OTP                              |
| `/auth/identity/email/verify-otp` | POST   | Verify email OTP                            |
| `/auth/identity/wallet/nonce`     | GET    | Get nonce for wallet auth                   |
| `/auth/identity/wallet`           | POST   | Wallet signature authentication             |
| `/vault`                          | GET    | Get vault data                              |
| `/vault/init`                     | POST   | Initialize vault (first-time setup)         |
| `/vault/config`                   | GET    | Get vault configuration                     |
| `/vault/export`                   | GET    | Generate vault export                       |
| `/vault/quota`                    | GET    | Get storage quota                           |
| `/ipfs/upload`                    | POST   | Upload encrypted file (multipart/form-data) |
| `/ipfs/unpin`                     | POST   | Unpin CID from IPFS                         |
| `/ipfs/:cid`                      | GET    | Fetch file by CID                           |
| `/ipns/publish`                   | POST   | Publish IPNS record                         |
| `/ipns/publish-batch`             | POST   | Batch publish IPNS records                  |
| `/ipns/resolve`                   | GET    | Resolve IPNS name to CID                    |
| `/device-approval/request`        | POST   | Request device approval                     |
| `/device-approval/pending`        | GET    | Get pending approvals                       |
| `/shares`                         | POST   | Create a share                              |
| `/shares/received`                | GET    | Get received shares                         |

## Development Patterns

### API Development Workflow

When working on `apps/api` code:

1. **After modifying API endpoints, DTOs, or controllers**, regenerate the API client:

   ```bash
   pnpm api:generate
   ```

2. **Always run `pnpm api:generate` before completing a feature** that touches the API.

3. **Commit the regenerated client files** (`apps/web/src/api/`) along with your API changes.

### File Upload Flow (Reference)

```typescript
// 1. Generate random file key
const fileKey = crypto.getRandomValues(new Uint8Array(32));
const fileIV = crypto.getRandomValues(new Uint8Array(12));

// 2. Encrypt file content
const encryptedFile = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: fileIV },
  await crypto.subtle.importKey('raw', fileKey, 'AES-GCM', false, ['encrypt']),
  fileContent
);

// 3. Wrap file key with user's public key (ECIES)
const encryptedFileKey = await eciesEncrypt(fileKey, userPublicKey);

// 4. Upload encrypted file to backend → IPFS → get CID
// POST /ipfs/upload (multipart/form-data with 'file' field)
const formData = new FormData();
formData.append('file', new Blob([encryptedFile]));
const { cid } = await api.post('/ipfs/upload', formData);
// NOTE: No fileName sent — the server never sees plaintext file names

// 5. Create per-file FileMetadata (own IPNS record)
// Contains: cid, fileKeyEncrypted, fileIv, size, etc.

// 6. Add FilePointer to folder metadata children
// Contains: type, nameEncrypted, nameIv, fileMetaIpnsName

// 7. Re-encrypt folder metadata and republish IPNS
await republishFolderIPNS(folderId, updatedMetadata);
```

### IPNS Publishing Pattern

Every write operation (create/rename/move/delete) must:

1. Update the in-memory folder metadata
2. Re-encrypt the entire metadata JSON with the folder key
3. Upload encrypted metadata to IPFS → get new CID
4. Publish IPNS record: `/ipns/k51...` → `/ipfs/<new CID>`

**Performance Note:** IPNS publishing is the bottleneck (~2s). Batch operations when possible.

## Common Pitfalls & Anti-Patterns

### Never Do This

1. **Store keys in plaintext localStorage** — use in-memory state only
2. **Log sensitive data** — no `console.log` of keys, decrypted content
3. **Send plaintext to server** — all file content and names must be encrypted client-side
4. **Send file names to server** — the server is zero-knowledge, it never sees plaintext names
5. **Use sync crypto in main thread** — use Web Workers for large files

### Correct Patterns

1. **Store keys in memory, clear on logout** (React context / Zustand)
2. **Use Web Workers for large file encryption**
3. **Use `Uint8Array` for all binary data**, not strings
4. **Use `camelCase` for API fields, `snake_case` for database columns**

## MVP Scope Boundaries (v1.0)

### In Scope

- Multi-method auth (email OTP, Google OAuth, magic link, external wallet)
- File upload/download (E2E encrypted)
- Folder operations (create/rename/move/delete)
- Web UI (React) + Desktop mount (macOS FUSE via Tauri v2)
- Multi-device sync (IPNS polling, ~30s latency)
- Vault export (data portability)
- TEE-based IPNS republishing (Phala Cloud)

### Out of Scope (defer to v1.1+)

- Billing/payments
- File versioning
- Search/indexing
- Mobile apps
- Linux/Windows desktop

## Testing

### Security Test Checklist

- [ ] Private key never logged (search logs for "privateKey", "ecdsa", "0x04")
- [ ] Private key never in localStorage/sessionStorage
- [ ] All file uploads: server receives ciphertext only
- [ ] All folder/file names: encrypted in metadata, never sent plaintext
- [ ] IPNS signature verification passes
- [ ] Wrong private key cannot decrypt vault

### Running Tests

```bash
pnpm test              # Unit tests (all workspaces)
pnpm test:e2e          # Playwright E2E (Playwright starts API/web automatically)
pnpm typecheck         # TypeScript type checking
```

## Verification with MCP Tools

### Playwright MCP for Application Testing

**ALWAYS attempt to verify application changes using Playwright MCP** when available.

**If Playwright MCP is not available:**

- Document what needs manual verification
- Provide step-by-step test instructions

### Pencil MCP for Design Work

For UI work, verify implementations against Pencil design files at `designs/*.pen`.

## Questions to Ask When Unclear

1. **Auth-related:** "Does this require Phase 1 (Web3Auth) or Phase 2 (CipherBox backend) authentication?"
2. **Encryption:** "Should this data be encrypted client-side before transmission?"
3. **Keys:** "Which key in the hierarchy (ECDSA private, root folder, subfolder, file) should be used here?"
4. **IPNS:** "Does this operation require republishing an IPNS entry?"
5. **Scope:** "Is this feature in v1.0 MVP scope, or should it be deferred to v1.1+?"

## Final Note

This project prioritizes **cryptographic correctness over convenience**. When in doubt, err on the side of more encryption, more validation, and stricter security.

**For detailed guidance:** See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for crypto design and [docs/METADATA_SCHEMAS.md](../docs/METADATA_SCHEMAS.md) for all metadata object schemas.
