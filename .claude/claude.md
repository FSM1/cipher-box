# CipherBox - Claude AI Rules

## Project Context

CipherBox is a **technology demonstrator** for privacy-first encrypted cloud storage using IPFS/IPNS and Web3Auth. It is not a commercial product.

## Documentation Structure

| Document | Purpose |
|----------|---------|
| `Documentation/PRD.md` | Product requirements, user journeys, scope |
| `Documentation/TECHNICAL_ARCHITECTURE.md` | Encryption, key hierarchy, system design |
| `Documentation/API_SPECIFICATION.md` | Backend endpoints, database schema |
| `Documentation/DATA_FLOWS.md` | Sequence diagrams, test vectors |
| `Documentation/CLIENT_SPECIFICATION.md` | Web UI, desktop app specs |

## Version Management

**Current Version:** 1.11.1

### Version Bump Rule

When modifying any documentation file in `Documentation/`, you MUST:

1. Increment the patch version (e.g., 1.7.0 → 1.7.1) for minor updates
2. Increment the minor version (e.g., 1.7.0 → 1.8.0) for new sections or significant changes
3. Update the `version` field in the YAML frontmatter of the modified file
4. Update the `last_updated` field to the current date
5. Update this file's "Current Version" to match

Example frontmatter update:
```yaml
---
version: 1.7.1  # Incremented from 1.7.0
last_updated: 2026-01-17  # Updated to current date
status: Active
ai_context: ...
---
```

## Terminology Standards

Always use consistent terminology:

| Correct | Avoid |
|---------|-------|
| `publicKey` | `pubkey`, `user_pubkey`, `ownerPublicKey` |
| `privateKey` | `privkey`, `user_private_key` |
| `rootFolderKey` | `rootKey`, `root_folder_key` |
| `ipnsName` | IPNS entry (for identifier) |
| `ipnsRecord` | IPNS entry (for data structure) |
| `folderKey` | `subfolderKey` (unless specifically for subfolder) |
| `fileKey` | `file_key` |
| `keyEpoch` | `epoch`, `key_epoch` |
| `encryptedIpnsPrivateKey` | `encrypted_ipns_key`, `ipns_key_encrypted` |
| `teePublicKey` | `tee_pubkey`, `TEE_public_key` |

## Critical Security Rules

1. **Never** suggest storing `privateKey` in localStorage/sessionStorage
2. **Never** suggest logging sensitive keys
3. **Never** suggest sending unencrypted keys to server
4. **Always** use ECIES for key wrapping
5. **Always** use AES-256-GCM for content encryption
6. The server NEVER has access to plaintext or unencrypted keys
7. **Always** encrypt `ipnsPrivateKey` with TEE public key before sending for republishing
8. TEE decrypts IPNS keys in hardware only, signs, and immediately discards

## Code Generation Guidelines

When generating code for CipherBox:

1. Use TypeScript for all JavaScript code
2. Use `Uint8Array` for binary data, not strings
3. Use Web Crypto API for browser encryption
4. Use camelCase for API fields, snake_case for database columns
5. Include proper error handling for crypto operations
6. Clear sensitive data from memory after use

## Architecture Decisions

- **Auth:** Web3Auth for key derivation, CipherBox backend for tokens
- **Storage:** IPFS via Pinata for files, IPNS for metadata (all relayed via CipherBox API)
- **Encryption:** Client-side only, server is zero-knowledge
- **Sync:** IPNS polling (30s interval), no push infrastructure
- **Desktop:** FUSE mount for transparent file access
- **TEE Republishing:** Phala Cloud (primary) / AWS Nitro (fallback) for automatic IPNS republishing every 3 hours
- **Key Epochs:** TEE public keys rotate with 4-week grace period for seamless migration

## Out of Scope (v1.0)

Do not implement or suggest implementations for:
- Billing/payments
- File versioning
- File/folder sharing
- Mobile apps
- Search/indexing
- Collaborative editing
- Team accounts
