# CipherBox - Claude AI Rules

## Project Context

CipherBox is a **technology demonstrator** for privacy-first encrypted cloud storage using IPFS/IPNS and Web3Auth. It is not a commercial product.

## Documentation Structure

| Document | Purpose |
|----------|---------|
| `Preliminary/Documentation/PRD.md` | Product requirements, user journeys, scope |
| `Preliminary/Documentation/TECHNICAL_ARCHITECTURE.md` | Encryption, key hierarchy, system design |
| `Preliminary/Documentation/API_SPECIFICATION.md` | Backend endpoints, database schema |
| `Preliminary/Documentation/DATA_FLOWS.md` | Sequence diagrams, test vectors |
| `Preliminary/Documentation/CLIENT_SPECIFICATION.md` | Web UI, desktop app specs |
| `Preliminary/Documentation/IMPLEMENTATION_ROADMAP.md` | Week-by-week development plan |

## Finalized Specifications

**Current Version:** 1.10.0
**Status:** Finalized (2026-01-20)

### ⚠️ IMPORTANT: Do Not Edit Preliminary/Documentation Files

All files in `Preliminary/Documentation/` are **FINALIZED** specifications (version 1.10.0, status: Finalized). These documents represent the agreed-upon design and should **NOT** be modified.

**If you need to make changes:**
- New implementation documentation should be created in a separate location
- Working notes and updates belong in `.planning/` or project-specific directories
- Do not modify version numbers or content in `Preliminary/Documentation/`

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

## Critical Security Rules

1. **Never** suggest storing `privateKey` in localStorage/sessionStorage
2. **Never** suggest logging sensitive keys
3. **Never** suggest sending unencrypted keys to server
4. **Always** use ECIES for key wrapping
5. **Always** use AES-256-GCM for content encryption
6. The server NEVER has access to plaintext or unencrypted keys

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

## Out of Scope (v1.0)

Do not implement or suggest implementations for:
- Billing/payments
- File versioning
- File/folder sharing
- Mobile apps
- Search/indexing
- Collaborative editing
- Team accounts
