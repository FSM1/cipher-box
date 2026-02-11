# Requirements: CipherBox

**Defined:** 2026-01-20
**Core Value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Authentication

- [x] **AUTH-01**: User can sign up with email and password via Web3Auth
- [x] **AUTH-02**: User can sign in with OAuth (Google, Apple, GitHub) via Web3Auth
- [x] **AUTH-03**: User can sign in with magic link (passwordless email) via Web3Auth
- [x] **AUTH-04**: User can sign in with external wallet (MetaMask, WalletConnect) via Web3Auth
- [x] **AUTH-05**: User session persists via access token (15min) and refresh token (7 days)
- [x] **AUTH-06**: User can link multiple auth methods to the same vault
- [x] **AUTH-07**: User can log out and all keys are cleared from memory

### Encryption

- [x] **CRYPT-01**: Files are encrypted client-side with AES-256-GCM before upload
- [x] **CRYPT-02**: File keys are wrapped with user's public key via ECIES (secp256k1)
- [x] **CRYPT-03**: Folder metadata is encrypted with folder key (AES-256-GCM)
- [x] **CRYPT-04**: IPNS records are signed client-side with Ed25519 keys
- [x] **CRYPT-05**: Private key exists only in client RAM, never persisted or transmitted
- [x] **CRYPT-06**: Each file uses unique random key and IV (no deduplication)

### File Operations

- [x] **FILE-01**: User can upload files up to 100MB
- [x] **FILE-02**: User can download and decrypt files
- [x] **FILE-03**: User can delete files (with IPFS unpin)
- [x] **FILE-04**: User can rename files
- [x] **FILE-05**: User can move files between folders
- [x] **FILE-06**: User can select multiple files for bulk upload
- [x] **FILE-07**: User can select multiple files for bulk delete

### Folder Operations

- [x] **FOLD-01**: User can create folders
- [x] **FOLD-02**: User can delete folders (recursive)
- [x] **FOLD-03**: User can nest folders up to 20 levels deep
- [x] **FOLD-04**: User can rename folders
- [x] **FOLD-05**: User can move folders between parent folders
- [x] **FOLD-06**: Each folder has its own IPNS keypair for metadata

### Backend API

- [x] **API-01**: Backend verifies Web3Auth JWT via JWKS endpoint
- [x] **API-02**: Backend issues and rotates access/refresh tokens
- [x] **API-03**: Backend relays encrypted blobs to Pinata (POST /ipfs/add)
- [x] **API-04**: Backend relays unpin requests to Pinata (POST /vault/unpin)
- [x] **API-05**: Backend relays pre-signed IPNS records (POST /ipns/publish)
- [x] **API-06**: Backend stores encrypted vault keys (rootFolderKey, ipnsPrivateKey)
- [x] **API-07**: Backend enforces 500 MiB storage quota per user
- [x] **API-08**: Backend returns TEE public keys on login

### Multi-Device Sync

- [x] **SYNC-01**: Changes sync across devices via IPNS polling (~30s interval)
- [ ] **SYNC-02**: Desktop app runs background sync daemon
- [x] **SYNC-03**: User sees loading state during IPNS resolution

### TEE Republishing

- [x] **TEE-01**: IPNS records are republished every 3 hours via Phala Cloud TEE
- [x] **TEE-02**: Client encrypts IPNS private key with TEE public key before sending
- [x] **TEE-03**: TEE decrypts key in hardware, signs record, immediately zeros memory
- [x] **TEE-04**: Backend schedules and tracks republish jobs
- [x] **TEE-05**: Key epochs rotate with 4-week grace period

### Web UI

- [ ] **WEB-01**: User sees login page with Web3Auth modal
- [ ] **WEB-02**: User sees file browser with folder tree sidebar
- [ ] **WEB-03**: User can drag-drop files to upload
- [ ] **WEB-04**: User can right-click for context menu (rename, delete, move)
- [ ] **WEB-05**: UI is responsive for mobile web access
- [ ] **WEB-06**: User can navigate folder hierarchy with breadcrumbs

### Desktop App (macOS)

- [ ] **DESK-01**: User can log in via Web3Auth in desktop app
- [ ] **DESK-02**: FUSE mount appears at ~/CipherVault after login
- [ ] **DESK-03**: User can open files directly in native apps (Preview, etc.)
- [ ] **DESK-04**: User can save files through FUSE mount
- [ ] **DESK-05**: App runs in system tray with status icon
- [ ] **DESK-06**: Refresh tokens stored securely in OS keychain
- [ ] **DESK-07**: Background sync runs while app is in tray

### Data Portability

- [x] **PORT-01**: User can export vault as JSON file
- [x] **PORT-02**: Export includes encrypted keys and folder structure
- [x] **PORT-03**: Export format is publicly documented

## Milestone 2 Requirements (Production v1.0)

Requirements for production release. Each maps to roadmap phases 12+.

### File Sharing

- [ ] **SHARE-01**: User can share a folder (read-only) with another CipherBox user via ECIES key re-wrapping
- [ ] **SHARE-02**: User can invite a recipient by email or public key
- [ ] **SHARE-03**: Recipient can accept or decline a share invitation
- [ ] **SHARE-04**: User can revoke a share (triggers folder key rotation for remaining recipients)
- [ ] **SHARE-05**: User can view "Shared with me" folders in file browser
- [ ] **SHARE-06**: User can generate a shareable link for a file (decryption key in URL fragment only)
- [ ] **SHARE-07**: Recipient can download shared file via link without a CipherBox account

### Search

- [ ] **SRCH-01**: User can search file names across all folders (client-side)
- [ ] **SRCH-02**: Search index is encrypted and persisted in IndexedDB
- [ ] **SRCH-03**: Search index updates incrementally when IPNS polling detects changes

### Multi-Factor Authentication

- [ ] **MFA-01**: User can enable MFA via Web3Auth settings
- [ ] **MFA-02**: User can configure device share as an MFA factor
- [ ] **MFA-03**: User can generate and store a backup recovery phrase
- [ ] **MFA-04**: MFA enrollment does not change the derived keypair (vault remains accessible)

### File Versioning

- [ ] **VER-01**: System automatically retains previous file versions on update (old CIDs kept pinned)
- [ ] **VER-02**: User can view version history for a file
- [ ] **VER-03**: User can restore a previous version of a file
- [ ] **VER-04**: Version retention policy enforced (max versions per file, configurable)
- [ ] **VER-05**: Version storage counted against user quota

### Advanced Sync

- [ ] **SYNC-04**: Client detects conflicts via IPNS sequence number mismatch before publishing
- [ ] **SYNC-05**: Offline write operations are queued locally and replayed on reconnect
- [ ] **SYNC-06**: Queued operations use idempotency keys to prevent duplicate application

### TEE Enhancements

- [ ] **TEE-06**: AWS Nitro enclave as fallback TEE provider for IPNS republishing

## Future Requirements (Milestone 3+)

Deferred to future milestones. Tracked but not in current roadmap.

### Sharing Enhancements

- **SHARE-08**: User can set password on shared link (PBKDF2 key derivation)
- **SHARE-09**: User can set expiration on shared link
- **SHARE-10**: Per-subfolder granular sharing (share subfolder without exposing parent)
- **SHARE-11**: Read-write shared folders (multi-writer IPNS)

### Additional MFA

- **MFA-05**: CipherBox-layer WebAuthn/Passkey for sensitive operations
- **MFA-06**: TOTP authenticator support
- **MFA-07**: Custom recovery phrase (beyond Web3Auth built-in)

### Advanced Sync Enhancements

- **SYNC-07**: Selective sync for desktop (choose folders to sync locally)
- **SYNC-08**: Conflict resolution UI with merge options

### Mobile Apps

- **MOB-01**: iOS app with full functionality
- **MOB-02**: Android app with full functionality
- **MOB-03**: Photo backup feature

### Additional Platforms

- **PLAT-01**: Linux desktop app
- **PLAT-02**: Windows desktop app

### Productivity Suite (Milestone 3)

- **DOCS-01**: Built-in document editor
- **DOCS-02**: Spreadsheet editor
- **DOCS-03**: Presentation editor
- **DOCS-04**: Secure document signing
- **TEAM-01**: Team accounts with org structure
- **TEAM-02**: Admin/member/viewer roles
- **BILL-01**: Billing integration (Stripe or crypto)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature                    | Reason                                                         |
| -------------------------- | -------------------------------------------------------------- |
| Read-write shared folders  | Multi-writer IPNS unsolved; no competitor has solved it either |
| Full-text content search   | Encrypted index leaks access patterns; defer to research spike |
| CRDTs / automatic merging  | Overkill for metadata-blob sync; simple conflict detection     |
| Billing/payments           | Deferred to Milestone 3                                        |
| Docs/sheets/slides editors | Deferred to Milestone 3                                        |
| Team accounts              | Deferred to Milestone 3                                        |
| Collaborative editing      | Real-time sync complexity, v3.0+                               |
| Mobile apps                | Platform expansion, Milestone 3+                               |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase    | Status   |
| ----------- | -------- | -------- |
| AUTH-01     | Phase 2  | Complete |
| AUTH-02     | Phase 2  | Complete |
| AUTH-03     | Phase 2  | Complete |
| AUTH-04     | Phase 2  | Complete |
| AUTH-05     | Phase 2  | Complete |
| AUTH-06     | Phase 2  | Complete |
| AUTH-07     | Phase 2  | Complete |
| CRYPT-01    | Phase 3  | Complete |
| CRYPT-02    | Phase 3  | Complete |
| CRYPT-03    | Phase 3  | Complete |
| CRYPT-04    | Phase 3  | Complete |
| CRYPT-05    | Phase 3  | Complete |
| CRYPT-06    | Phase 3  | Complete |
| FILE-01     | Phase 4  | Complete |
| FILE-02     | Phase 4  | Complete |
| FILE-03     | Phase 4  | Complete |
| FILE-04     | Phase 5  | Complete |
| FILE-05     | Phase 5  | Complete |
| FILE-06     | Phase 4  | Complete |
| FILE-07     | Phase 4  | Complete |
| FOLD-01     | Phase 5  | Complete |
| FOLD-02     | Phase 5  | Complete |
| FOLD-03     | Phase 5  | Complete |
| FOLD-04     | Phase 5  | Complete |
| FOLD-05     | Phase 5  | Complete |
| FOLD-06     | Phase 5  | Complete |
| API-01      | Phase 2  | Complete |
| API-02      | Phase 2  | Complete |
| API-03      | Phase 4  | Complete |
| API-04      | Phase 4  | Complete |
| API-05      | Phase 5  | Complete |
| API-06      | Phase 4  | Complete |
| API-07      | Phase 4  | Complete |
| API-08      | Phase 8  | Complete |
| SYNC-01     | Phase 7  | Complete |
| SYNC-02     | Phase 9  | Pending  |
| SYNC-03     | Phase 7  | Complete |
| TEE-01      | Phase 8  | Complete |
| TEE-02      | Phase 8  | Complete |
| TEE-03      | Phase 8  | Complete |
| TEE-04      | Phase 8  | Complete |
| TEE-05      | Phase 8  | Complete |
| WEB-01      | Phase 6  | Pending  |
| WEB-02      | Phase 6  | Pending  |
| WEB-03      | Phase 6  | Pending  |
| WEB-04      | Phase 6  | Pending  |
| WEB-05      | Phase 6  | Pending  |
| WEB-06      | Phase 6  | Pending  |
| DESK-01     | Phase 9  | Pending  |
| DESK-02     | Phase 9  | Pending  |
| DESK-03     | Phase 9  | Pending  |
| DESK-04     | Phase 9  | Pending  |
| DESK-05     | Phase 9  | Pending  |
| DESK-06     | Phase 9  | Pending  |
| DESK-07     | Phase 9  | Pending  |
| PORT-01     | Phase 10 | Complete |
| PORT-02     | Phase 10 | Complete |
| PORT-03     | Phase 10 | Complete |

**Milestone 1 Coverage:**

- M1 requirements: 52 total
- Mapped to phases: 52
- Unmapped: 0

**Milestone 2 Coverage:**

- M2 requirements: 24 total
- Mapped to phases: TBD (roadmap creation)
- Unmapped: 24

---

Requirements defined: 2026-01-20
Last updated: 2026-02-11 after Milestone 2 requirements definition
