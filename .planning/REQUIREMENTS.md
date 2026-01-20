# Requirements: CipherBox

**Defined:** 2026-01-20
**Core Value:** Zero-knowledge privacy - files encrypted client-side, server never sees plaintext

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Authentication

- [ ] **AUTH-01**: User can sign up with email and password via Web3Auth
- [ ] **AUTH-02**: User can sign in with OAuth (Google, Apple, GitHub) via Web3Auth
- [ ] **AUTH-03**: User can sign in with magic link (passwordless email) via Web3Auth
- [ ] **AUTH-04**: User can sign in with external wallet (MetaMask, WalletConnect) via Web3Auth
- [ ] **AUTH-05**: User session persists via access token (15min) and refresh token (7 days)
- [ ] **AUTH-06**: User can link multiple auth methods to the same vault
- [ ] **AUTH-07**: User can log out and all keys are cleared from memory

### Encryption

- [ ] **CRYPT-01**: Files are encrypted client-side with AES-256-GCM before upload
- [ ] **CRYPT-02**: File keys are wrapped with user's public key via ECIES (secp256k1)
- [ ] **CRYPT-03**: Folder metadata is encrypted with folder key (AES-256-GCM)
- [ ] **CRYPT-04**: IPNS records are signed client-side with Ed25519 keys
- [ ] **CRYPT-05**: Private key exists only in client RAM, never persisted or transmitted
- [ ] **CRYPT-06**: Each file uses unique random key and IV (no deduplication)

### File Operations

- [ ] **FILE-01**: User can upload files up to 100MB
- [ ] **FILE-02**: User can download and decrypt files
- [ ] **FILE-03**: User can delete files (with IPFS unpin)
- [ ] **FILE-04**: User can rename files
- [ ] **FILE-05**: User can move files between folders
- [ ] **FILE-06**: User can select multiple files for bulk upload
- [ ] **FILE-07**: User can select multiple files for bulk delete

### Folder Operations

- [ ] **FOLD-01**: User can create folders
- [ ] **FOLD-02**: User can delete folders (recursive)
- [ ] **FOLD-03**: User can nest folders up to 20 levels deep
- [ ] **FOLD-04**: User can rename folders
- [ ] **FOLD-05**: User can move folders between parent folders
- [ ] **FOLD-06**: Each folder has its own IPNS keypair for metadata

### Backend API

- [ ] **API-01**: Backend verifies Web3Auth JWT via JWKS endpoint
- [ ] **API-02**: Backend issues and rotates access/refresh tokens
- [ ] **API-03**: Backend relays encrypted blobs to Pinata (POST /ipfs/add)
- [ ] **API-04**: Backend relays unpin requests to Pinata (POST /vault/unpin)
- [ ] **API-05**: Backend relays pre-signed IPNS records (POST /ipns/publish)
- [ ] **API-06**: Backend stores encrypted vault keys (rootFolderKey, ipnsPrivateKey)
- [ ] **API-07**: Backend enforces 500 MiB storage quota per user
- [ ] **API-08**: Backend returns TEE public keys on login

### Multi-Device Sync

- [ ] **SYNC-01**: Changes sync across devices via IPNS polling (~30s interval)
- [ ] **SYNC-02**: Desktop app runs background sync daemon
- [ ] **SYNC-03**: User sees loading state during IPNS resolution

### TEE Republishing

- [ ] **TEE-01**: IPNS records are republished every 3 hours via Phala Cloud TEE
- [ ] **TEE-02**: Client encrypts IPNS private key with TEE public key before sending
- [ ] **TEE-03**: TEE decrypts key in hardware, signs record, immediately zeros memory
- [ ] **TEE-04**: Backend schedules and tracks republish jobs
- [ ] **TEE-05**: Key epochs rotate with 4-week grace period

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

- [ ] **PORT-01**: User can export vault as JSON file
- [ ] **PORT-02**: Export includes encrypted keys and folder structure
- [ ] **PORT-03**: Export format is publicly documented

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### File Sharing

- **SHARE-01**: User can generate shareable link for file
- **SHARE-02**: User can set password on shared link
- **SHARE-03**: User can set expiration on shared link
- **SHARE-04**: Recipient can download without account

### File Versioning

- **VER-01**: System keeps previous versions of files
- **VER-02**: User can view version history
- **VER-03**: User can restore previous version

### Mobile Apps

- **MOB-01**: iOS app with full functionality
- **MOB-02**: Android app with full functionality
- **MOB-03**: Photo backup feature

### Search

- **SEARCH-01**: User can search file names
- **SEARCH-02**: Search index is encrypted client-side

### Advanced Sync

- **SYNC-04**: Conflict detection with user resolution
- **SYNC-05**: Offline write queue with retry on reconnect
- **SYNC-06**: Selective sync (choose folders to sync locally)

### TEE Enhancements

- **TEE-06**: AWS Nitro as fallback TEE provider
- **TEE-07**: Multi-epoch support for seamless migration

### Additional Platforms

- **PLAT-01**: Linux desktop app
- **PLAT-02**: Windows desktop app

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Billing/payments | Tech demo focus, defer to v1.1+ |
| AES-256-CTR streaming | Implementation complexity, defer to v1.1 |
| File preview (images, PDFs) | UX enhancement, not core |
| Soft delete / recycle bin | Complexity, defer to v2 |
| Independent recovery | Requires offline tooling |
| Collaborative editing | Real-time sync complexity, v3.0 |
| Team accounts | Permission management complexity, v3.0 |
| Storage indicator in UI | Nice-to-have, not critical |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| AUTH-01 | TBD | Pending |
| AUTH-02 | TBD | Pending |
| AUTH-03 | TBD | Pending |
| AUTH-04 | TBD | Pending |
| AUTH-05 | TBD | Pending |
| AUTH-06 | TBD | Pending |
| AUTH-07 | TBD | Pending |
| CRYPT-01 | TBD | Pending |
| CRYPT-02 | TBD | Pending |
| CRYPT-03 | TBD | Pending |
| CRYPT-04 | TBD | Pending |
| CRYPT-05 | TBD | Pending |
| CRYPT-06 | TBD | Pending |
| FILE-01 | TBD | Pending |
| FILE-02 | TBD | Pending |
| FILE-03 | TBD | Pending |
| FILE-04 | TBD | Pending |
| FILE-05 | TBD | Pending |
| FILE-06 | TBD | Pending |
| FILE-07 | TBD | Pending |
| FOLD-01 | TBD | Pending |
| FOLD-02 | TBD | Pending |
| FOLD-03 | TBD | Pending |
| FOLD-04 | TBD | Pending |
| FOLD-05 | TBD | Pending |
| FOLD-06 | TBD | Pending |
| API-01 | TBD | Pending |
| API-02 | TBD | Pending |
| API-03 | TBD | Pending |
| API-04 | TBD | Pending |
| API-05 | TBD | Pending |
| API-06 | TBD | Pending |
| API-07 | TBD | Pending |
| API-08 | TBD | Pending |
| SYNC-01 | TBD | Pending |
| SYNC-02 | TBD | Pending |
| SYNC-03 | TBD | Pending |
| TEE-01 | TBD | Pending |
| TEE-02 | TBD | Pending |
| TEE-03 | TBD | Pending |
| TEE-04 | TBD | Pending |
| TEE-05 | TBD | Pending |
| WEB-01 | TBD | Pending |
| WEB-02 | TBD | Pending |
| WEB-03 | TBD | Pending |
| WEB-04 | TBD | Pending |
| WEB-05 | TBD | Pending |
| WEB-06 | TBD | Pending |
| DESK-01 | TBD | Pending |
| DESK-02 | TBD | Pending |
| DESK-03 | TBD | Pending |
| DESK-04 | TBD | Pending |
| DESK-05 | TBD | Pending |
| DESK-06 | TBD | Pending |
| DESK-07 | TBD | Pending |
| PORT-01 | TBD | Pending |
| PORT-02 | TBD | Pending |
| PORT-03 | TBD | Pending |

**Coverage:**
- v1 requirements: 52 total
- Mapped to phases: 0
- Unmapped: 52

---
*Requirements defined: 2026-01-20*
*Last updated: 2026-01-20 after initial definition*
