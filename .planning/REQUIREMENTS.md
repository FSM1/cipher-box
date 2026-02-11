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
- [x] **SYNC-02**: Desktop app runs background sync daemon
- [x] **SYNC-03**: User sees loading state during IPNS resolution

### TEE Republishing

- [x] **TEE-01**: IPNS records are republished every 3 hours via Phala Cloud TEE
- [x] **TEE-02**: Client encrypts IPNS private key with TEE public key before sending
- [x] **TEE-03**: TEE decrypts key in hardware, signs record, immediately zeros memory
- [x] **TEE-04**: Backend schedules and tracks republish jobs
- [x] **TEE-05**: Key epochs rotate with 4-week grace period

### Web UI

- [x] **WEB-01**: User sees login page with Web3Auth modal
- [x] **WEB-02**: User sees file browser with folder tree sidebar
- [x] **WEB-03**: User can drag-drop files to upload
- [x] **WEB-04**: User can right-click for context menu (rename, delete, move)
- [x] **WEB-05**: UI is responsive for mobile web access
- [x] **WEB-06**: User can navigate folder hierarchy with breadcrumbs

### Desktop App (macOS)

- [x] **DESK-01**: User can log in via Web3Auth in desktop app
- [x] **DESK-02**: FUSE mount appears at ~/CipherBox after login
- [x] **DESK-03**: User can open files directly in native apps (Preview, etc.)
- [x] **DESK-04**: User can save files through FUSE mount
- [x] **DESK-05**: App runs in system tray with status icon
- [x] **DESK-06**: Refresh tokens stored securely in OS keychain
- [x] **DESK-07**: Background sync runs while app is in tray

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

### Cross-Platform Desktop

- [ ] **PLAT-01**: Linux desktop app (Tauri + AppImage/deb, FUSE mount via libfuse)
- [ ] **PLAT-02**: Windows desktop app (Tauri + MSI/NSIS, virtual drive via WinFsp/Dokany)

## Milestone 3 Requirements (Encrypted Productivity Suite)

Requirements for productivity suite. Each maps to roadmap phases 18+.
See `.planning/milestones/m3/REQUIREMENTS.md` for full details including deferred items and out-of-scope.

### Billing

- [ ] **BILL-01**: User can subscribe to a paid plan (Pro or Team) via Stripe Checkout
- [ ] **BILL-02**: User can manage their subscription (upgrade, downgrade, cancel) via Stripe Customer Portal
- [ ] **BILL-03**: Subscription lifecycle is driven by Stripe webhooks with idempotent event processing and signature verification
- [ ] **BILL-04**: Free tier enforces existing 500 MiB storage limit; Pro tier increases to 50 GiB; Team tier provides 200 GiB shared
- [ ] **BILL-05**: User can view subscription status, current tier, and billing history in settings
- [ ] **BILL-06**: Failed payments trigger a grace period before access downgrade (Stripe Smart Retries)
- [ ] **BILL-07**: User can pay with cryptocurrency via NOWPayments invoice flow (BTC, ETH, USDC, and 350+ coins)
- [ ] **BILL-08**: Periodic reconciliation job compares CipherBox subscription state with Stripe and fixes discrepancies

### Team Accounts

- [ ] **TEAM-01**: User can create a team (organization) and become its owner
- [ ] **TEAM-02**: Owner/admin can invite members by email or public key; invitee receives an invitation they can accept or decline
- [ ] **TEAM-03**: Team supports role-based permissions: owner, admin, editor, viewer -- enforced at both API level (CASL guards) and client-side (UI gating)
- [ ] **TEAM-04**: Team has a Per-Team Key (PTK) that is ECIES-wrapped to each member's publicKey; server never stores plaintext PTK
- [ ] **TEAM-05**: Team vault is initialized with team-scoped IPNS keypair and root folder key encrypted with the PTK
- [ ] **TEAM-06**: User can switch between personal vault and team vaults in the sidebar
- [ ] **TEAM-07**: Owner/admin can remove a member, which triggers PTK rotation and re-wrapping for all remaining members
- [ ] **TEAM-08**: Team member limits are enforced by subscription tier (Team tier: 25 members)
- [ ] **TEAM-09**: Team admin can view aggregate storage usage for the team

### Document Editors

- [ ] **EDIT-01**: User can create and edit rich text documents in-browser using TipTap with basic formatting (bold, italic, headings, lists, links, tables)
- [ ] **EDIT-02**: Documents use the decrypt-edit-encrypt pipeline: fetch encrypted blob from IPFS, decrypt client-side, load in editor, re-encrypt on save, upload new CID
- [ ] **EDIT-03**: Autosave with debounced save queue (60s after last edit); only one save in-flight at a time (mutual exclusion); dirty indicator shown when unsaved changes exist
- [ ] **EDIT-04**: Folder metadata extended with editorType and editorFormat fields (stored encrypted, server never sees them)
- [ ] **EDIT-05**: User can create and edit spreadsheets in-browser using Univer (single-user editing only, no real-time collaboration)
- [ ] **EDIT-06**: User can export documents to PDF and Markdown; user can export spreadsheets to XLSX and CSV (all client-side)
- [ ] **EDIT-07**: Advisory document locking for team contexts -- when a user opens a team document for editing, other team members see "Currently being edited by [user]" and can choose read-only or force-edit
- [ ] **EDIT-08**: Unsaved changes are buffered to IndexedDB via y-indexeddb; beforeunload handler warns about unsaved changes
- [ ] **EDIT-09**: Encryption operations for large documents run in a Web Worker to avoid blocking the main thread

### Document Signing

- [ ] **SIGN-01**: User can sign any file or document with their secp256k1 privateKey via ECDSA (client-side, Web Crypto API); signature computed over SHA-256 hash of plaintext content
- [ ] **SIGN-02**: Any user with folder access can verify a signature given the signer's publicKey and the document content
- [ ] **SIGN-03**: User can draw or type a visual signature via react-signature-canvas; visual signature is stored alongside the cryptographic signature
- [ ] **SIGN-04**: Multi-party signing workflow: user can request signatures from other CipherBox users; signature status tracked as pending/partial/complete
- [ ] **SIGN-05**: Signed document metadata (signerPublicKey, signatureHex, contentHash, signedAt, signedCid) stored in encrypted folder metadata alongside the file entry
- [ ] **SIGN-06**: User can export a signed PDF with embedded digital signature via LibPDF (client-side)

## Future Requirements (Milestone 4+)

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

### Real-Time Collaboration (Milestone 4)

- **COLLAB-01**: Real-time collaborative editing via encrypted CRDT relay (Yjs + Hocuspocus with encrypted WebSocket transport)
- **COLLAB-02**: Cursor and selection awareness for real-time co-editing
- **SHEET-COLLAB-01**: Spreadsheet real-time collaboration (requires custom Yjs adapter for Univer OT)

### Presentation Editor (Milestone 4)

- **SLIDES-01**: In-browser presentation/slide editing

### Advanced Signing (Milestone 4+)

- **SIGN-07**: Blockchain-timestamped signing (anchor document hash on-chain)
- **SIGN-08**: Zero-knowledge signing verification (ZK-SNARK circuits)

### Advanced Team Features (Milestone 4+)

- **TEAM-10**: Zero-knowledge organization metadata (encrypted org structure on IPFS)
- **TEAM-11**: Cryptographic role enforcement (separate read/write key hierarchies)
- **TEAM-12**: SSO/LDAP integration
- **TEAM-13**: Enterprise policy templates
- **TEAM-14**: Decentralized team key recovery via Shamir's Secret Sharing

### Advanced Billing (Milestone 4+)

- **BILL-09**: Pay-per-use metered storage billing
- **BILL-10**: Stablecoin subscription payments via Stripe

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature                         | Reason                                                          |
| ------------------------------- | --------------------------------------------------------------- |
| Read-write shared folders       | Multi-writer IPNS unsolved; no competitor has solved it either  |
| Full-text content search        | Encrypted index leaks access patterns; defer to research spike  |
| Real-time collaborative editing | Encrypted CRDT relay is highest-risk item; deferred to M4       |
| Spreadsheet collaboration       | Univer uses OT, incompatible with ZK without custom Yjs adapter |
| Slide/presentation editing      | No mature open-source WYSIWYG editor exists; deferred to M4     |
| Full Google Docs feature parity | Years of effort, not a tech demo goal                           |
| eIDAS/QES compliance            | Requires certified CA, hardware tokens, legal framework         |
| Server-side document rendering  | Breaks zero-knowledge guarantee                                 |
| AI writing assistance           | Requires server access to plaintext                             |
| SSO/LDAP                        | Enterprise scope, not demo territory                            |
| Mobile apps                     | Platform expansion, Milestone 4+                                |

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
| SYNC-02     | Phase 9  | Complete |
| SYNC-03     | Phase 7  | Complete |
| TEE-01      | Phase 8  | Complete |
| TEE-02      | Phase 8  | Complete |
| TEE-03      | Phase 8  | Complete |
| TEE-04      | Phase 8  | Complete |
| TEE-05      | Phase 8  | Complete |
| WEB-01      | Phase 6  | Complete |
| WEB-02      | Phase 6  | Complete |
| WEB-03      | Phase 6  | Complete |
| WEB-04      | Phase 6  | Complete |
| WEB-05      | Phase 6  | Complete |
| WEB-06      | Phase 6  | Complete |
| DESK-01     | Phase 9  | Complete |
| DESK-02     | Phase 9  | Complete |
| DESK-03     | Phase 9  | Complete |
| DESK-04     | Phase 9  | Complete |
| DESK-05     | Phase 9  | Complete |
| DESK-06     | Phase 9  | Complete |
| DESK-07     | Phase 9  | Complete |
| PORT-01     | Phase 10 | Complete |
| PORT-02     | Phase 10 | Complete |
| PORT-03     | Phase 10 | Complete |
| MFA-01      | Phase 12 | Pending  |
| MFA-02      | Phase 12 | Pending  |
| MFA-03      | Phase 12 | Pending  |
| MFA-04      | Phase 12 | Pending  |
| VER-01      | Phase 13 | Pending  |
| VER-02      | Phase 13 | Pending  |
| VER-03      | Phase 13 | Pending  |
| VER-04      | Phase 13 | Pending  |
| VER-05      | Phase 13 | Pending  |
| SHARE-01    | Phase 14 | Pending  |
| SHARE-02    | Phase 14 | Pending  |
| SHARE-03    | Phase 14 | Pending  |
| SHARE-04    | Phase 14 | Pending  |
| SHARE-05    | Phase 14 | Pending  |
| SHARE-06    | Phase 15 | Pending  |
| SHARE-07    | Phase 15 | Pending  |
| SRCH-01     | Phase 15 | Pending  |
| SRCH-02     | Phase 15 | Pending  |
| SRCH-03     | Phase 15 | Pending  |
| SYNC-04     | Phase 16 | Pending  |
| SYNC-05     | Phase 16 | Pending  |
| SYNC-06     | Phase 16 | Pending  |
| TEE-06      | Phase 17 | Pending  |
| PLAT-01     | Phase 11 | Pending  |
| PLAT-02     | Phase 11 | Pending  |
| BILL-01     | Phase 18 | Pending  |
| BILL-02     | Phase 18 | Pending  |
| BILL-03     | Phase 18 | Pending  |
| BILL-04     | Phase 18 | Pending  |
| BILL-05     | Phase 18 | Pending  |
| BILL-06     | Phase 18 | Pending  |
| BILL-07     | Phase 18 | Pending  |
| BILL-08     | Phase 18 | Pending  |
| TEAM-01     | Phase 19 | Pending  |
| TEAM-02     | Phase 19 | Pending  |
| TEAM-03     | Phase 19 | Pending  |
| TEAM-04     | Phase 19 | Pending  |
| TEAM-05     | Phase 19 | Pending  |
| TEAM-06     | Phase 19 | Pending  |
| TEAM-07     | Phase 19 | Pending  |
| TEAM-08     | Phase 19 | Pending  |
| TEAM-09     | Phase 19 | Pending  |
| EDIT-01     | Phase 20 | Pending  |
| EDIT-02     | Phase 20 | Pending  |
| EDIT-03     | Phase 20 | Pending  |
| EDIT-04     | Phase 20 | Pending  |
| EDIT-05     | Phase 20 | Pending  |
| EDIT-06     | Phase 20 | Pending  |
| EDIT-07     | Phase 20 | Pending  |
| EDIT-08     | Phase 20 | Pending  |
| EDIT-09     | Phase 20 | Pending  |
| SIGN-01     | Phase 21 | Pending  |
| SIGN-02     | Phase 21 | Pending  |
| SIGN-03     | Phase 21 | Pending  |
| SIGN-04     | Phase 21 | Pending  |
| SIGN-05     | Phase 21 | Pending  |
| SIGN-06     | Phase 21 | Pending  |

**Milestone 1 Coverage:**

- M1 requirements: 52 total
- Mapped to phases: 52
- Unmapped: 0

**Milestone 2 Coverage:**

- M2 requirements: 25 total
- Mapped to phases: 25
- Unmapped: 0

**Milestone 3 Coverage:**

- M3 requirements: 32 total
- Mapped to phases: 32
- Unmapped: 0

---

Requirements defined: 2026-01-20
Last updated: 2026-02-11 after Milestone 3 roadmap creation (M3 phase mappings added)
