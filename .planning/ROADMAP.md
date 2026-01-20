# Roadmap: CipherBox v1.0

## Overview

CipherBox v1.0 delivers zero-knowledge encrypted cloud storage with IPFS/IPNS and Web3Auth. The build follows a full-stack vertical approach: each phase delivers testable end-to-end functionality. We start with infrastructure, add authentication, build encryption and storage layers, create the web UI, enable multi-device sync via IPNS, integrate TEE for auto-republishing, deploy the macOS desktop client with FUSE mount, and finish with data portability and polish.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Project scaffolding, CI/CD, development environment
- [x] **Phase 2: Authentication** - Web3Auth integration with backend token management
- [x] **Phase 3: Core Encryption** - Shared crypto module and vault initialization
- [ ] **Phase 4: File Storage** - Upload/download encrypted files via IPFS relay
- [ ] **Phase 5: Folder System** - IPNS metadata, folder hierarchy, and operations
- [ ] **Phase 6: File Browser UI** - Web interface for file management
- [ ] **Phase 7: Multi-Device Sync** - IPNS polling and sync state management
- [ ] **Phase 8: TEE Integration** - Auto-republishing via Phala Cloud
- [ ] **Phase 9: Desktop Client** - Tauri app with FUSE mount for macOS
- [ ] **Phase 10: Data Portability** - Vault export and documentation
- [ ] **Phase 11: Security Enhancements** - Web3Auth MFA (post-v1.0)

## Phase Details

### Phase 1: Foundation

**Goal**: Infrastructure exists for development and deployment
**Depends on**: Nothing (first phase)
**Requirements**: None (infrastructure-only phase)
**Success Criteria** (what must be TRUE):

1. NestJS backend scaffold runs with PostgreSQL connection
2. React frontend scaffold runs with Vite dev server
3. CI/CD pipeline runs tests and linting on push
4. Local development environment has Pinata sandbox access
   **Plans**: 3 plans

Plans:

- [x] 01-01-PLAN.md — pnpm workspace + NestJS backend + health endpoint
- [x] 01-02-PLAN.md — React 18 frontend with Vite and routing
- [x] 01-03-PLAN.md — CI/CD pipeline + Docker Compose + linting/formatting

### Phase 2: Authentication

**Goal**: Users can securely sign in and get tokens for API access
**Depends on**: Phase 1
**Requirements**: AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-07, API-01, API-02
**Success Criteria** (what must be TRUE):

1. User can sign up with email/password and receive tokens
2. User can sign in with OAuth (Google, Apple, GitHub) and receive tokens
3. User can sign in with magic link and receive tokens
4. User can sign in with external wallet (MetaMask) and receive tokens
5. User session persists via refresh tokens (access token refresh works)
6. User can link multiple auth methods to the same vault (via Web3Auth grouped connections - no custom implementation needed)
7. User can log out and all keys are cleared from memory
8. External wallet users can authenticate via signature-derived keys (ADR-001)
   **Plans**: 4 plans

Plans:

- [x] 02-01-PLAN.md — Backend auth module with entities, JWT verification, and endpoints
- [x] 02-02-PLAN.md — Web3Auth modal integration with auth state management
- [x] 02-03-PLAN.md — Complete login/logout flow with HTTP-only cookie tokens
- [x] 02-04-PLAN.md — Account linking and settings page

### Phase 3: Core Encryption

**Goal**: Shared crypto module works for all encryption operations
**Depends on**: Phase 2
**Requirements**: CRYPT-01, CRYPT-02, CRYPT-03, CRYPT-04, CRYPT-05, CRYPT-06
**Success Criteria** (what must be TRUE):

1. Files encrypt/decrypt correctly with AES-256-GCM (test vectors pass)
2. Keys wrap/unwrap correctly with ECIES secp256k1 (cross-platform compatible)
3. Ed25519 keypairs generate and sign IPNS records correctly
4. Private key exists only in RAM and never persists to storage
5. Each file uses unique random key and IV (no nonce reuse)
   **Plans**: 3 plans

Plans:

- [x] 03-01-PLAN.md — AES-256-GCM and ECIES encryption primitives
- [x] 03-02-PLAN.md — Ed25519 IPNS signing and key generation
- [x] 03-03-PLAN.md — Vault initialization and key management

### Phase 4: File Storage

**Goal**: Users can upload and download encrypted files
**Depends on**: Phase 3
**Requirements**: FILE-01, FILE-02, FILE-03, FILE-06, FILE-07, API-03, API-04, API-06, API-07
**Success Criteria** (what must be TRUE):

1. User can upload file up to 100MB, file appears as encrypted blob on IPFS
2. User can download file and decrypt it to original content
3. User can delete file and IPFS blob is unpinned
4. User can bulk upload multiple files
5. User can bulk delete multiple files
6. Storage quota enforces 500 MiB limit with clear error on exceed
   **Plans**: TBD

Plans:

- [ ] 04-01: Backend IPFS relay endpoints (add, unpin)
- [ ] 04-02: Backend vault and storage quota management
- [ ] 04-03: Frontend file upload with encryption
- [ ] 04-04: Frontend file download with decryption

### Phase 5: Folder System

**Goal**: Users can organize files in encrypted folder hierarchy
**Depends on**: Phase 4
**Requirements**: FOLD-01, FOLD-02, FOLD-03, FOLD-04, FOLD-05, FOLD-06, FILE-04, FILE-05, API-05
**Success Criteria** (what must be TRUE):

1. User can create folders and they persist across sessions
2. User can delete folders and all contents are recursively removed
3. User can nest folders up to 20 levels deep
4. User can rename files and folders
5. User can move files and folders between parent folders
6. Each folder has its own IPNS keypair for metadata
   **Plans**: TBD

Plans:

- [ ] 05-01: IPNS relay endpoints and metadata structure
- [ ] 05-02: Folder CRUD operations with encrypted metadata
- [ ] 05-03: File rename and move operations
- [ ] 05-04: Folder tree traversal and hierarchy management

### Phase 6: File Browser UI

**Goal**: Web interface provides complete file management experience
**Depends on**: Phase 5
**Requirements**: WEB-01, WEB-02, WEB-03, WEB-04, WEB-05, WEB-06
**Success Criteria** (what must be TRUE):

1. User sees login page with Web3Auth modal on first visit
2. User sees file browser with folder tree sidebar after login
3. User can drag-drop files to upload to current folder
4. User can right-click for context menu with rename, delete, move options
5. UI is responsive and usable on mobile web
6. User can navigate folder hierarchy with breadcrumbs
   **Plans**: TBD

Plans:

- [ ] 06-01: Login page with Web3Auth modal
- [ ] 06-02: File browser layout with folder tree sidebar
- [ ] 06-03: Drag-drop upload and context menus
- [ ] 06-04: Responsive design and breadcrumb navigation

### Phase 7: Multi-Device Sync

**Goal**: Changes sync across devices via IPNS polling
**Depends on**: Phase 6
**Requirements**: SYNC-01, SYNC-02, SYNC-03
**Success Criteria** (what must be TRUE):

1. Changes made on one device appear on another within ~30 seconds
2. User sees loading state during IPNS resolution
3. Desktop sync daemon runs in background while app is open
   **Plans**: TBD

Plans:

- [ ] 07-01: IPNS polling infrastructure with 30s interval
- [ ] 07-02: Sync state management and optimistic UI
- [ ] 07-03: Loading states and conflict handling

### Phase 8: TEE Integration

**Goal**: IPNS records auto-republish via TEE without user online
**Depends on**: Phase 7
**Requirements**: TEE-01, TEE-02, TEE-03, TEE-04, TEE-05, API-08
**Success Criteria** (what must be TRUE):

1. IPNS records republish every 3 hours via Phala Cloud TEE
2. Client encrypts IPNS private key with TEE public key before sending
3. TEE decrypts key in hardware, signs, and immediately zeros memory
4. Backend schedules and tracks republish jobs with monitoring
5. Key epochs rotate with 4-week grace period (old keys still work)
   **Plans**: TBD

Plans:

- [ ] 08-01: TEE key state tables and epoch management
- [ ] 08-02: Republish scheduling and cron jobs
- [ ] 08-03: Client TEE key encryption on publish
- [ ] 08-04: Phala Cloud integration and monitoring

### Phase 9: Desktop Client

**Goal**: macOS users can access vault through FUSE mount
**Depends on**: Phase 8
**Requirements**: DESK-01, DESK-02, DESK-03, DESK-04, DESK-05, DESK-06, DESK-07
**Success Criteria** (what must be TRUE):

1. User can log in via Web3Auth in desktop app
2. FUSE mount appears at ~/CipherVault after login
3. User can open files directly in native apps (Preview, TextEdit)
4. User can save files through FUSE mount (transparent encryption)
5. App runs in system tray with status icon
6. Refresh tokens stored securely in macOS Keychain
7. Background sync runs while app is in system tray
   **Plans**: TBD

Plans:

- [ ] 09-01: Tauri app scaffold with shared crypto module
- [ ] 09-02: Desktop Web3Auth integration and keychain storage
- [ ] 09-03: FUSE mount implementation (read operations)
- [ ] 09-04: FUSE mount implementation (write operations)
- [ ] 09-05: System tray and background sync daemon

### Phase 10: Data Portability

**Goal**: Users can export vault for independent recovery
**Depends on**: Phase 9
**Requirements**: PORT-01, PORT-02, PORT-03
**Success Criteria** (what must be TRUE):

1. User can export vault as JSON file from settings
2. Export includes all encrypted keys and complete folder structure
3. Export format is publicly documented for independent recovery
   **Plans**: TBD

Plans:

- [ ] 10-01: Vault export functionality in web and desktop
- [ ] 10-02: Export format documentation
- [ ] 10-03: Final polish and edge case handling

### Phase 11: Security Enhancements (Post-v1.0)

**Goal**: Optional MFA for users requiring stronger authentication guarantees
**Depends on**: Phase 10 (v1.0 complete)
**Requirements**: None (post-v1.0 enhancement)
**Success Criteria** (what must be TRUE):

1. User can optionally enable MFA in settings
2. User can enroll passkey/WebAuthn as second factor
3. User can enroll authenticator app (TOTP) as second factor
4. User can generate recovery phrase for account recovery
5. MFA-enabled users prompted for second factor on login
   **Plans**: TBD (see ADR-002)

Plans:

- [ ] 11-01: MFA enrollment UI in settings page
- [ ] 11-02: Passkey/WebAuthn integration with Web3Auth tKey
- [ ] 11-03: TOTP authenticator support
- [ ] 11-04: Recovery phrase generation and recovery flows

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> ... -> 10 (v1.0), then 11 (post-v1.0)
Decimal phases (if any) execute between their surrounding integers.

| Phase                | Plans Complete | Status      | Completed  |
| -------------------- | -------------- | ----------- | ---------- |
| 1. Foundation        | 3/3            | Complete    | 2026-01-20 |
| 2. Authentication    | 4/4            | Complete    | 2026-01-20 |
| 3. Core Encryption   | 3/3            | Complete    | 2026-01-20 |
| 4. File Storage      | 0/4            | Not started | -          |
| 5. Folder System     | 0/4            | Not started | -          |
| 6. File Browser UI   | 0/4            | Not started | -          |
| 7. Multi-Device Sync | 0/3            | Not started | -          |
| 8. TEE Integration   | 0/4            | Not started | -          |
| 9. Desktop Client    | 0/5            | Not started | -          |
| 10. Data Portability | 0/3            | Not started | -          |
| 11. Security (MFA)   | 0/4            | Post-v1.0   | -          |

---

_Roadmap created: 2026-01-20_
_Phase 1 planned: 2026-01-20_
_Phase 1 complete: 2026-01-20_
_Phase 2 planned: 2026-01-20_
_Phase 2 complete: 2026-01-20_
_Phase 3 planned: 2026-01-20_
_Phase 3 complete: 2026-01-20_
_Total phases: 11 | Total plans: 41 | Depth: Comprehensive_
