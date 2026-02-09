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
- [x] **Phase 4: File Storage** - Upload/download encrypted files via IPFS relay
- [x] **Phase 4.1: API Service Testing** - Unit tests for backend services per TESTING.md (INSERTED)
- [x] **Phase 4.2: Local IPFS Testing Infrastructure** - Add local IPFS node to Docker for offline testing (INSERTED)
- [x] **Phase 5: Folder System** - IPNS metadata, folder hierarchy, and operations
- [x] **Phase 6: File Browser UI** - Web interface for file management
- [x] **Phase 6.1: Webapp Automation Testing** - E2E UI testing with automation framework (INSERTED)
- [x] **Phase 6.2: Restyle App with Pencil Design** - Complete UI redesign using Pencil design tool (INSERTED)
- [x] **Phase 6.3: UI Structure Refactor** - Page layouts, component hierarchy, and structural redesign using Pencil (INSERTED)
- [x] **Phase 7: Multi-Device Sync** - IPNS polling and sync state management
- [x] **Phase 7.1: Atomic File Upload** - Refactor multi-request upload into single atomic backend call with batch IPNS publishing (INSERTED)
- [x] **Phase 8: TEE Integration** - Auto-republishing via Phala Cloud
- [x] **Phase 9: Desktop Client** - Tauri app with FUSE mount for macOS
- [x] **Phase 9.1: Environment Changes, DevOps & Staging Deployment** - CI/CD, environment config, staging deploy (INSERTED)
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
   **Plans**: 4 plans

Plans:

- [x] 04-01-PLAN.md — Backend IPFS relay endpoints (add, unpin)
- [x] 04-02-PLAN.md — Backend vault and storage quota management
- [x] 04-03-PLAN.md — Frontend file upload with encryption
- [x] 04-04-PLAN.md — Frontend file download with decryption

### Phase 4.1: API Service Testing (INSERTED)

**Goal**: Backend services have comprehensive unit test coverage per TESTING.md
**Depends on**: Phase 4
**Requirements**: Per .planning/codebase/TESTING.md coverage thresholds
**Success Criteria** (what must be TRUE):

1. Auth services have 90% line coverage, 85% branch coverage
2. Vault services have 90% line coverage, 85% branch coverage
3. IPFS services have 85% line coverage, 80% branch coverage
4. All controllers have 80% line coverage, 75% branch coverage
5. Overall backend coverage meets 85% line, 80% branch minimum
6. TDD workflow established for future development
   **Plans**: 3 plans

Plans:

- [x] 04.1-01-PLAN.md — Auth service unit tests (AuthService, TokenService, Web3AuthVerifierService, JwtStrategy)
- [x] 04.1-02-PLAN.md — Vault service unit tests (VaultService with QueryBuilder mocking)
- [x] 04.1-03-PLAN.md — Controller tests + Jest coverage thresholds configuration

### Phase 4.2: Local IPFS Testing Infrastructure (INSERTED)

**Goal**: Enable offline integration/E2E testing with local IPFS node
**Depends on**: Phase 4
**Requirements**: Testing infrastructure improvement
**Success Criteria** (what must be TRUE):

1. Local IPFS node (Kubo) runs in Docker Compose stack
2. Backend IPFS service works with both local node and Pinata
3. Configuration switches IPFS backend via environment variable
4. Integration tests can run without external network dependencies
   **Plans**: 2 plans

Plans:

- [x] 04.2-01-PLAN.md — Docker + Provider Abstraction (Kubo service, IpfsProvider interface, PinataProvider, LocalProvider)
- [x] 04.2-02-PLAN.md — Integration Tests + CI (IPFS service container, LocalProvider tests, E2E tests)

### Phase 5: Folder System

**Goal**: Users can organize files in encrypted folder hierarchy with IPNS metadata
**Depends on**: Phase 4.1
**Requirements**: FOLD-01, FOLD-02, FOLD-03, FOLD-04, FOLD-05, FOLD-06, FILE-04, FILE-05, API-05
**Success Criteria** (what must be TRUE):

1. User can create folders and they persist across sessions
2. User can delete folders and all contents are recursively removed
3. User can nest folders up to 20 levels deep
4. User can rename files and folders
5. User can move files and folders between parent folders
6. Each folder has its own IPNS keypair for metadata
   **Plans**: 4 plans

Plans:

- [x] 05-01-PLAN.md — Backend IPNS relay endpoints and FolderIpns entity
- [x] 05-02-PLAN.md — Crypto module IPNS record creation and folder metadata types
- [x] 05-03-PLAN.md — Frontend vault/folder stores and IPNS publishing service
- [x] 05-04-PLAN.md — Frontend folder CRUD operations (create, rename, delete, move)

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
   **Plans**: 4 plans

Plans:

- [x] 06-01-PLAN.md — File browser layout with folder tree sidebar and file list
- [x] 06-02-PLAN.md — Upload zone with drag-drop and progress modal
- [x] 06-03-PLAN.md — Context menu with rename, delete, download actions
- [x] 06-04-PLAN.md — Responsive design and breadcrumb navigation

### Phase 6.1: Webapp Automation Testing (INSERTED)

**Goal**: E2E UI testing with Playwright validates critical user flows
**Depends on**: Phase 6
**Requirements**: Testing infrastructure
**Success Criteria** (what must be TRUE):

1. E2E test framework configured and running
2. Critical user flows covered by automated tests
3. Tests run in CI pipeline
4. Test reports generated on failure
   **Plans**: 7 plans

Plans:

- [x] 06.1-01-PLAN.md — Playwright setup and base infrastructure
- [x] 06.1-02-PLAN.md — Page objects for File Browser components
- [x] 06.1-03-PLAN.md — Auth flow tests (login, logout, session)
- [x] 06.1-04-PLAN.md — File operations tests (upload, download, rename, delete)
- [x] 06.1-05-PLAN.md — Folder operations tests (create, rename, delete, navigate)
- [x] 06.1-06-PLAN.md — CI integration with GitHub Actions
- [x] 06.1-07-PLAN.md — Mock delegated routing service for IPNS E2E testing

### Phase 6.2: Restyle App with Pencil Design (INSERTED)

**Goal**: Complete UI redesign using Pencil design tool for modern, polished appearance
**Depends on**: Phase 6.1
**Requirements**: Visual refresh of all UI components
**Success Criteria** (what must be TRUE):

1. All UI components restyled with Pencil design system
2. Consistent visual language across login, file browser, and settings pages
3. Responsive design maintained after restyle
4. Existing E2E tests pass with new styling
   **Plans**: 6 plans

Plans:

- [x] 06.2-01-PLAN.md — Global styles, typography, and color scheme
- [x] 06.2-02-PLAN.md — File browser component styling
- [x] 06.2-03-PLAN.md — Overlay component styling (modals, dialogs, context menus)
- [x] 06.2-04-PLAN.md — Mobile responsive styling and matrix background
- [x] 06.2-05-PLAN.md — Component text updates ([DIR], [FILE], [CONNECT], --upload)
- [x] 06.2-06-PLAN.md — E2E test verification and final testing

### Phase 6.3: UI Structure Refactor (INSERTED)

**Goal**: Complete structural redesign of page layouts, component hierarchy, toolbars, and navigation using Pencil MCP for design-first approach
**Depends on**: Phase 6.2
**Requirements**: UI/UX structural improvements
**Success Criteria** (what must be TRUE):

1. Page layouts redesigned using Pencil MCP designs as source of truth
2. Component hierarchy refactored for better maintainability
3. New toolbar and navigation patterns implemented
4. File browser structure improved (sidebar, main area, toolbars)
5. All new designs created in Pencil before implementation
6. Existing E2E tests pass with structural changes
   **Plans**: 5 plans

Plans:

- [x] 06.3-01-PLAN.md — AppShell layout components (Header, Sidebar, Footer)
- [x] 06.3-02-PLAN.md — Routing and URL-based folder navigation
- [x] 06.3-03-PLAN.md — File list structure (ParentDirRow, 3-column layout, Breadcrumbs)
- [x] 06.3-04-PLAN.md — FileBrowser integration and responsive styles
- [x] 06.3-05-PLAN.md — Visual verification and final adjustments

### Phase 7: Multi-Device Sync

**Goal**: Changes sync across devices via IPNS polling
**Depends on**: Phase 6
**Requirements**: SYNC-01, SYNC-02, SYNC-03
**Success Criteria** (what must be TRUE):

1. Changes made on one device appear on another within ~30 seconds
2. User sees loading state during IPNS resolution
   **Plans**: 4 plans

Plans:

- [x] 07-01-PLAN.md — Backend IPNS resolution endpoint and sync state store
- [x] 07-02-PLAN.md — Polling infrastructure hooks (useInterval, useVisibility, useOnlineStatus, useSyncPolling)
- [x] 07-03-PLAN.md — Frontend integration with SyncIndicator and OfflineBanner UI
- [x] 07-04-PLAN.md — Gap closure: full metadata refresh with decryption on sync

### Phase 7.1: Atomic File Upload (INSERTED)

**Goal:** Refactor multi-request upload flow into single atomic backend call with batch IPNS publishing
**Depends on:** Phase 7
**Plans:** 2 plans

Plans:

- [x] 07.1-01-PLAN.md — Backend atomic upload endpoint (POST /ipfs/upload with quota check + pin recording)
- [x] 07.1-02-PLAN.md — Frontend batch upload flow (new endpoint, batch folder registration, server-authoritative quota)

**Details:**
Based on todo: `.planning/todos/pending/2026-01-22-atomic-file-upload-flow.md`

Current upload requires 3 sequential requests (pin to IPFS, record metadata, publish IPNS) which is non-atomic and wastes latency. This phase consolidates into a single backend call with DB transaction wrapping, batch IPNS publishing for multi-file uploads, and granular error response with retry tokens for partial failures.

### Phase 8: TEE Integration

**Goal**: IPNS records auto-republish every 6 hours via Phala Cloud TEE without user online
**Depends on**: Phase 7
**Requirements**: TEE-01, TEE-02, TEE-03, TEE-04, TEE-05, API-08
**Success Criteria** (what must be TRUE):

1. IPNS records republish every 6 hours via Phala Cloud TEE (4x/day, 48h record TTL)
2. Client encrypts IPNS private key with TEE public key before sending
3. TEE decrypts key in hardware, signs, and immediately zeros memory
4. Backend schedules and tracks republish jobs with monitoring
5. Key epochs rotate with 4-week grace period (old keys still work)
   **Plans**: 4 plans

Plans:

- [x] 08-01-PLAN.md — TEE key state entities, epoch management service, and TEE worker HTTP client
- [x] 08-02-PLAN.md — Redis + BullMQ republish scheduling, processor, and admin health endpoint
- [x] 08-03-PLAN.md — Client TEE key encryption on publish and backend auto-enrollment
- [x] 08-04-PLAN.md — Standalone TEE worker (Express/Phala Cloud CVM) with ECIES decrypt and IPNS signing

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
   **Plans**: 7 plans

Plans:

- [x] 09-01-PLAN.md — Tauri v2 app scaffold in pnpm workspace
- [x] 09-02-PLAN.md — Rust-native crypto module (AES, ECIES, Ed25519, IPNS) with cross-language test vectors
- [x] 09-03-PLAN.md — Backend auth endpoint modification for desktop body-based refresh tokens
- [x] 09-04-PLAN.md — Desktop auth flow: Web3Auth in webview, IPC, Keychain, vault key decryption
- [x] 09-05-PLAN.md — FUSE mount read operations (readdir, getattr, open, read with IPFS fetch + decrypt)
- [x] 09-06-PLAN.md — FUSE mount write operations (create, write, delete, mkdir, rmdir, rename)
- [x] 09-07-PLAN.md — System tray menu bar icon, background sync daemon, offline write queue

### Phase 9.1: Environment Changes, DevOps & Staging Deployment (INSERTED)

**Goal**: Production-ready environment configuration, CI/CD pipeline updates, and deployment to staging
**Depends on**: Phase 9
**Requirements**: Infrastructure and deployment readiness - See [ENVIRONMENTS.md](.planning/ENVIRONMENTS.md) for preliminary planning.
**Success Criteria** (what must be TRUE):

1. Environment configuration supports staging and production targets
2. CI/CD pipeline builds and deploys to staging
3. Infrastructure provisioned for staging environment
4. Application deployable and functional in staging
   **Plans**: 6 plans

Plans:

- [x] 09.1-01-PLAN.md — Environment config fixes (configurable port, TEE guard, hash routing, Web3Auth network, logging cleanup)
- [x] 09.1-02-PLAN.md — API Dockerfile, staging Docker Compose, Caddyfile, .dockerignore
- [x] 09.1-03-PLAN.md — Full schema database migration for fresh staging database
- [x] 09.1-04-PLAN.md — Tag-triggered deployment workflow (build, push, deploy to VPS + Pinata)
- [x] 09.1-05-PLAN.md — Infrastructure provisioning and first deployment verification
- [x] 09.1-06-PLAN.md — Monitoring: Grafana Cloud log aggregation + Better Stack uptime monitoring

**Details:**
Urgent insertion to prepare environment, DevOps pipeline, and staging deployment before continuing to data portability. Ensures the application is deployable and testable in a real environment.

### Phase 10: Data Portability

**Goal**: Users can export vault for independent recovery
**Depends on**: Phase 9.1
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

| Phase                   | Plans Complete | Status      | Completed  |
| ----------------------- | -------------- | ----------- | ---------- |
| 1. Foundation           | 3/3            | Complete    | 2026-01-20 |
| 2. Authentication       | 4/4            | Complete    | 2026-01-20 |
| 3. Core Encryption      | 3/3            | Complete    | 2026-01-20 |
| 4. File Storage         | 4/4            | Complete    | 2026-01-20 |
| 4.1 API Service Testing | 3/3            | Complete    | 2026-01-21 |
| 4.2 Local IPFS Testing  | 2/2            | Complete    | 2026-01-21 |
| 5. Folder System        | 4/4            | Complete    | 2026-01-21 |
| 6. File Browser UI      | 4/4            | Complete    | 2026-01-22 |
| 6.1 Webapp Automation   | 7/7            | Complete    | 2026-01-22 |
| 6.2 Restyle App         | 6/6            | Complete    | 2026-01-27 |
| 6.3 UI Structure        | 5/5            | Complete    | 2026-01-30 |
| 7. Multi-Device Sync    | 4/4            | Complete    | 2026-02-02 |
| 7.1 Atomic File Upload  | 2/2            | Complete    | 2026-02-07 |
| 8. TEE Integration      | 4/4            | Complete    | 2026-02-07 |
| 9. Desktop Client       | 7/7            | Complete    | 2026-02-08 |
| 9.1 Env/DevOps/Staging  | 6/6            | Complete    | 2026-02-09 |
| 10. Data Portability    | 0/3            | Not started | -          |
| 11. Security (MFA)      | 0/4            | Post-v1.0   | -          |

---

_Roadmap created: 2026-01-20_
_Phase 1 planned: 2026-01-20_
_Phase 1 complete: 2026-01-20_
_Phase 2 planned: 2026-01-20_
_Phase 2 complete: 2026-01-20_
_Phase 3 planned: 2026-01-20_
_Phase 3 complete: 2026-01-20_
_Phase 4 planned: 2026-01-20_
_Phase 4 complete: 2026-01-20_
_Phase 4.1 planned: 2026-01-20_
_Phase 4.1 complete: 2026-01-21_
_Phase 5 planned: 2026-01-21_
_Phase 5 complete: 2026-01-21_
_Phase 4.2 complete: 2026-01-21_
_Phase 6.1 inserted: 2026-01-21_
_Phase 6 planned: 2026-01-21_
_Phase 6.1 planned: 2026-01-22_
_Phase 6.1 complete: 2026-01-22_
_Phase 7 planned: 2026-01-22_
_Phase 6.3 inserted: 2026-01-25_
_Phase 6.2 complete: 2026-01-27_
_Phase 6.3 planned: 2026-01-30_
_Phase 6.3 complete: 2026-01-30_
_Phase 7 complete: 2026-02-02_
_Phase 7.1 inserted: 2026-02-07_
_Phase 7.1 planned: 2026-02-07_
_Phase 7.1 complete: 2026-02-07_
_Phase 8 planned: 2026-02-07_
_Phase 8 complete: 2026-02-07_
_Phase 9 planned: 2026-02-07_
_Phase 9 revised: 2026-02-07_
_Phase 9 complete: 2026-02-08_
_Phase 9.1 planned: 2026-02-09_
_Phase 9.1 complete: 2026-02-09_
_Total phases: 14 | Total plans: 74 | Depth: Comprehensive_
