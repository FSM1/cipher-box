# Roadmap: CipherBox

## Milestones

- Milestone 1: Staging MVP (Phases 1-10) -- shipped 2026-02-11
- Milestone 2: Production v1.0 (Phases 11-17) -- in progress
- Milestone 3: Encrypted Productivity Suite (Phases 18-21) -- planned

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

<details>
<summary>Milestone 1: Staging MVP (Phases 1-10) -- SHIPPED 2026-02-11</summary>

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
- [x] **Phase 10: Data Portability** - Vault export and documentation

**72 plans executed across 15 phase directories. Total execution time: ~5.6 hours.**

See `.planning/archive/m1-ROADMAP.md` for full M1 phase details and plan lists.

</details>

### Milestone 2: Production v1.0 (In Progress)

**Milestone Goal:** Elevate the staging MVP into a production-ready encrypted storage platform with sharing, search, MFA, file versioning, cross-platform desktop, and TEE failover.

- [ ] **Phase 11: Cross-Platform Desktop** - Linux and Windows desktop apps (Tauri, platform-specific FUSE/virtual drive) -- can run in parallel
- [x] **Phase 12: Core Kit Identity Provider Foundation** - Replace PnP Modal SDK with MPC Core Kit, CipherBox as identity provider
- [ ] **Phase 12.1: AES-CTR Streaming Encryption** - AES-256-CTR for media files with byte-range decryption and in-browser playback (INSERTED)
- [x] **Phase 12.2: Encrypted Device Registry** - Encrypted device metadata on IPFS for cross-device infrastructure (INSERTED)
- [ ] **Phase 12.3: SIWE + Unified Identity** - Wallet login via SIWE, multi-auth linking, ADR-001 cleanup (INSERTED)
- [ ] **Phase 12.4: MFA + Cross-Device Approval** - MFA enrollment, recovery phrase, factor management, device approval flow (INSERTED)
- [ ] **Phase 13: File Versioning** - Automatic version retention with history view and restore
- [ ] **Phase 14: User-to-User Sharing** - Read-only folder sharing with ECIES key re-wrapping
- [ ] **Phase 15: Link Sharing and Search** - Shareable file links and client-side encrypted search
- [ ] **Phase 16: Advanced Sync** - Conflict detection, offline queue, and idempotent replay
- [ ] **Phase 17: AWS Nitro TEE** - Nitro enclave as fallback TEE provider for IPNS republishing

### Milestone 3: Encrypted Productivity Suite (Planned)

**Milestone Goal:** Transform CipherBox into an encrypted productivity platform with billing, team accounts, document editors, and document signing.

- [ ] **Phase 18: Billing Infrastructure** - Stripe subscriptions, NOWPayments crypto billing, tier enforcement
- [ ] **Phase 19: Team Accounts** - Team CRUD, ECIES-wrapped Per-Team Key hierarchy, CASL permissions
- [ ] **Phase 20: Document Editors** - TipTap rich text and Univer spreadsheet editors with decrypt-edit-encrypt pipeline
- [ ] **Phase 21: Document Signing** - ECDSA signing/verification, visual signature capture, multi-party workflows

See `.planning/milestones/m3/ROADMAP.md` for full M3 phase details.

## Phase Details

### Phase 11: Cross-Platform Desktop

**Goal**: CipherBox desktop app runs on Linux and Windows with native filesystem integration
**Depends on**: Phase 9 (macOS desktop complete in M1). Can run in parallel with any M2 phase.
**Requirements**: PLAT-01, PLAT-02
**Research flag**: NEEDS `/gsd:research-phase` -- Linux FUSE (libfuse) and Windows virtual drive (WinFsp or Dokany) have platform-specific build and packaging requirements. Tauri cross-compilation and CI matrix need investigation.
**Success Criteria** (what must be TRUE):

1. Linux user can install CipherBox via AppImage or .deb, log in, and access a FUSE mount at ~/CipherBox
2. Windows user can install CipherBox via MSI or NSIS installer, log in, and access a virtual drive (e.g., C:\CipherBox or mapped drive letter)
3. Background sync, system tray, and keychain storage work on both platforms (parity with macOS)
4. CI builds and packages desktop apps for all three platforms (macOS, Linux, Windows)
   **Plans**: TBD

### Phase 12: Core Kit Identity Provider Foundation

**Goal**: Replace PnP Modal SDK with MPC Core Kit and establish CipherBox backend as the identity provider for Web3Auth, building the foundation for MFA, SIWE, and cross-device approval in subsequent phases
**Depends on**: Phase 10 (Milestone 1 complete)
**Requirements**: MFA-01 (partial — foundation only), AUTH infrastructure
**Success Criteria** (what must be TRUE):

1. User can log in via Google OAuth through CipherBox-branded UI (not Web3Auth modal)
2. User can log in via email through CipherBox-branded UI
3. CipherBox backend issues JWTs with `sub = userId`, verified by Web3Auth custom verifier
4. Core Kit initialization, login, and private key export work end-to-end
5. Existing PnP users' keys are preserved via `importTssKey` migration
6. User's derived keypair (publicKey) remains identical after migration — vault data stays accessible

**Plans:** 5 plans

Plans:

- [ ] 12-PLAN-01.md — Backend identity provider (JWKS, Google OAuth, email OTP, JWT issuing)
- [ ] 12-PLAN-02.md — Core Kit SDK installation + React context provider
- [ ] 12-PLAN-03.md — Frontend auth flow rewrite (loginWithJWT, key export, session)
- [ ] 12-PLAN-04.md — Custom CipherBox-branded login UI (Google + email)
- [ ] 12-PLAN-05.md — PnP migration (importTssKey), cleanup, and E2E verification

### Phase 12.1: AES-CTR Streaming Encryption (INSERTED)

**Goal**: Media files (video/audio) are encrypted with AES-256-CTR instead of GCM, enabling byte-range decryption for in-browser playback and efficient FUSE reads
**Depends on**: Phase 12 (MFA must stabilize auth and key derivation first)
**Requirements**: Spec'd in TECHNICAL_ARCHITECTURE.md (v1.1 roadmap item), DATA_FLOWS.md (CTR upload/download sequences)
**Research flag**: NEEDS `/gsd:research-phase` -- MediaSource API + Service Worker decryption pipeline, byte-range IPFS fetching, CTR nonce/counter management for random-access reads
**Success Criteria** (what must be TRUE):

1. Media files (detected by MIME type) are encrypted with AES-256-CTR; all other files continue using AES-256-GCM
2. User can play encrypted video/audio in-browser without downloading the entire file first (streaming decryption via MediaSource or Service Worker)
3. Desktop FUSE client can decrypt CTR-encrypted files with random-access byte-range reads (no full-file download)
4. Existing GCM-encrypted files remain fully readable -- encryptionMode field in metadata drives mode selection
5. Upload pipeline streams file data through CTR encryption instead of loading entirely into memory
   **Plans**: TBD

### Phase 12.2: Encrypted Device Registry (INSERTED)

**Goal**: Encrypted device metadata stored on IPFS alongside user's vault, providing durable infrastructure for cross-device approval and resilience against backend rebuilds
**Depends on**: Phase 12 (Core Kit foundation must be in place)
**Requirements**: Infrastructure for MFA-02 (device management)
**Success Criteria** (what must be TRUE):

1. Authenticated devices are tracked in an encrypted registry pinned on IPFS
2. Device registry is encrypted with user's key and only readable by the user
3. Device metadata includes public keys, device names, authorization status, and revocation capability
4. Registry is discoverable and recoverable by any authenticated session

**Plans:** 3 plans

Plans:

- [x] 12.2-PLAN-01.md — Registry and device crypto primitives (types, HKDF IPNS derivation, ECIES encrypt/decrypt, device keygen, tests)
- [x] 12.2-PLAN-02.md — Device identity persistence (IndexedDB) and registry service (CRUD + IPFS/IPNS publish)
- [x] 12.2-PLAN-03.md — Auth flow integration (Zustand store, non-blocking init, polling, logout cleanup)

### Phase 12.3: SIWE + Unified Identity (INSERTED)

**Goal**: Wallet users can log in via SIWE and all auth methods (wallet, Google, email) resolve to the same CipherBox identity and Web3Auth key
**Depends on**: Phase 12.2 (device registry for multi-device state)
**Requirements**: AUTH unification, MFA-01 (wallet MFA prerequisite)
**Research flag**: COMPLETE -- SIWE message format, backend verification, wallet address hashing, multi-auth linking UX researched
**Success Criteria** (what must be TRUE):

1. Wallet user can sign SIWE message -> CipherBox API verifies -> issues JWT -> Core Kit login succeeds
2. User can link additional auth methods (second wallet, email) from settings
3. Any linked auth method produces a JWT with same `sub = userId` -> same Web3Auth key
4. Wallet addresses are stored as hashes in the database (not plaintext)
5. ADR-001 legacy code (signatureKeyDerivation, derivationVersion, external_wallet) is fully removed (clean break, no migration needed)

**Plans:** 4 plans

Plans:

- [ ] 12.3-01-PLAN.md — Backend SIWE service, schema evolution, wallet identity endpoints
- [ ] 12.3-02-PLAN.md — Backend ADR-001 cleanup (auth service, vault export, verifier, API client regen)
- [ ] 12.3-03-PLAN.md — Frontend wallet login (wagmi, WalletLoginButton, SIWE flow) + ADR-001 cleanup (rename derivedKeypair to vaultKeypair)
- [ ] 12.3-04-PLAN.md — Settings page auth method management (view, link, unlink)

### Phase 12.4: MFA + Cross-Device Approval (INSERTED)

**Goal**: Users can enroll in MFA with device shares and recovery phrases, and approve new devices from existing authenticated devices
**Depends on**: Phase 12.3 (unified identity for consistent MFA across all auth methods)
**Requirements**: MFA-01, MFA-02, MFA-03, MFA-04
**Research flag**: NEEDS `/gsd:research-phase` -- Core Kit enableMFA() flow, createFactor/inputFactorKey for cross-device, bulletin board API design, ECIES ephemeral key exchange
**Success Criteria** (what must be TRUE):

1. User can enable MFA from settings and is guided through factor enrollment (device share + recovery phrase)
2. User can approve a new device from an existing authenticated device (bulletin board pattern)
3. User can recover access using recovery phrase when device share is lost
4. User's derived keypair (publicKey) remains identical after MFA enrollment — vault data stays accessible
5. MFA factors are manageable from settings (view, add, revoke)

Plans:

- [ ] TBD (run `/gsd:plan-phase 12.4` to break down)

### Phase 13: File Versioning

**Goal**: Users can access and restore previous versions of their files
**Depends on**: Phase 12
**Requirements**: VER-01, VER-02, VER-03, VER-04, VER-05
**Research flag**: Standard patterns -- metadata schema extension plus "stop unpinning old CIDs." Skip `/gsd:research-phase`.
**Success Criteria** (what must be TRUE):

1. When a user uploads a new version of an existing file, the previous version is automatically retained (old CID stays pinned)
2. User can open a version history panel for any file and see a list of previous versions with timestamps
3. User can restore a previous version, which becomes the current version while preserving the version chain
4. Version retention policy is enforced (configurable max versions per file) and excess versions are pruned automatically
5. Storage consumed by retained versions counts against the user's 500 MiB quota
   **Plans**: TBD

### Phase 14: User-to-User Sharing

**Goal**: Users can share encrypted folders with other CipherBox users while maintaining zero-knowledge guarantees
**Depends on**: Phase 13
**Requirements**: SHARE-01, SHARE-02, SHARE-03, SHARE-04, SHARE-05
**Research flag**: NEEDS `/gsd:research-phase` -- share revocation key rotation protocol is the most complex protocol in M2. ECIES re-wrapping correctness must be validated with test vectors.
**Success Criteria** (what must be TRUE):

1. User can share a folder (read-only) with another CipherBox user by re-wrapping the folderKey with the recipient's publicKey via ECIES
2. User can invite a recipient by email or public key, and the recipient sees the invitation and can accept or decline
3. User can revoke a share, which triggers folderKey rotation and re-wrapping for all remaining recipients
4. Recipient can browse shared folders in a "Shared with me" section of the file browser
5. Server never sees plaintext folderKey at any point during the sharing flow
   **Plans**: TBD

### Phase 15: Link Sharing and Search

**Goal**: Users can share individual files via link with non-users, and search across their entire vault
**Depends on**: Phase 14
**Requirements**: SHARE-06, SHARE-07, SRCH-01, SRCH-02, SRCH-03
**Research flag**: Link sharing NEEDS `/gsd:research-phase` -- web viewer for unauthenticated access is a new security surface. Search is standard patterns (skip research).
**Success Criteria** (what must be TRUE):

1. User can generate a shareable link for a file where the decryption key is in the URL fragment only (never sent to server)
2. Recipient can open the link in a browser and download the decrypted file without a CipherBox account
3. User can search file names across all folders and see matching results with navigation to the file location
4. Search index is encrypted and persisted in IndexedDB, surviving page refreshes
5. Search index updates incrementally when IPNS polling detects metadata changes
   **Plans**: TBD

### Phase 16: Advanced Sync

**Goal**: Users experience reliable sync with conflict awareness and offline resilience
**Depends on**: Phase 15
**Requirements**: SYNC-04, SYNC-05, SYNC-06
**Research flag**: NEEDS `/gsd:research-phase` -- three-way merge edge cases with encrypted metadata need exhaustive test matrix. Offline replay with idempotency keys is uncharted territory for this codebase.
**Success Criteria** (what must be TRUE):

1. Client detects when another device has published a newer IPNS sequence number and alerts the user before overwriting
2. When the user goes offline and makes changes, operations are queued locally and automatically replayed on reconnect
3. Queued operations use idempotency keys so replaying them after reconnect never produces duplicate files or folders
   **Plans**: TBD

### Phase 17: AWS Nitro TEE

**Goal**: IPNS republishing has a fallback TEE provider for high availability
**Depends on**: Phase 12 (can run in parallel with Phases 14-16 after MFA stabilizes auth)
**Requirements**: TEE-06
**Research flag**: NEEDS `/gsd:research-phase` -- Rust enclave binary, vsock communication, KMS attestation are entirely new technology for this project. Highest-risk item in M2.
**Success Criteria** (what must be TRUE):

1. AWS Nitro enclave can receive ECIES-encrypted IPNS keys, decrypt in hardware, sign IPNS records, and zero memory
2. Backend routes republish jobs to Nitro when Phala Cloud is unavailable, with automatic failover and failback
   **Plans**: TBD

## Progress

**Execution Order:**

Sequential order: 12 -> 12.1 -> 13 -> 14 -> 15 -> 16 -> 17 -> 18 -> 19 -> 20 -> 21

Parallel phases:

- Phase 11 (Cross-Platform Desktop) can run in parallel with any M2 phase (depends only on Phase 9/M1).
- Phase 17 (AWS Nitro TEE) can optionally execute in parallel with Phases 14-16 (depends on Phase 12).

| Phase                      | Milestone | Plans Complete | Status      | Completed  |
| -------------------------- | --------- | -------------- | ----------- | ---------- |
| 1. Foundation              | M1        | 3/3            | Complete    | 2026-01-20 |
| 2. Authentication          | M1        | 4/4            | Complete    | 2026-01-20 |
| 3. Core Encryption         | M1        | 3/3            | Complete    | 2026-01-20 |
| 4. File Storage            | M1        | 4/4            | Complete    | 2026-01-20 |
| 4.1 API Service Testing    | M1        | 3/3            | Complete    | 2026-01-21 |
| 4.2 Local IPFS Testing     | M1        | 2/2            | Complete    | 2026-01-21 |
| 5. Folder System           | M1        | 4/4            | Complete    | 2026-01-21 |
| 6. File Browser UI         | M1        | 4/4            | Complete    | 2026-01-22 |
| 6.1 Webapp Automation      | M1        | 7/7            | Complete    | 2026-01-22 |
| 6.2 Restyle App            | M1        | 6/6            | Complete    | 2026-01-27 |
| 6.3 UI Structure           | M1        | 5/5            | Complete    | 2026-01-30 |
| 7. Multi-Device Sync       | M1        | 4/4            | Complete    | 2026-02-02 |
| 7.1 Atomic File Upload     | M1        | 2/2            | Complete    | 2026-02-07 |
| 8. TEE Integration         | M1        | 4/4            | Complete    | 2026-02-07 |
| 9. Desktop Client          | M1        | 7/7            | Complete    | 2026-02-08 |
| 9.1 Env/DevOps/Staging     | M1        | 6/6            | Complete    | 2026-02-09 |
| 10. Data Portability       | M1        | 3/3            | Complete    | 2026-02-11 |
| 12. Core Kit Identity      | M2        | 5/5            | Complete    | 2026-02-13 |
| 12.1 AES-CTR Streaming     | M2        | 0/TBD          | Not started | -          |
| 12.2 Device Registry       | M2        | 3/3            | Complete    | 2026-02-13 |
| 12.3 SIWE + Identity       | M2        | 0/4            | Planned     | -          |
| 13. File Versioning        | M2        | 0/TBD          | Not started | -          |
| 14. User-to-User Sharing   | M2        | 0/TBD          | Not started | -          |
| 15. Link Sharing + Search  | M2        | 0/TBD          | Not started | -          |
| 16. Advanced Sync          | M2        | 0/TBD          | Not started | -          |
| 11. Cross-Platform Desktop | M2        | 0/TBD          | Not started | -          |
| 17. AWS Nitro TEE          | M2        | 0/TBD          | Not started | -          |
| 18. Billing Infrastructure | M3        | 0/TBD          | Not started | -          |
| 19. Team Accounts          | M3        | 0/TBD          | Not started | -          |
| 20. Document Editors       | M3        | 0/TBD          | Not started | -          |
| 21. Document Signing       | M3        | 0/TBD          | Not started | -          |

---

Roadmap created: 2026-01-20
Milestone 1 shipped: 2026-02-11
Milestone 2 roadmap created: 2026-02-11
Milestone 3 roadmap created: 2026-02-11
Total M1 phases: 17 | Total M1 plans: 72 | Depth: Comprehensive
Total M2 phases: 8 | Total M2 plans: TBD | Depth: Comprehensive
Total M3 phases: 4 | Total M3 plans: TBD | Depth: Comprehensive
