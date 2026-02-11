# Roadmap: CipherBox

## Milestones

- Milestone 1: Staging MVP (Phases 1-10) -- shipped 2026-02-11
- Milestone 2: Production v1.0 (Phases 12-17) -- in progress
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

**Milestone Goal:** Elevate the staging MVP into a production-ready encrypted storage platform with sharing, search, MFA, and file versioning.

- [ ] **Phase 12: Multi-Factor Authentication** - Web3Auth MFA factor configuration and backup recovery
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

### Phase 12: Multi-Factor Authentication

**Goal**: Users can strengthen account security with additional authentication factors and recovery options
**Depends on**: Phase 10 (Milestone 1 complete)
**Requirements**: MFA-01, MFA-02, MFA-03, MFA-04
**Research flag**: Standard patterns -- Web3Auth mfaSettings is documented SDK configuration. Skip `/gsd:research-phase`.
**Success Criteria** (what must be TRUE):

1. User can enable MFA from the settings page and is guided through factor enrollment
2. User can configure a device share as an additional MFA factor for login
3. User can generate a backup recovery phrase and use it to regain vault access
4. User's derived keypair (publicKey) remains identical after MFA enrollment -- vault data stays accessible without re-encryption
   **Plans**: TBD

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

Phases execute in numeric order: 12 -> 13 -> 14 -> 15 -> 16 -> 17 -> 18 -> 19 -> 20 -> 21

Phase 17 (AWS Nitro TEE) can optionally execute in parallel with Phases 14-16.

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
| 12. MFA                    | M2        | 0/TBD          | Not started | -          |
| 13. File Versioning        | M2        | 0/TBD          | Not started | -          |
| 14. User-to-User Sharing   | M2        | 0/TBD          | Not started | -          |
| 15. Link Sharing + Search  | M2        | 0/TBD          | Not started | -          |
| 16. Advanced Sync          | M2        | 0/TBD          | Not started | -          |
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
Total M2 phases: 6 | Total M2 plans: TBD | Depth: Comprehensive
Total M3 phases: 4 | Total M3 plans: TBD | Depth: Comprehensive
