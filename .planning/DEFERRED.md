# Deferred Items Inventory

**Last updated:** 2026-03-29

Items deferred across milestones v1.0 (phases 11-17.1) and v1.1 (phases 18-27).
Cross-referenced with `.planning/todos/pending/` and security review findings.

## Active Pending Todos

These are explicitly tracked in `.planning/todos/pending/`:

| Date       | Item                                                                          | Priority |
| ---------- | ----------------------------------------------------------------------------- | -------- |
| 2026-02-07 | Offload large file encryption to Web Worker (files >= 10MB block main thread) | Medium   |
| 2026-02-14 | ERC-1271 contract wallet authentication (Safe, Argent, Sequence)              | Low      |
| 2026-02-22 | CRDT-based IPNS inbox for serverless share discovery                          | Research |
| 2026-02-24 | Make search index build async/incremental for large vaults                    | Medium   |
| 2026-02-26 | Alternative MFA factor types (passkeys, password-derived)                     | Medium   |
| 2026-03-23 | Investigate removal of mock-ipns-routing layer (someguy works now)            | Low      |

## Security Review Findings (Deferred from Phase 14)

From `.planning/todos/done/2026-02-21-phase14-security-review-deferred.md`:

| ID  | Severity | Item                                                                    | Status      |
| --- | -------- | ----------------------------------------------------------------------- | ----------- |
| M1  | Medium   | `itemName` stored plaintext on server -- encrypt with recipient pubkey  | Open        |
| M5  | Medium   | `reWrapForRecipients` silently swallows errors -- surface notifications | Open        |
| L1  | Low      | `/shares/lookup` enables public key enumeration -- always return 200    | Open        |
| L4  | Low      | No pagination on shares endpoints -- add limit/offset                   | Implemented |

## Deferred by Category

### Sharing & Collaboration

| Item                                                      | Source Phase | Notes                                                        |
| --------------------------------------------------------- | ------------ | ------------------------------------------------------------ |
| Metadata-embedded sharing (hide social graph from server) | 27           | Move share data + wrapped keys onto IPFS metadata            |
| Attribution / audit trail (`lastModifiedBy` in metadata)  | 27           | Track who modified what in shared folders                    |
| Transitive re-sharing                                     | 27           | Allow recipients to share onward; needs cascading revocation |
| Share notifications (permission changes)                  | 14, 27       | Notify recipients of upgrade/downgrade/revoke                |
| User discovery service (by email/username/wallet)         | 14           | Privacy controls needed; separate phase                      |
| Display names for share recipients                        | 14           | Depends on user discovery/profile                            |
| Immediate key rotation on revoke                          | 14, 27       | Currently lazy; more secure but requires re-wrapping         |
| CRDT-based IPNS inbox                                     | 14           | Decentralized share discovery replacing `shares` table       |
| Faster sync for shared folders (10s poll)                 | 27           | Reduce interval for active multi-writer scenarios            |

### Desktop Platform

| Item                                                             | Source Phase | Notes                                                         |
| ---------------------------------------------------------------- | ------------ | ------------------------------------------------------------- |
| Desktop sharing UI                                               | 14           | No share dialog in desktop app                                |
| Desktop recycle bin UI                                           | 17           | Bin operations web-only; desktop has no bin browsing          |
| Desktop search                                                   | 15.1         | No search in desktop app                                      |
| Desktop device approval polling                                  | 11.1         | `approveDevice()` API-complete but no desktop notification UI |
| Desktop FUSE CTR streaming support                               | 12.1         | Web has CTR playback; desktop update deferred                 |
| Desktop .Trash folder integration                                | 17           | Finder/Explorer native trash integration                      |
| Platform code signing (Apple notarization, Windows Authenticode) | 25           | Required for production distribution                          |
| Beta/canary update channels                                      | 25           | Future if needed                                              |
| Delta updates                                                    | 25           | Tauri supports but adds complexity                            |
| Linux FUSE mount                                                 | 11.3         | Implemented but less tested than macOS                        |

### Authentication & Security

| Item                                    | Source Phase | Notes                                             |
| --------------------------------------- | ------------ | ------------------------------------------------- |
| ERC-1271 contract wallet authentication | 12           | Smart contract wallets need on-chain verification |
| Alternative MFA factor types            | 12           | Passkeys (WebAuthn PRF), password-derived keys    |
| WalletConnect QR code flow              | 11.1         | Only injected provider MVP currently              |
| Social recovery (Shamir Secret Sharing) | 12           | High complexity                                   |

### Performance & Infrastructure

| Item                                 | Source Phase | Notes                                              |
| ------------------------------------ | ------------ | -------------------------------------------------- |
| Web Worker for large file encryption | -            | Files >= 10MB block main thread                    |
| Async/incremental search index       | 15.1         | `buildFromFolderTree()` blocks UI for large vaults |
| BYO IPFS provider benchmarks         | 21           | Requires external provider infrastructure          |
| Automated CI timing gates            | 26           | Flaky due to runner variance                       |
| Remove mock-ipns-routing             | 19           | Someguy at <docker-host>:8190 may replace it       |
| Push notifications (WebSocket sync)  | 16           | Currently polling-only; requires backend infra     |

### Sync & Conflict Resolution (Deferred to Milestone 4)

| Item                                         | Source Phase | Notes                                      |
| -------------------------------------------- | ------------ | ------------------------------------------ |
| Offline operation queue (IndexedDB)          | 16           | Persist writes for replay on reconnect     |
| Idempotent replay                            | 16           | Idempotency keys for queued operations     |
| Auto-merge of non-conflicting folder changes | 16           | Three-way merge on encrypted metadata      |
| Per-file IPNS conflict detection             | 16           | Currently covered by versioning safety net |

### Data Management

| Item                                          | Source Phase | Notes                                                              |
| --------------------------------------------- | ------------ | ------------------------------------------------------------------ |
| TEE unenrollment on file/folder delete        | 12.6, 17     | Orphaned IPNS records expire naturally (24h) but waste TEE compute |
| TEE enrollment drift reconciliation           | 12.6         | Periodic vault scan to sync enrollment                             |
| Column DROP migration (vault v1 fields)       | 20           | After all users migrated, drop legacy columns                      |
| User-configurable bin retention period        | 17           | Currently fixed 30-day retention                                   |
| Retroactive TEE enrollment for existing files | 25           | New files only; existing files not enrolled                        |

### Code Quality

| Item                                            | Source Phase | Notes                                 |
| ----------------------------------------------- | ------------ | ------------------------------------- |
| DTS circular build dependency (crypto <-> core) | 19.1         | Workaround in place; not fixed        |
| Desktop FUSE automated tests                    | -            | Manual testing only (see CONCERNS.md) |

## Items Implemented in Later Phases

These were deferred but have since been completed:

| Item                                   | Deferred From            | Implemented In |
| -------------------------------------- | ------------------------ | -------------- |
| File versioning                        | v1.0 scope exclusion     | Phase 13       |
| User-to-user sharing                   | v1.0 scope exclusion     | Phase 14       |
| Read-write sharing                     | Phase 14                 | Phase 27       |
| Per-file IPNS metadata                 | Phase 12                 | Phase 12.6     |
| SDK extraction                         | Phase 11                 | Phase 19.1     |
| Rust SDK extraction                    | Phase 19.1               | Phase 23       |
| BYO IPFS node support                  | Phase 12.1               | Phase 21       |
| Vault key blob (zero-knowledge server) | Phase 12                 | Phase 20       |
| Client-side search                     | Phase 15                 | Phase 15.1     |
| Performance baselines                  | Phase 18                 | Phase 22       |
| Link sharing                           | Phase 14                 | Phase 15       |
| Pagination on shares endpoints (L4)    | Phase 14 security review | Phase 14       |
| Structured logging wrapper for web app | -                        | Phase 28       |

<!-- Deferred inventory: 2026-03-28 -->
