# Deferred Items Inventory

**Last updated:** 2026-03-31

Items deferred across milestones v1.0 (phases 11-17.1) and v1.1 (phases 18-37).
Cross-referenced with `.planning/todos/pending/` and security review findings.

## Active Pending Todos

These are explicitly tracked in `.planning/todos/pending/`:

| Date       | Item                                                             | Priority |
| ---------- | ---------------------------------------------------------------- | -------- |
| 2026-02-14 | ERC-1271 contract wallet authentication (Safe, Argent, Sequence) | Low      |
| 2026-02-22 | CRDT-based IPNS inbox for serverless share discovery             | Research |
| 2026-02-24 | Make search index build async/incremental for large vaults       | Medium   |
| 2026-02-26 | Alternative MFA factor types (passkeys, password-derived)        | Medium   |
| 2026-03-23 | Investigate removal of mock-ipns-routing layer (someguy works)   | Low      |

## Security Review Findings (Deferred from Phase 14)

From `.planning/todos/done/2026-02-21-phase14-security-review-deferred.md`:

| ID  | Severity | Item                                                                    | Status      |
| --- | -------- | ----------------------------------------------------------------------- | ----------- |
| M1  | Medium   | `itemName` stored plaintext on server -- encrypt with recipient pubkey  | Open        |
| M5  | Medium   | `reWrapForRecipients` silently swallows errors -- surface notifications | Open        |
| L1  | Low      | `/shares/lookup` enables public key enumeration -- always return 200    | Open        |
| L4  | Low      | No pagination on shares endpoints -- add limit/offset                   | Implemented |

## Security Review Findings (Deferred from IPNS Signature Storage PR #448)

From `.planning/security/REVIEW-20260402-172126.md`:

| ID  | Severity | Item                                                                                                       | Status   |
| --- | -------- | ---------------------------------------------------------------------------------------------------------- | -------- |
| S1  | Medium   | Validate signedRecord on publish: parse embedded CID/sequence and reject mismatches with dto fields        | Open     |
| S2  | Medium   | Signature verification silently skipped when server omits fields (downgrade) -- enforce once data is ready | Deferred |
| S3  | Medium   | Inconsistent private key zeroization -- establish caller-owns-key convention across SDK                    | Deferred |

## Deferred by Category

### Sharing & Collaboration

| Item                                                      | Source Phase | Notes                                                        |
| --------------------------------------------------------- | ------------ | ------------------------------------------------------------ |
| Metadata-embedded sharing (hide social graph from server) | 27           | Move share data + wrapped keys onto IPFS metadata            |
| Attribution / audit trail (`lastModifiedBy` in metadata)  | 27           | Track who modified what in shared folders                    |
| Transitive re-sharing                                     | 27           | Allow recipients to share onward; needs cascading revocation |
| Share notifications (permission changes)                  | 14, 27       | Notify recipients of upgrade/downgrade/revoke                |
| User discovery service (by email/username/wallet)         | 14           | Public key lookup exists; email/username discovery not built |
| Display names for share recipients                        | 14           | Depends on user discovery/profile                            |
| Immediate key rotation on revoke                          | 14, 27       | Currently lazy; more secure but requires re-wrapping         |
| CRDT-based IPNS inbox                                     | 14           | Decentralized share discovery replacing `shares` table       |
| Faster sync for shared folders (10s poll)                 | 27           | Reduce interval for active multi-writer scenarios            |

### Desktop Platform

| Item                                       | Source Phase | Notes                                                                       |
| ------------------------------------------ | ------------ | --------------------------------------------------------------------------- |
| Desktop sharing UI                         | 14           | No share dialog in desktop app (FUSE-only, no file browser)                 |
| Desktop recycle bin UI                     | 17           | Bin operations web-only; desktop has no bin browsing                        |
| Desktop search                             | 15.1         | No search in desktop app                                                    |
| Desktop device approval polling            | 11.1         | Core polling logic exists; post-auth always-on listener not yet implemented |
| Desktop .Trash folder integration          | 17           | Finder/Explorer native trash integration                                    |
| Platform code signing (Apple notarization) | 25           | Windows signing configured; macOS notarization not yet set up               |
| Beta/canary update channels                | 25           | Single release channel only                                                 |
| Delta updates                              | 25           | Tauri supports but adds complexity                                          |

### Authentication & Security

| Item                                    | Source Phase | Notes                                             |
| --------------------------------------- | ------------ | ------------------------------------------------- |
| ERC-1271 contract wallet authentication | 12           | Smart contract wallets need on-chain verification |
| Alternative MFA factor types            | 12           | Passkeys (WebAuthn PRF), password-derived keys    |
| WalletConnect QR code flow              | 11.1         | Only injected provider MVP currently              |
| Social recovery (Shamir Secret Sharing) | 12           | High complexity                                   |

### Performance & Infrastructure

| Item                                           | Source Phase | Notes                                                   |
| ---------------------------------------------- | ------------ | ------------------------------------------------------- |
| Async/incremental search index                 | 15.1         | `buildFromFolderTree()` blocks UI for large vaults      |
| BYO IPFS provider benchmarks                   | 21           | Requires external provider infrastructure               |
| Automated CI timing gates                      | 26           | Flaky due to runner variance                            |
| Remove mock-ipns-routing                       | 19           | Someguy at `<docker-host>:8190` may replace it          |
| Push notifications (WebSocket sync)            | 16           | Currently polling-only; requires backend infra          |
| Batch API endpoint for IPNS resolves           | 32           | Could reduce round trips for folders with many files    |
| Kubo API access control (reverse proxy or ACL) | 29           | Current Docker 127.0.0.1 binding sufficient for staging |

### Upload Pipeline (Phase 37)

| Item                                            | Source Phase | Notes                                                                              |
| ----------------------------------------------- | ------------ | ---------------------------------------------------------------------------------- |
| Adaptive concurrency based on file size         | 37           | Fixed pool of 3 is sufficient; adaptive sizing adds complexity                     |
| FUSE write-coalescing for desktop batch uploads | 37           | Desktop uploads arrive one-at-a-time via `release()`; FUSE has no batch context    |
| Accumulated retry batching                      | 37           | Batch retries into single folder publish instead of N individual publishes         |
| AbortSignal support for in-flight batch uploads | 37           | No way to cancel once `uploadFiles()` invoked; needs AbortSignal through p-limit   |
| Lazy file reading within concurrency pool       | 37           | `useDropUpload` reads all files upfront; SDK needs `File` objects or read callback |

### Observability (Phases 28, 30)

| Item                                    | Source Phase | Notes                                    |
| --------------------------------------- | ------------ | ---------------------------------------- |
| `no-console` ESLint rule enforcement    | 28           | Optional enforcement mechanism           |
| Web Worker logging (MessagePort bridge) | 28           | Requires separate communication protocol |
| "Report a problem" user-facing button   | 30           | Nice-to-have, not in scope               |

### Sync & Conflict Resolution (Deferred to Milestone 4)

| Item                                         | Source Phase | Notes                                  |
| -------------------------------------------- | ------------ | -------------------------------------- |
| Offline operation queue (IndexedDB)          | 16           | Persist writes for replay on reconnect |
| Idempotent replay                            | 16           | Idempotency keys for queued operations |
| Auto-merge of non-conflicting folder changes | 16           | Three-way merge on encrypted metadata  |

### Data Management

| Item                                          | Source Phase | Notes                                                              |
| --------------------------------------------- | ------------ | ------------------------------------------------------------------ |
| TEE unenrollment on file/folder delete        | 12.6, 17     | Orphaned IPNS records expire naturally (24h) but waste TEE compute |
| TEE enrollment drift reconciliation           | 12.6         | Periodic vault scan to sync enrollment                             |
| User-configurable bin retention period        | 17           | End-user setting; operator env var exists but no per-user control  |
| Retroactive TEE enrollment for existing files | 25           | New files only; existing files not enrolled                        |
| Periodic reconciliation job for unenrollment  | 29           | Fire-and-forget pattern may be insufficient                        |

### Code Quality

| Item                                         | Source Phase | Notes                                                                                                                              |
| -------------------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Full retirement of folder.service.ts         | 31           | 1,059 lines, 9 importers; migrate callers to SDK methods                                                                           |
| Full retirement of bin.service.ts            | 31           | 971 lines, only `initializeBin` + `purgeExpired` still used by 2 hooks                                                             |
| Remove crypto -> core circular devDependency | 19.1         | Test-only import; refactor vault-ipns test to use hardcoded vectors                                                                |
| Deduplicate `uint8ToBase64` helper           | PR #448      | Duplicated in sdk-core/file, sdk-core/folder, web/ipns.service; extract to shared util in `@cipherbox/crypto` or `@cipherbox/core` |

## Items Implemented in Later Phases

These were deferred but have since been completed:

| Item                                      | Deferred From            | Implemented In |
| ----------------------------------------- | ------------------------ | -------------- |
| File versioning                           | v1.0 scope exclusion     | Phase 13       |
| User-to-user sharing                      | v1.0 scope exclusion     | Phase 14       |
| Read-write sharing                        | Phase 14                 | Phase 27       |
| Per-file IPNS metadata                    | Phase 12                 | Phase 12.6     |
| SDK extraction                            | Phase 11                 | Phase 19.1     |
| Rust SDK extraction                       | Phase 19.1               | Phase 23       |
| BYO IPFS node support                     | Phase 12.1               | Phase 21       |
| Vault key blob (zero-knowledge server)    | Phase 12                 | Phase 20       |
| Client-side search                        | Phase 15                 | Phase 15.1     |
| Performance baselines                     | Phase 18                 | Phase 22       |
| Link sharing                              | Phase 14                 | Phase 15       |
| Pagination on shares endpoints (L4)       | Phase 14 security review | Phase 14       |
| Structured logging wrapper for web app    | -                        | Phase 28       |
| Web Worker for large file encryption      | -                        | Phase 37       |
| Error tracking (Grafana Faro)             | Phase 28, 30             | Phase 30       |
| Desktop FUSE CTR streaming                | Phase 12.1               | Phase 12.1     |
| Linux FUSE mount                          | Phase 11.3               | Phase 11.3     |
| Per-file IPNS conflict detection          | Phase 16                 | Phase 12.6     |
| Batch upload secondary pin warning events | Phase 37                 | Phase 37       |
| Remote log shipping (Grafana Faro)        | Phase 28                 | Phase 30       |

<!-- Deferred inventory: 2026-03-31 -->
