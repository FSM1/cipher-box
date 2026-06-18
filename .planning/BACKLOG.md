# Backlog

> Pending ideas and deferred work. Consolidated 2026-06-12 from the former `.planning/DEFERRED.md` and `.planning/REFACTORING.md` (gsd-health W019 remediation).

## v1.1 Tech Debt Close-out (2026-06-18)

A full tech-debt sweep of milestone v1.1 (phases 18–49) — including the phase 42/43 `REVIEW.md`
code reviews and in-code TODOs — was consolidated and verified against current code. See the
ledger at [`reports/TECH_DEBT-v1.1.md`](reports/TECH_DEBT-v1.1.md) (companion to
[`reports/MILESTONE_SUMMARY-v1.1.md`](reports/MILESTONE_SUMMARY-v1.1.md)).

Net-new, verified-open items promoted to `.planning/todos/pending/` (not previously tracked):

- `2026-06-18-phase42-unpin-integrity-review-open-findings.md` — **high**; incl. WR-01 advisory-lock `INT_MIN` overflow (permanent undeletability) and WR-03 stale-outbox re-pin race (data loss), plus 10 more WR/IN items.
- `2026-06-18-fuse-journal-growth-and-replay-timeout.md` — **high**; WR-06 unbounded journal + full ciphertext in JSON (no GC/purge), WR-07 replay has no network timeout, + IN-03/04/05.
- `2026-06-18-web-logger-redaction-and-faro-transport-unwired.md` — **med**; logger `redact()` never implemented, `registerFaroTransport` defined but never called (warn/error not reaching Faro).
- `2026-06-18-unenroll-skips-unloaded-subtrees.md` — **med**; `collectSubtreeIpnsNames` only walks loaded folders.
- `2026-06-18-gsd-verification-gaps-phases-18-31-32.md` — **med**; phases 18/31/32 still lack `VERIFICATION.md` (PERF-01..04 orphaned).

Verified resolved during the sweep (so they are not re-filed): phase 43 critical findings CR-01..CR-08
(fixed 2026-06-14) and most of its warnings (closed by phases 45/46); phase 42 WR-04 (Counter is
acceptable). Already-tracked v1.1 deferrals (sharing, desktop signing, upload-pipeline P37, Kubo ACL,
`uint8ToBase64` Tier 3.3, etc.) remain in the inventory below and are referenced, not duplicated, by
the ledger.

## Status Reconciliation (2026-06-13)

The inventories below are a verbatim snapshot dated 2026-03-31 and predate phases 36-44. They were reviewed against the current codebase on 2026-06-13. The original tables are preserved unchanged for the historical record; the current status of changed items is authoritative here.

### Now implemented (previously listed as open)

| Item                                                           | Section             | Shipped in                                                                                                                        |
| -------------------------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Full retirement of `folder.service.ts`                         | Code Quality        | Phase 38 / PR #422 — file deleted, 0 importers                                                                                    |
| Full retirement of `bin.service.ts`                            | Code Quality        | Phase 38 / PR #422 — deleted, logic moved to SDK                                                                                  |
| Remove crypto → core circular devDependency                    | Code Quality        | Phase 38 / PR #422                                                                                                                |
| User-configurable bin retention period                         | Data Management     | Phase 39 — per-user `VaultSettings.recycleBinRetentionDays`                                                                       |
| Auto-merge of non-conflicting folder changes (three-way merge) | Sync & Conflict     | Phase 44 — `mergeChildren` in `sdk-core/folder/merge.ts`                                                                          |
| M5 — `reWrapForRecipients` surfaces failures                   | Security (Phase 14) | Done — failure toast + `share:reWrapFailed` event. Residual: file-update caller ignores `failedRecipients`; no desktop subscriber |
| L1 — `/shares/lookup` always returns 200 `{ exists }`          | Security (Phase 14) | Done — no 404/200 oracle                                                                                                          |
| Tier 3.6 — `InitVaultDto` uses generated type                  | Refactoring         | Done                                                                                                                              |
| Tier 3.9 — `publishBatch` delegates to shared `publishRecord`  | Refactoring         | Done                                                                                                                              |

### Still open, promoted to actionable todos (2026-06-13)

These were genuinely open and tracked nowhere actionable (only in stale review docs + this snapshot), so they are now `.planning/todos/pending/`:

- **M1** — share `itemName` stored plaintext at rest → `2026-06-13-encrypt-share-itemname-at-rest.md`
- **S1, S2, S3** — IPNS signed-record validation, verification enforcement, key-zeroization convention → `2026-06-13-ipns-signature-storage-review-deferred.md`

### Still open, remaining in this backlog

All other items below remain open and correctly tracked here: the deferred feature set (sharing, desktop UI, MFA, performance, etc.), the `uint8ToBase64` dedup (Tier 3.3 — confirmed still 4-5 copies, no shared util), and Tier-3 cleanups 3.1, 3.2, 3.4, 3.5, 3.7, 3.8, 3.10, 3.11, 3.12, 3.13, 3.14.

## Deferred Items Inventory

**Last updated:** 2026-03-31

Items deferred across milestones v1.0 (phases 11-17.1) and v1.1 (phases 18-37).
Cross-referenced with `.planning/todos/pending/` and security review findings.

### Active Pending Todos

These are explicitly tracked in `.planning/todos/pending/`:

| Date       | Item                                                             | Priority |
| ---------- | ---------------------------------------------------------------- | -------- |
| 2026-02-14 | ERC-1271 contract wallet authentication (Safe, Argent, Sequence) | Low      |
| 2026-02-22 | CRDT-based IPNS inbox for serverless share discovery             | Research |
| 2026-02-24 | Make search index build async/incremental for large vaults       | Medium   |
| 2026-02-26 | Alternative MFA factor types (passkeys, password-derived)        | Medium   |
| 2026-03-23 | Investigate removal of mock-ipns-routing layer (someguy works)   | Low      |

### Security Review Findings (Deferred from Phase 14)

From `.planning/todos/done/2026-02-21-phase14-security-review-deferred.md`:

| ID  | Severity | Item                                                                    | Status      |
| --- | -------- | ----------------------------------------------------------------------- | ----------- |
| M1  | Medium   | `itemName` stored plaintext on server -- encrypt with recipient pubkey  | Open        |
| M5  | Medium   | `reWrapForRecipients` silently swallows errors -- surface notifications | Open        |
| L1  | Low      | `/shares/lookup` enables public key enumeration -- always return 200    | Open        |
| L4  | Low      | No pagination on shares endpoints -- add limit/offset                   | Implemented |

### Security Review Findings (Deferred from IPNS Signature Storage PR #448)

From `.planning/security/REVIEW-20260402-172126.md`:

| ID  | Severity | Item                                                                                                       | Status   |
| --- | -------- | ---------------------------------------------------------------------------------------------------------- | -------- |
| S1  | Medium   | Validate signedRecord on publish: parse embedded CID/sequence and reject mismatches with dto fields        | Open     |
| S2  | Medium   | Signature verification silently skipped when server omits fields (downgrade) -- enforce once data is ready | Deferred |
| S3  | Medium   | Inconsistent private key zeroization -- establish caller-owns-key convention across SDK                    | Deferred |

### Deferred by Category

##### Sharing & Collaboration

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

##### Desktop Platform

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

##### Authentication & Security

| Item                                    | Source Phase | Notes                                             |
| --------------------------------------- | ------------ | ------------------------------------------------- |
| ERC-1271 contract wallet authentication | 12           | Smart contract wallets need on-chain verification |
| Alternative MFA factor types            | 12           | Passkeys (WebAuthn PRF), password-derived keys    |
| WalletConnect QR code flow              | 11.1         | Only injected provider MVP currently              |
| Social recovery (Shamir Secret Sharing) | 12           | High complexity                                   |

##### Performance & Infrastructure

| Item                                           | Source Phase | Notes                                                   |
| ---------------------------------------------- | ------------ | ------------------------------------------------------- |
| Async/incremental search index                 | 15.1         | `buildFromFolderTree()` blocks UI for large vaults      |
| BYO IPFS provider benchmarks                   | 21           | Requires external provider infrastructure               |
| Automated CI timing gates                      | 26           | Flaky due to runner variance                            |
| Remove mock-ipns-routing                       | 19           | Someguy at `<docker-host>:8190` may replace it          |
| Push notifications (WebSocket sync)            | 16           | Currently polling-only; requires backend infra          |
| Batch API endpoint for IPNS resolves           | 32           | Could reduce round trips for folders with many files    |
| Kubo API access control (reverse proxy or ACL) | 29           | Current Docker 127.0.0.1 binding sufficient for staging |

##### Upload Pipeline (Phase 37)

| Item                                            | Source Phase | Notes                                                                              |
| ----------------------------------------------- | ------------ | ---------------------------------------------------------------------------------- |
| Adaptive concurrency based on file size         | 37           | Fixed pool of 3 is sufficient; adaptive sizing adds complexity                     |
| FUSE write-coalescing for desktop batch uploads | 37           | Desktop uploads arrive one-at-a-time via `release()`; FUSE has no batch context    |
| Accumulated retry batching                      | 37           | Batch retries into single folder publish instead of N individual publishes         |
| AbortSignal support for in-flight batch uploads | 37           | No way to cancel once `uploadFiles()` invoked; needs AbortSignal through p-limit   |
| Lazy file reading within concurrency pool       | 37           | `useDropUpload` reads all files upfront; SDK needs `File` objects or read callback |

##### Observability (Phases 28, 30)

| Item                                    | Source Phase | Notes                                    |
| --------------------------------------- | ------------ | ---------------------------------------- |
| `no-console` ESLint rule enforcement    | 28           | Optional enforcement mechanism           |
| Web Worker logging (MessagePort bridge) | 28           | Requires separate communication protocol |
| "Report a problem" user-facing button   | 30           | Nice-to-have, not in scope               |

##### Sync & Conflict Resolution (Deferred to Milestone 4)

| Item                                         | Source Phase | Notes                                  |
| -------------------------------------------- | ------------ | -------------------------------------- |
| Offline operation queue (IndexedDB)          | 16           | Persist writes for replay on reconnect |
| Idempotent replay                            | 16           | Idempotency keys for queued operations |
| Auto-merge of non-conflicting folder changes | 16           | Three-way merge on encrypted metadata  |

##### Data Management

| Item                                          | Source Phase | Notes                                                              |
| --------------------------------------------- | ------------ | ------------------------------------------------------------------ |
| TEE unenrollment on file/folder delete        | 12.6, 17     | Orphaned IPNS records expire naturally (24h) but waste TEE compute |
| TEE enrollment drift reconciliation           | 12.6         | Periodic vault scan to sync enrollment                             |
| User-configurable bin retention period        | 17           | End-user setting; operator env var exists but no per-user control  |
| Retroactive TEE enrollment for existing files | 25           | New files only; existing files not enrolled                        |
| Periodic reconciliation job for unenrollment  | 29           | Fire-and-forget pattern may be insufficient                        |

##### Code Quality

| Item                                         | Source Phase | Notes                                                                                                                              |
| -------------------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Full retirement of folder.service.ts         | 31           | 1,059 lines, 9 importers; migrate callers to SDK methods                                                                           |
| Full retirement of bin.service.ts            | 31           | 971 lines, only `initializeBin` + `purgeExpired` still used by 2 hooks                                                             |
| Remove crypto -> core circular devDependency | 19.1         | Test-only import; refactor vault-ipns test to use hardcoded vectors                                                                |
| Deduplicate `uint8ToBase64` helper           | PR #448      | Duplicated in sdk-core/file, sdk-core/folder, web/ipns.service; extract to shared util in `@cipherbox/crypto` or `@cipherbox/core` |

### Items Implemented in Later Phases

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

---

## CipherBox Refactoring Tracker

> Identified 2026-03-02 | Branch: `refactor/quick-wins`

### Tier 1: High-Impact Quick Wins

##### 1.1 Extract file-type utilities (Web) — ~150 lines eliminated

- [x] **Status:** DONE
- **Files:** `FileBrowser.tsx`, `SharedFileBrowser.tsx`
- **Problem:** 7 identical functions + 5 identical constant Sets copy-pasted between both files (`isTextFile`, `isImageFile`, `isPdfFile`, `isAudioFile`, `isVideoFile`, `isPreviewableFile`, `isFilePointer`, plus `TEXT_EXTENSIONS`, `IMAGE_EXTENSIONS`, etc.)
- **Fix:** Extract to `apps/web/src/utils/fileTypes.ts`

##### 1.2 Extract `DelegatedRoutingClient` (API) — ~300 lines consolidated

- [x] **Status:** DONE
- **Files:** `apps/api/src/ipns/ipns.service.ts` (560 lines), `apps/api/src/republish/republish.service.ts` (446 lines)
- **Problem:** Duplicated exponential-backoff retry loops with 429/Retry-After handling, identical `delay()` helper, identical `DELEGATED_ROUTING_URL` config lookups, same URL template construction
- **Fix:** New injectable `DelegatedRoutingClient` service with `publish()` and `resolve()` methods

##### 1.3 Extract shared FUSE helpers (Desktop Rust) — ~494 lines eliminated

- [x] **Status:** DONE
- **Files:** `fuse/operations.rs` (2,602 lines), `fuse/windows/operations.rs` (2,644 lines)
- **Problem:** 5 exact-duplicate functions across macOS and Windows backends:
  - `fetch_and_decrypt_content_async` — byte-for-byte identical
  - `publish_file_metadata` — near-identical
  - `fetch_and_populate_folder` — near-identical
  - `resolve_file_pointers_blocking` — near-identical
  - `mime_from_extension` — exact duplicate (35 MIME mappings)
  - Plus 4 duplicated constants (`QUOTA_BYTES`, `MAX_VERSIONS_PER_FILE`, `VERSION_COOLDOWN_MS`, `CONTENT_DOWNLOAD_TIMEOUT`)
  - Plus 3 private copies of `decrypt_metadata_from_ipfs` when `fuse::decrypt::decrypt_metadata_from_ipfs_public` already exists
- **Fix:** Move to `fuse/helpers.rs` and `fuse/constants.rs`

##### 1.4 Extract `useDialogState` hook (Web) — simplifies `FileBrowser.tsx`

- [x] **Status:** DONE
- **Files:** `apps/web/src/components/file-browser/FileBrowser.tsx` (1,153 lines)
- **Problem:** 12 separate `useState` calls for dialog state + 18 open/close callbacks that are all one-liners
- **Fix:** Create `useDialogState<T>()` hook returning `[state, open, close]`

---

### Tier 2: Medium-Impact Structural Splits

##### 2.1 Split `useFolder.ts` (1,262 lines) into 3 hooks

- [x] **Status:** DONE
- **Files:** `apps/web/src/hooks/useFolder.ts`
- **Problem:** 11 async operations with identical try/catch/setState boilerplate (repeated 11x), `resolveFolderById` pattern (repeated 10x), lazy IPNS migration block (repeated 3x)
- **Fix:** Split into `useFolderMutations`, `useFileOperations`, `useFileVersions`; extract `withLoading()` wrapper and `resolveFolderById()` helper

##### 2.2 Split `AuthService` (669 lines, 8 injected deps)

- [x] **Status:** DONE
- **Files:** `apps/api/src/auth/auth.service.ts`
- **Problem:** 6 distinct responsibilities, cross-domain dependencies (IPFS in auth)
- **Fix:** Split into `AuthService` (core), `AuthMethodService`, `AccountService`, `TestAuthService`

##### 2.3 Split `SharesService` (569 lines)

- [x] **Status:** DONE
- **Files:** `apps/api/src/shares/shares.service.ts`
- **Problem:** Natural seam at line 334 (`// Invite link methods`); controllers already split but service is monolith
- **Fix:** Extract `ShareInviteService` for invite methods

##### 2.4 Split `commands.rs` (907 lines) into modules

- [x] **Status:** DONE
- **Files:** `apps/desktop/src-tauri/src/commands.rs`
- **Problem:** All Tauri IPC commands in one file, `parse_private_key_hex` duplicated 3x
- **Fix:** Split into `commands/auth.rs`, `commands/vault.rs`, `commands/sync.rs`, `commands/debug.rs`, `commands/oauth.rs`

##### 2.5 Split FUSE operations by category

- [x] **Status:** DONE
- **Files:** `fuse/operations.rs`, `fuse/windows/operations.rs`
- **Problem:** Each file >2,600 lines with all filesystem callbacks mixed together
- **Fix:** Split into `read_ops.rs`, `write_ops.rs`, `dir_ops.rs` for each platform

##### 2.6 Extract Redis module (API)

- [x] **Status:** DONE
- **Files:** `auth.service.ts`, `email-otp.service.ts`, `identity.controller.ts`
- **Problem:** Same `new Redis({...})` + `ConfigService` lookup + `OnModuleDestroy` quit pattern repeated 3x
- **Fix:** Create `RedisModule` with shared `REDIS_CLIENT` injection token

---

### Tier 3: Lower-Priority Cleanup

| #    | Issue                                           | Location                                               | Fix                                                 | Status |
| ---- | ----------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------- | ------ |
| 3.1  | `RequestWithUser` defined twice                 | `auth.controller.ts` + `common/types.ts`               | Delete local copy, import from common               | TODO   |
| 3.2  | `findShareOrThrow` pattern 6x                   | `shares.service.ts`                                    | Extract private helper                              | TODO   |
| 3.3  | `uint8ToBase64` duplicated                      | `folder.service.ts` + `file-metadata.service.ts`       | Move to `utils/encoding.ts`                         | TODO   |
| 3.4  | `truncatePublicKey`/`truncatePubkey`            | `ShareDialog.tsx` + `SharedFileBrowser.tsx`            | Add to existing `utils/format.ts`                   | TODO   |
| 3.5  | `MAX_FOLDER_DEPTH = 20` defined 3x              | `folder.service.ts`, `useFolder.ts`, `MoveDialog.tsx`  | Single export from folder.service                   | TODO   |
| 3.6  | `InitVaultDto` hand-written alongside generated | `lib/api/vault.ts` vs `api/models/`                    | Delete hand-written, use generated                  | TODO   |
| 3.7  | REQUIRED_SHARE block 3x in `useAuth`            | `loginWithGoogle`, `loginWithEmail`, `loginWithWallet` | Extract `handleRequiredShare()` helper              | TODO   |
| 3.8  | Controller has repo access + business logic     | `identity.controller.ts`                               | Move `findOrCreateUserByIdentifier` to service      | TODO   |
| 3.9  | `publishBatch` duplicates single-record logic   | `ipns.service.ts`                                      | Extract `processSingleRecord` helper                | TODO   |
| 3.10 | Inline IPFS fetch+decode 4x                     | `useSharedNavigation.ts`                               | Reuse existing `fetchAndDecryptMetadata`            | TODO   |
| 3.11 | Catch variable inconsistency                    | 206 catch blocks use `err`/`error`/`e` randomly        | Pick one, add ESLint rule                           | TODO   |
| 3.12 | Metrics 100-line constructor                    | `metrics.service.ts`                                   | Extract `initializeMetrics()` method                | TODO   |
| 3.13 | `publicKey` 0x-normalization 2x                 | `shares.service.ts`                                    | Extract `normalizePublicKey()` to `common/utils.ts` | TODO   |
| 3.14 | `toVaultResponse` + TEE fetch 3x                | `vault.service.ts`                                     | Extract `toVaultResponseWithTeeKeys()`              | TODO   |

---

### Architecture Notes (Not Bugs, Monitor)

- **Desktop `auth.ts` (771 lines) parallels web `useAuth.ts` (510 lines)** — structural duplication from Tauri/browser split. Can't easily share.
- **12 services call `useStore.getState()` directly** — valid Zustand pattern but implicit coupling. No circular deps.
- **`generate-openapi.ts` has 39 manual imports** — must update when adding controllers. Consider auto-discovery.
- **Rust IPNS implementation (408 lines hand-rolled CBOR/protobuf)** parallels TypeScript `ipns` npm package — risks silent divergence.
- **`pendingPublishes: Set<string>` in folder store** — may be unused dead code. Audit and remove if so.
- **`quota.store.ts` calls `vaultApi` directly** — inverted dependency direction (store has network dependency).
