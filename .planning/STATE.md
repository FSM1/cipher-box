---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: complete
last_updated: '2026-03-26T05:00:00.000Z'
progress:
  total_phases: 12
  completed_phases: 12
  total_plans: 53
  completed_plans: 53
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-07)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 27 — writable-shares-poc (COMPLETE)

## Current Position

Phase: 27 (writable-shares-poc) — COMPLETE
Plan: 3 of 3 (all plans complete)

## Performance Metrics

**Velocity:**

- Total plans completed: 161 (72 M1 + 83 M2 + 6 M3)
- Average duration: 5.5 min
- Total execution time: ~16.5 hours

| Phase | Plan | Duration | Tasks | Files |
| ----- | ---- | -------- | ----- | ----- |
| 19    | 01   | 2min     | 2     | 3     |
| 19    | 02   | 5min     | 2     | 5     |
| 19.1  | 02   | 4min     | 2     | 133   |
| 19.1  | 01   | 17min    | 2     | 42    |
| 19.1  | 03   | 12min    | 3     | 18    |
| 19.1  | 04   | 10min    | 2     | 14    |
| 19.1  | 06   | 13min    | 3     | 52    |
| 19.2  | 01   | 6min     | 2     | 4     |
| 19.2  | 02   | 12min    | 3     | 3     |
| 19.2  | 03   | 1min     | 1     | 1     |
| 19.2  | 04   | 71min    | 2     | 1     |
| 20    | 01   | 4min     | 2     | 5     |
| 20    | 02   | 17min    | 3     | 16    |
| 20    | 03   | 25min    | 2     | 6     |
| 20    | 04   | 45min    | 3     | 15    |
| 20    | 05   | 6min     | 2     | 13    |
| 20    | 06   | 6min     | 2     | 4     |
| 21    | 01   | 5min     | 2     | 9     |
| 21    | 03   | 10min    | 3     | 13    |
| 21    | 05   | 9min     | 2     | 13    |
| 21    | 04   | 8min     | 3     | 9     |
| 21    | 06   | 3min     | 2     | 4     |
| 21    | 07   | 5min     | 3     | 5     |
| 23    | 01   | 13min    | 2     | 26    |
| 23    | 02   | 10min    | 2     | 33    |
| 23    | 03   | 11min    | 2     | 23    |
| 23    | 05   | 12min    | 2     | 24    |
| 23    | 04   | 22min    | 2     | 17    |
| 23    | 07   | 7min     | 2     | 5     |
| 23    | 06   | 23min    | 2     | 7     |
| 23    | 08   | 20min    | 2     | 7     |
| 21    | 08   | 5min     | 2     | 6     |
| 21    | 10   | 5min     | 2     | 7     |
| 21    | 09   | 9min     | 3     | 17    |
| 21    | 11   | 12min    | 2     | 3     |
| 22    | 02   | 4min     | 2     | 2     |
| 22    | 01   | 8min     | 2     | 7     |
| 22    | 03   | 8min     | 2     | 8     |
| 26    | 02   | 4min     | 2     | 5     |
| 26    | 01   | 5min     | 2     | 6     |
| 27    | 01   | 6min     | 2     | 23    |
| 27    | 02   | 5min     | 2     | 4     |
| 27    | 03   | 25min    | 3     | 15    |

## Accumulated Context

### Key Decisions

See PROJECT.md Key Decisions table for full list with outcomes.

Recent for v1.1:

- Network-first with self-hosted Someguy + DB fallback adopted as IPNS resolution strategy (revised from DB-first during Phase 19 context -- see 19-SCOPING_RATIONALE.md #1)
- rootFolderKey DB copy kept as permanent fallback (never drop column, IPFS copy for recovery independence)
- BYO-IPFS affects pinning only, all IPNS publishes still route through CipherBox API
- PERF requirements split across Phase 18 (server-side, pre-change) and Phase 22 (client + load testing, post-change)
- IPFS/IPNS histogram buckets: 1ms-30s exponential (14 buckets); republish batch: 1s-120s (10 buckets)
- Source label (db/network) only for resolve operations; empty string for pin/cat/publish
- Alloy scrapes Kubo directly via Docker internal network (ipfs:5001), not proxied through API
- Kubo Health dashboard panels use fallback Go runtime metrics alongside libp2p metrics pending post-deploy verification
- IPNS-specific histograms: resolve 50ms-30s, publish 100ms-60s with source/outcome labels
- Null resolve results (not found) excluded from IPNS histogram observations
- Used axios-functions orval client for @cipherbox/api-client (plain functions, no React deps)
- sdk-core IPFS ops use direct axios/fetch (not api-client) for upload progress; IPNS ops use api-client generated functions
- Bin/share operations take explicit context objects (BinOperationContext, ShareOperationContext) instead of Zustand stores
- Share module accepts callback functions for API calls to stay transport-decoupled
- Moved @cipherbox/core from dependencies to devDependencies in crypto (test-only cross-package assertions)
- Kubo pebbleds datastore (LSM-tree) configured via IPFS_PROFILE=server,pebbleds; requires fresh volume on deploy
- SDK concurrent pins require pebbleds datastore (synergistic); concurrent pins alone cause regression at 50 clients
- Combined per-task commits into single commit due to pre-commit hook requiring api-client regeneration with entity/dto/controller changes
- Desktop root folder detected by inode::ROOT_INO at publish call sites (simpler than modifying build_folder_metadata return type)
- Desktop initialize_vault produces v2 blob for new users from day one (not just on migration)
- decrypt_metadata_from_ipfs_public transparently handles both v1 JSON and v2 binary blobs
- VaultExportDto returns only rootIpnsName and derivationMethod (crypto columns dropped)
- Recovery tool IPNS resolution uses gateway /ipns/ HEAD request with redirect following (most reliable without API dependency)
- fetchAndDecryptMetadata handles both v1 JSON and v2 binary blobs transparently for folder sync
- Zero-crypto vault schema: server stores only ownerPublicKey and rootIpnsName, all crypto material lives exclusively in IPFS v2 blobs
- DB crypto columns (encrypted_root_folder_key, encrypted_root_ipns_private_key, migrated_at) fully dropped — no fallback paths
- PinningProvider interface: KuboProvider uses Basic auth, PsaProvider uses Bearer auth, matching each protocol's native auth model
- PsaProvider.pin() throws intentionally; pinByCid() is the correct PSA workflow (CID-reference-only protocol)
- Connection test uses sequential probe: Kubo /api/v0/id first, then PSA /pins, with 10s timeout per probe
- CID registration gated to BYO users only via ForbiddenException (non-BYO users cannot bypass upload relay)
- Advisory quota: checkQuota() always true for BYO, getQuota() includes advisory boolean flag for UI display
- pinFn injection pattern: optional pinFn parameter on sdkCore.uploadFile() replaces addToIpfs when BYO mode active
- External+Kubo bypasses CipherBox entirely; external+PSA uses relay for CID only; dual does both with best-effort secondary
- PsaProvider.pinByCid() accessed via cast in client.ts (PSA-specific, not on PinningProvider interface)
- Migration uses existing BullMQ pattern with pin-migration queue name; TEE decrypts ECIES-encrypted provider configs in-enclave with epoch key
- SSRF protection on TEE migration: validates URL structure (HTTPS-only, no private IPs) and DNS resolution (rebinding check)
- BYO config stored as encrypted IPNS entry using rootFolderKey — no server-side credential storage (zero-knowledge preserved)
- Dedicated IPNS key derived via HKDF with context string byo-ipfs-config from vault keypair
- BYO benchmark execution (21-07 Task 4) deferred — requires external IPFS provider infrastructure; test scenarios ready to run when provider available
- BYO config loaded at login via IPNS resolve with graceful fallback to cipherbox-only mode
- Source unpin is best-effort and non-fatal after verified CID transfer to destination
- Cargo workspace with centralized deps at repo root; cipherbox-crypto crate as foundation for all Rust SDK extraction
- Module re-export pattern in desktop crypto/mod.rs preserves all existing crate::crypto::\* paths without touching call sites
- cipherbox-core crate layered on cipherbox-crypto: folder, file, bin, vault_blob, ipns, registry, decrypt, error modules
- File module re-exports FileMetadata types from folder.rs (shared AES encryption context with parent folder key)
- decrypt module moved from fuse to crypto re-export (domain logic, not FUSE-specific)
- Hand-structured API client crate rather than openapi-generator (modest API surface, proven code, no Java/Docker CI dependency)
- critical-section std feature required for standalone ecies linking (Tauri provides it in desktop builds)
- Shared test vectors in tests/vectors/ JSON files loadable by both Rust and TypeScript for CI parity gates
- SyncDaemon uses Arc<dyn Fn(SyncStatus)> generic callback instead of Tauri AppHandle for testability
- Desktop api/client.rs re-exports cipherbox_api_client::ApiClient as type alias to unify types across modules
- Desktop AppState wraps Arc<KeyState> from SDK; all key material accessed via state.sdk.\*
- Keychain operations kept as desktop-specific keychain.rs module (not in api-client crate)
- Desktop api/ and crypto/ directories fully removed; all imports use workspace crates directly
- CI parity gate uses needs.changes.outputs.src (not nonexistent packages) for trigger condition
- Desktop-e2e binary paths updated to target/debug/ to match workspace cargo build output
- PinataProvider uses dual base URLs: uploads.pinata.cloud (fixed) for upload, api.pinata.cloud (configurable) for management
- pinWithMode treats Pinata like Kubo: direct upload bypasses CipherBox relay entirely
- Connection test probe order updated: Kubo -> Pinata -> PSA; pinata.cloud URLs skip Kubo probe
- BYO Pinata baselines: pin p50=2.0s (+47% vs local Kubo), tail latency p99 13.5% better, 98% CipherBox API load reduction per file
- perf.ts PERF_ENABLED evaluated once at module load (zero overhead in production); **CIPHERBOX_PERF** global for opt-in production debugging
- Load test thresholds set at 2-3x observed baselines; spike test most generous (15s/15%); vitest expect() for CI failure on breach
- Write-share authorization in upsertFolderIpns falls through to create-new-entry when no write share found (preserves backward compat for owner first publish)
- TEE enrollFolder uses existing.userId (FolderIpns owner) for write-share publishes, not authenticated userId
- Per-file IPNS records created for shared uploads (same as owner uploads) instead of empty fileMetaIpnsName PoC shortcut
- File IPNS private key dual-wrapped: owner key in FilePointer, recipient key in share_keys (keyType: file-ipns)
- addShareKeys API relaxed to allow write-share recipients to add keys to their own share
- TextEditorDialog has separate shared file save path via onSaveSharedFile callback
- Shared file download/view falls back to fileKeyEncrypted from metadata when no share_key exists

### Roadmap Evolution

- Phase 19.1 inserted after Phase 19: Extract core crypto SDK as shared package (URGENT)
- Phase 19.2 inserted after Phase 19: IPFS Upload Performance Optimization (URGENT) — concurrent pins, Kubo worker tuning, pin batching to address ~95% bottleneck in upload path identified by Phase 19 baselines
- Phase 23 added: Rust SDK Extraction — extract shared cipherbox-core crate, replace duplicated logic in desktop FUSE code, enable unit testing parity with TypeScript
- Phase 27 added: Writable Shares (PoC) — extend read-only sharing to read-write using existing server-coordinated conflict resolution

### Open Concerns

- 9 LOW-priority tech debt items from M2 audit (see `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`)
- rootFolderKey migration dual-write window duration TBD (forced migration strategy for dormant accounts)
- BYO-IPFS auth token storage model needs explicit acceptance (server sees token but not plaintext content)
- Kubo v0.34.0 -> v0.40.1 upgrade decision (recommended before Phase 19, not blocking)
- Recovery tool independence verified for v2 blobs (root-level works; subfolder limited by IPNS DHT propagation)

### Pending Todos

10 items in `.planning/todos/pending/` — see `/gsd:check-todos` for full list.

### Resolved

All M2 blockers resolved. See `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`.

### Quick Tasks Completed

| #          | Description                                                   | Date       | Commit     | Directory                                                                                                           |
| ---------- | ------------------------------------------------------------- | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------- |
| 260327-2ab | Extract shared-write operations from web UI into SDK packages | 2026-03-27 | see branch | [260327-2ab-extract-shared-write-operations-from-web](./quick/260327-2ab-extract-shared-write-operations-from-web/) |

---

Last activity: 2026-03-27 - Completed quick task 260327-2ab: Extract shared-write operations from web UI into SDK packages
