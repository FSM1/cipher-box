---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: Executing Phase 59
last_updated: "2026-06-23T19:48:00.000Z"
last_activity: 2026-06-23
progress:
  total_phases: 45
  completed_phases: 43
  total_plans: 190
  completed_plans: 187
  percent: 96
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-07)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 59 — fuse-ipns-verify-publish-hardening-and-cleanup

## Current Position

Phase: 59 (fuse-ipns-verify-publish-hardening-and-cleanup) — EXECUTING
Plan: 2 of 4
Milestone v1.1 hardening block extended 2026-06-21 with deferred-findings Phases 56–58 (HARD-07..09), sourced from the Phase 50–55 / PR #529 + #538 review backlog. Next: run /gsd:plan-phase 58 (recommended order was 56 FUSE/IPNS durability → 57 API CID/provider hardening → 58 IPNS signature-verify coverage; 58 last as it is the most regression-prone and full-SDK-E2E-gated). Note: STATE frontmatter progress counts are approximate and were periodically unreconciled (see todo `2026-06-18-gsd-phase-complete-regresses-state-final-phase.md`).

## Performance Metrics

**Velocity:**

- Total plans completed: 164 (all 34 milestone v1.1 phases; every PLAN has a SUMMARY)
- Average duration: 5.5 min
- Total execution time: ~16.5 hours

| Plan            | Duration | Tasks   | Files     |
| --------------- | -------- | ------- | --------- |
| Phase 18 P01    | 7min     | 2 tasks | -         |
| Phase 18 P02    | 5min     | 3 tasks | -         |
| Phase 19 P01    | 2min     | 2 tasks | 3 files   |
| Phase 19 P02    | 5min     | 2 tasks | 5 files   |
| Phase 19.1 P01  | 17min    | 2 tasks | 42 files  |
| Phase 19.1 P02  | 4min     | 2 tasks | 133 files |
| Phase 19.1 P03  | 12min    | 3 tasks | 18 files  |
| Phase 19.1 P04  | 10min    | 2 tasks | 14 files  |
| Phase 19.1 P05  | -        | 3 tasks | -         |
| Phase 19.1 P06  | 13min    | 3 tasks | 52 files  |
| Phase 19.2 P01  | 6min     | 2 tasks | 4 files   |
| Phase 19.2 P02  | 12min    | 3 tasks | 3 files   |
| Phase 19.2 P03  | 1min     | 1 tasks | 1 files   |
| Phase 19.2 P04  | 71min    | 2 tasks | 1 files   |
| Phase 20 P01    | 4min     | 2 tasks | 5 files   |
| Phase 20 P02    | 17min    | 3 tasks | 16 files  |
| Phase 20 P03    | 25min    | 2 tasks | 6 files   |
| Phase 20 P04    | 45min    | 3 tasks | 15 files  |
| Phase 20 P05    | 6min     | 2 tasks | 13 files  |
| Phase 20 P06    | 6min     | 2 tasks | 4 files   |
| Phase 21 P01    | 5min     | 2 tasks | 9 files   |
| Phase 21 P02    | 6min     | 2 tasks | -         |
| Phase 21 P03    | 10min    | 3 tasks | 13 files  |
| Phase 21 P04    | 8min     | 3 tasks | 9 files   |
| Phase 21 P05    | 9min     | 2 tasks | 13 files  |
| Phase 21 P06    | 3min     | 2 tasks | 4 files   |
| Phase 21 P07    | 5min     | 4 tasks | 5 files   |
| Phase 21 P08    | 5min     | 2 tasks | 6 files   |
| Phase 21 P09    | 9min     | 3 tasks | 17 files  |
| Phase 21 P10    | 5min     | 2 tasks | 7 files   |
| Phase 21 P11    | 12min    | 2 tasks | 3 files   |
| Phase 22 P01    | 8min     | 2 tasks | 7 files   |
| Phase 22 P02    | 4min     | 2 tasks | 2 files   |
| Phase 22 P03    | 8min     | 2 tasks | 8 files   |
| Phase 23 P01    | 13min    | 2 tasks | 26 files  |
| Phase 23 P02    | 10min    | 2 tasks | 33 files  |
| Phase 23 P03    | 11min    | 2 tasks | 23 files  |
| Phase 23 P04    | 22min    | 2 tasks | 17 files  |
| Phase 23 P05    | 12min    | 2 tasks | 24 files  |
| Phase 23 P06    | 23min    | 2 tasks | 7 files   |
| Phase 23 P07    | 7min     | 2 tasks | 5 files   |
| Phase 23 P08    | 20min    | 2 tasks | 7 files   |
| Phase 24 P01    | 10min    | 2 tasks | -         |
| Phase 24 P02    | 4min     | 2 tasks | -         |
| Phase 24 P03    | 7min     | 2 tasks | -         |
| Phase 25 P01    | 5min     | 2 tasks | -         |
| Phase 25 P02    | 4min     | 2 tasks | -         |
| Phase 25 P03    | -        | 2 tasks | -         |
| Phase 26 P01    | 5min     | 2 tasks | 6 files   |
| Phase 26 P02    | 4min     | 2 tasks | 5 files   |
| Phase 27 P01    | 6min     | 2 tasks | 23 files  |
| Phase 27 P02    | 5min     | 2 tasks | 4 files   |
| Phase 27 P03    | 25min    | 3 tasks | 15 files  |
| Phase 28 P01    | -        | -       | -         |
| Phase 28 P02    | -        | -       | -         |
| Phase 28 P03    | -        | -       | -         |
| Phase 28 P04    | -        | -       | -         |
| Phase 29 P01    | 5min     | 2 tasks | -         |
| Phase 29 P02    | 8min     | 3 tasks | -         |
| Phase 29 P03    | 3min     | 2 tasks | -         |
| Phase 30 P01    | 5min     | 3 tasks | -         |
| Phase 30 P02    | 3min     | 3 tasks | -         |
| Phase 30 P03    | 3min     | 3 tasks | -         |
| Phase 30 P04    | 3min     | 3 tasks | -         |
| Phase 31 P01    | -        | 3 tasks | -         |
| Phase 31 P02    | -        | 3 tasks | -         |
| Phase 31 P03    | -        | 4 tasks | -         |
| Phase 32 P01    | -        | 2 tasks | -         |
| Phase 32 P02    | -        | 2 tasks | -         |
| Phase 32 P03    | -        | 1 tasks | -         |
| Phase 33 P01    | 11min    | 2 tasks | 3 files   |
| Phase 33 P02    | 3min     | 1 tasks | 3 files   |
| Phase 34 P01    | 3min     | 2 tasks | 9 files   |
| Phase 34 P02    | 4min     | 2 tasks | 8 files   |
| Phase 34 P03    | 2min     | 1 tasks | 1 files   |
| Phase 34 P04    | 25min    | 2 tasks | -         |
| Phase 35 P01    | 10min    | 8 tasks | -         |
| Phase 35 P02    | 5min     | 4 tasks | 6 files   |
| Phase 35 P03    | 8min     | 4 tasks | 14 files  |
| Phase 35 P04    | 2min     | 2 tasks | -         |
| Phase 35 P05    | 5min     | 3 tasks | 3 files   |
| Phase 35 P06    | 45min    | 5 tasks | -         |
| Phase 36 P01    | 2min     | 2 tasks | -         |
| Phase 36 P02    | 5min     | 2 tasks | -         |
| Phase 37 P01    | 8min     | 2 tasks | -         |
| Phase 37 P02    | 5min     | 2 tasks | 5 files   |
| Phase 38 P01-04 | -        | -       | -         |
| Phase 39 P01-02 | -        | -       | -         |
| Phase 39 P03    | -        | -       | -         |
| Phase 39 P04    | -        | -       | -         |
| Phase 40 P01    | 4min     | 2 tasks | 6 files   |
| Phase 40 P02    | 7min     | 2 tasks | 8 files   |
| Phase 41 P01    | 4min     | 2 tasks | 6 files   |
| Phase 41 P02    | 3min     | 2 tasks | 2 files   |
| Phase 41 P03    | 3min     | 2 tasks | 2 files   |
| Phase 41 P04    | 2min     | 2 tasks | 2 files   |
| Phase 41 P05    | 3min     | 2 tasks | 3 files   |
| Phase 45 P01    | 8min     | 2 tasks | 2 files   |
| Phase 45 P02    | 8min     | 1 tasks | 3 files   |
| Phase 45 P03 | 7min | 2 tasks | 4 files |
| Phase 45 P04 | 8min | 1 tasks | 2 files |
| Phase 45 P05 | 12 | 2 tasks | 1 files |
| Phase 45 P06 | 90 | - tasks | - files |
| Phase 48 P01 | 15min | 3 tasks | 4 files |
| Phase 48 P02 | 2min | 2 tasks | 5 files |
| Phase 48 P03 | 6min | 3 tasks | 7 files |
| Phase 48 P05 | 8min | 3 tasks | 145 files |
| Phase 48 P06 | 18min | 3 tasks | 5 files |
| Phase 49 P01 | 13min | 2 tasks | 5 files |
| Phase 49 P02 | 15min | 1 tasks | 1 files |
| Phase 49 P03 | 11min | 4 tasks | 7 files |
| Phase 49 P04 | 26min | 3 tasks | 5 files |
| Phase 49 P05 | 12min | 2 tasks | 2 files |
| Phase 51 P01 | 9min | 3 tasks | 2 files |
| Phase 51 P03 | 45min | 4 tasks | 12 files |
| Phase 51 P04 | 12min | 3 tasks | 6 files |
| Phase 56 P01 | 45min | 3 tasks | 5 files |
| Phase 56 P02 | 90min | 3 tasks | 8 files |
| Phase 58 P01 | 45 | 5 tasks | 10 files |
| Phase 58-ipns-signature-verify-coverage P02 | 30min | 3 tasks | 2 files |
| Phase 58-ipns-signature-verify-coverage P04 | 25min | 3 tasks | 4 files |
| Phase 59 P01 | 35min | 2 tasks | 2 files |
| Phase 59 P02 | 4min | 2 tasks | 6 files |

## Accumulated Context

### Key Decisions

See PROJECT.md Key Decisions table for full list with outcomes.

Recent for v1.1:

- make_temp_queue in crates/sdk/src/queue.rs uses pid+counter (not tid+counter) to prevent inter-run temp dir collisions (Phase 45 P01 Rule-1 fix)
- T-45-07 uses root-shortcut path (folder_ipns_name==root_ipns_name) for deterministic resolve_folder_key test without network; marked for #15 extension
- T-45-08 placed in crates/fuse/src/lib.rs (not apps/desktop) to keep characterization tests co-located with merge_folder_children under test
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
- [Phase 56 P02] publish_with_cas_retry uses sync Fn(u64) closure seam; folder site keeps its own CAS loop (async merge-on-conflict path cannot delegate to sync helper)
- [Phase 56 P02] D-01a: per-file/bin publish Conflict exhaustion returns Err→EIO; journal-on-exhaustion deferred (no JournalOp::FilePublish/BinPublish variant)
- [Phase 56 P02] D-11: matched_by_stable_id=false clears children_loaded and children to force fresh subtree load on display-name-only fallback match
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
- FilePointer resolution uses FileMetadata directly (no separate ResolvedFileMetadata struct)
- FilePointer resolution scoped to parent folder via get_unresolved_file_pointers_for_parent() to avoid wrong-folder-key decryption
- FilePointer async resolution: 500ms base \* 2^attempt exponential backoff (1s, 2s, 4s) with 3 retries
- Removed custom dstack-sdk.d.ts since @phala/dstack-sdk@0.5.7 ships own TypeScript types
- Defensive CVM key derivation handles both key (v0.5+) and asUint8Array (legacy) SDK return types
- TEE worker Prometheus metrics use `cipherbox_tee_*` prefix for Grafana dashboard coexistence with API metrics
- TEE worker structured JSON logger has zero external dependencies (JSON.stringify to stdout/stderr)
- [Phase 48-05] Share itemName encrypted at rest via additive nullable item_name_encrypted bytea on BOTH shares and share_invites (decision A3 includes invite flow); migration is additive-only with NO data UPDATE (server zero-knowledge cannot re-encrypt legacy plaintext); itemNameEncrypted optional hex DTO on create-share/create-invite/claim-invite; claim re-wraps ephemeral→recipient ciphertext onto the Share; web encrypt/decrypt/lazy-backfill deferred to 48-06
- [Phase 48-06] Web ECIES-wraps itemName on share/invite create (recipient pubkey for direct, ephemeral pubkey for invite) and sends ciphertext-only (itemName: '' + itemNameEncrypted) — no plaintext display name at rest for new rows; recipient decrypts itemNameEncrypted into the store's plaintext projection on received-share load so display sites are unchanged; owner sent-list uses plaintext fallback (zero-knowledge: name wrapped for recipient, owner can't decrypt — T-48-18 accept). API GAP: no update endpoint accepts itemNameEncrypted, so the legacy lazy-backfill (A2) is detect+re-wrap only; persist blocked pending a follow-up API plan (PATCH itemNameEncrypted)

### Roadmap Evolution

- Phase 19.1 inserted after Phase 19: Extract core crypto SDK as shared package (URGENT)
- Phase 19.2 inserted after Phase 19: IPFS Upload Performance Optimization (URGENT) — concurrent pins, Kubo worker tuning, pin batching to address ~95% bottleneck in upload path identified by Phase 19 baselines
- Phase 23 added: Rust SDK Extraction — extract shared cipherbox-core crate, replace duplicated logic in desktop FUSE code, enable unit testing parity with TypeScript
- Phase 27 added: Writable Shares (PoC) — extend read-only sharing to read-write using existing server-coordinated conflict resolution
- Phase 36 added: Refactor upload progress in web app, to an inline progress display and remove the popup upload progress
- Phase 37 added: Parallel batch upload pipeline — replace sequential per-file upload loop with parallel encrypt+pin and single folder metadata update
- Phase 41 added: Package and app versioning and release cycles
- Phase 42 added: API unpin integrity — ownership check, cross-user refcount, quota decrement (audit gap closure, todos 2026-06-11)
- Phase 43 added: FUSE write durability — persisted upload journal, mkdir orphan fix (audit gap closure, todos 2026-06-11)
- Phase 44 added: IPNS conflict handling — merge-on-409, file CAS (audit gap closure, todo 2026-06-11)
- Phase 45 added: Desktop FUSE write-durability cleanup — Rust hygiene refactors + test coverage for phase 43/44 journal+replay (todos #11, #12, #14, #15, #18, #19, #20); excludes data-loss bugs #7/#8/#17
- Phase 46 added 2026-06-15: Desktop FUSE data-loss bugs + replay hardening — the #7/#8/#17 bugs Phase 45 deferred, the two PR #491 replay follow-ups, and the deferred read_ops/write_ops + journal_helpers test coverage (grouped desktop todos)
- Phase 47 added 2026-06-15: SDK folder-state and publish-path consolidation — unify folderTree/Zustand ownership, one publishWithCas CAS-retry, encapsulate baseChildren bookkeeping, fix updateSharedFile prunedCids pin leak (grouped SDK todos)
- Phase 48 added 2026-06-16: SDK self-bootstrap regression fix + shared-folder/metadata consolidation — P0 fix for the PR #498 self-bootstrap clobber regressing main web-e2e (run 27587113911), then remove redundant web folder-seeding (#9, gated on the fix), route shared-folder writes through the SDK client (#8), encrypt share itemName at rest (#5 / Phase-14 M1); defers CRDT-inbox research (#2)
- Phase 49 added 2026-06-18: Shared-folder intra-share move + useFolderNavigation unwrap consolidation — recipient-side move of a file between subfolders within one share (re-encrypts FileMetadata to the dest folderKey via reencryptFileMetadataForFolderChange, mirroring owner moveItem / #507), anywhere-in-subtree destination picker (new SDK shared-subtree enumeration), plus consolidating the duplicate web useFolderNavigation ECIES unwrap onto client.ensureFolderLoaded; closes captured todos #8 + #7; builds on Phase 48 shared-folder ownership
- Milestone v1.1 REOPENED 2026-06-19 with a hardening block (Phases 50–55) absorbing tracked tech-debt/security todos from v1.1 verification and audits: 50 IPFS/IPNS data-integrity (#12 unpin-integrity, #14 unenroll-subtrees); 51 crypto-signature & secret-leak hardening (#5 IPNS sig, #15 web logger redaction/Faro); 52 desktop FUSE durability & at-rest safety (#9); 53 release & supply-chain engineering (#6 pin-actions, #13 cargo-lock, #16 release-please-pins); 54 E2E test-infra typing (#11); 55 large source-file refactor (#17). Reopened into Milestone 3 rather than opening v1.2, since Milestone 4 (v2.0) is already defined. Excludes the GSD-tooling STATE regression (#10 — upstream chore, not product code). Todos #7 (useFolderNavigation consolidation) and #8 (shared-move re-encrypt) were verified already-resolved by Phase 49 (confirmed in live code) and moved to `.planning/todos/completed/`.

- Phase 56 added 2026-06-21: FUSE & IPNS Durability Hardening (HARD-07) — per-file/bin IPNS Conflict re-resolve/retry, write-path EINVAL/EFBIG/EEXIST guards, key-wrap/decode error propagation, inode identity reset, spawn_metadata_publish zeroization; the pre-existing findings surfaced byte-identical by the PR #538 / Phase 55 refactor review (absorbs the superseded per-file-IPNS-conflict todo)
- Phase 57 added 2026-06-21: API CID/Provider Hardening & Module Dedup (HARD-08) — shared CID_REGEX+MaxLength across RegisterCidDto/UnpinDto, URL-encoded LocalProvider pin/cat URLs, leaf IpfsProviderModule, shared withCidLock/refcountAndMaybeUnpin
- Phase 58 added 2026-06-21: IPNS Signature-Verify Coverage (HARD-09) — CBOR cid/sequence binding + Rust resolve_ipns_verified chokepoint, non-CAS embedded-sequence validation, web/sdk-core resolve dedup, shared verify test vectors; the S1/S2 residue of Phase 51 / PR #529. Master IPNS-sig todo (2026-06-13) and large-file-refactor Tier-1/2 todo (2026-06-19) filed to completed/, the latter with its Tier-3 residue re-captured.
- Phase 59 added 2026-06-23: FUSE IPNS Verify/Publish Hardening & Cleanup (HARD-10) — the Phase 56/58 FUSE long-tail from the 2026-06-23 pending-todo audit: the 2 partial HARD-07 residuals (fs.rs File-branch wrap_key error propagation; inode file-side re-resolution on changed file_meta_ipns_name), VerifyError::Legacy carrying the legacy response, CAS dead journal_entry param + content_ops dead-binding cleanup, phase58 simplify follow-ups, and unifying the first-publish embedded-sequence convention (bridges to 60). Sourced from 6 captured todos.
- Phase 60 added 2026-06-23: IPNS Verification Cross-Layer Closeout — Desktop + API (HARD-11) — route remaining apps/desktop Tauri resolve_ipns sites through the verified resolver (scoped fail-closed), and recover per-op IPNS verify CPU on the API publish/resolve hot path via a safe short-circuit / short-TTL verified-record cache that still fully verifies untrusted/DHT records. Sourced from 2 captured todos: the API verify-caching todo (migrated from issue #549) and the desktop verified-resolve coverage todo.

### Open Concerns

- **main web-e2e is RED** (run 27587113911) since PR #498 merged — self-bootstrap `loadFolder` clobbers fresher folderTree state with a stale IPNS snapshot, failing `bin-restore-after-reload.spec.ts` + `full-workflow.spec.ts:6.6.2`. Blocks the staging E2E gate. Tracked as Phase 48 REQ-1 (P0).
- 6 LOW-priority tech debt items remain from M2 audit: Settings URL param parsing, OCC coverage, addManyFiles atomicity, conflict telemetry, lazy rotation, desktop E2E (see `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`)
- Recovery tool subfolder recovery limited by IPNS DHT propagation (root-level fully operational; per-file IPNS records may not be resolvable if not propagated — architectural limitation, not a bug)

### Pending Todos

21 items in `.planning/todos/pending/` — see `/gsd:check-todos` for full list. **2026-06-21:** filed resolved/superseded todos #5 (IPNS S1/S2/S3 → PR #529), #10 (refactor Tier-1/2 → PR #538), and the per-file-IPNS-conflict todo (folded into the PR #538 robustness todo) to `completed/`; re-captured the 14 Tier-3 refactor items as a new todo; grouped the FUSE/IPNS, API-CID, and IPNS-verify deferred-findings todos into new Phases 56–58. **2026-06-19:** todos #7 (useFolderNavigation consolidation) and #8 (shared-move re-encrypt) were verified already-resolved by Phase 49 (confirmed in live code) and moved to `completed/`; ten remaining tech-debt/security todos were grouped into the reopened v1.1 hardening block (Phases 50–55, see Roadmap Evolution). The four older feature todos (ERC-1271 wallet auth, CRDT IPNS inbox research, async search index, alternative MFA factors) and the GSD-tooling STATE regression (#10) remain unscheduled. _Historical:_ the desktop (6) and SDK (4) groups addressed by Phase 46 (merged) and Phase 47 (PR #494) were moved to `.planning/todos/completed/` on 2026-06-15 and their ROADMAP scope boxes checked. The architecture todo to give the SDK client the root IPNS key so it self-bootstraps/lazy-loads `folderTree` (root cause of the "Folder not loaded" class; bin-restore gap surfaced while combing the #494 fix) was completed 2026-06-16 in PR #498 (branch `feat/sdk-client-self-bootstrap-folder-tree`) and moved to `.planning/todos/completed/`; its follow-ups (delete the now-redundant web `ensureFolderRegistered`/`useFolderNavigation` unwrap paths once self-heal proves out; optional negative-cache) were captured as a new pending todo. Remaining pending still includes the route-shared-folder-writes follow-up — the lone folder-state mutation not consolidated by Phase 47. The v1.1 verification-ledger todo (phases 18/31/32 missing VERIFICATION.md) was completed 2026-06-19 — all three reports authored (goal-backward, adversarially spot-checked), PERF-01..04 closed (PERF-03 via accepted override), and the milestone audit verdict flipped to `passed` (66/66, 20/20); moved to `.planning/todos/completed/`.

### Resolved

All M2 blockers resolved. See `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`.

### Quick Tasks Completed

| #          | Description                                                   | Date       | Commit     | Directory                                                                                                           |
| ---------- | ------------------------------------------------------------- | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------- |
| 260327-2ab | Extract shared-write operations from web UI into SDK packages | 2026-03-27 | see branch | [260327-2ab-extract-shared-write-operations-from-web](./quick/260327-2ab-extract-shared-write-operations-from-web/) |
| 260401-5ft | Expose the API version on the /health endpoint                | 2026-04-01 | ba5e9de    | [260401-5ft-expose-the-api-version-on-the-api-health](./quick/260401-5ft-expose-the-api-version-on-the-api-health/) |
| 260401-kyv | Fix sidebar icons to be consistent                            | 2026-04-01 | 749065d    | [260401-kyv-fix-sidebar-icons-to-be-consistent](./quick/260401-kyv-fix-sidebar-icons-to-be-consistent/)             |

---

Last activity: 2026-06-23

Last session: 2026-06-23T19:48:00Z

## Decisions

- [Phase 59-02]: VerifyError::Legacy carries { cid: String, sequence_number: String } from bind_verified — no second resolve_ipns in any Legacy arm (T-59-04 TOCTOU eliminated)
- [Phase 59-02]: Display for VerifyError::Legacy includes cid and seq: 'legacy record: all signature fields absent (cid={cid}, seq={sequence_number})'
- [Phase 59-02]: events.rs synthetic VerifiedResolve keeps signature_verified: false until Finding E.1 (plan 03) removes the field
- [Phase ?]: deser_opt_string maps legacy empty-string file_meta_ipns_name to None; serde compat shim mandatory for pre-Phase-45 journal replay
- [Phase 45-04]: IpnsResolveOutcome lives in error.rs with #[derive(Debug)] only — not thiserror, it is an outcome not an error
- [Phase 45-04]: resolve_ipns_for_replay preserves both contains(not found) and contains(404) predicates to avoid classification regression
- [Phase ?]: Conditional use imports route replay to fuse->operations::implementation and winfsp->platform::windows::operations::implementation for publish_file_metadata
- [Phase ?]: folder_key_cache seeded with root key in replay_for_vault; resolve_folder_key_cached wrapper memoizes per replay call, never persisted or shared
- [Phase ?]: journal_helpers: helper takes &OpenFileHandle directly (open_files entry removed before call)
- [Phase ?]: journal_helpers: WinFsp write_gen read after write_generation bump; fuser uses result field captured before mutation
- [Phase ?]: journal_helpers: build_mkdir_journal_entry called after child inode inserted so build_folder_metadata sees new child
- [Phase ?]: Keep @internal on ensureFolderLoaded; call directly from web hook
- [Phase 49-03]: onMove wired for files only in folder-view ContextMenu; list-view synthetic items stay readOnly (T-49-09)
- [Phase 49-03]: currentFolderId for SharedMoveDialog derived from breadcrumbs last entry (not separate state)
- [Phase 49-03]: SharedMoveDialog lazy-loads subtree via enumerateSharedSubtree in useEffect gated on open && shareId
- [Phase 49-04]: batchMoveItemsHandler clearSelection called after runWrite completes (full success only)
- [Phase 49-04]: SharedFolderRow drop uses row's id/ipnsName as authoritative dest (ignores payload parentId per T-49-12)
- [Phase 49-04]: SelectionActionBar onDelete/onDownload are no-op stubs (REQ-6 scopes to move parity only)
- [Phase 49-05]: SharedMoveDialogPage.dialog() scoped via .move-dialog-folder-list filter (avoids collision with private MoveDialog)
- [Phase 49-05]: readContentViaEditor dispatches rightClickFolderItem vs rightClickItem based on instanceof check (shared vs private browser page)
- [Phase 49-05]: Alice decrypt assertion uses FileListPage (private vault view), not SharedFileBrowserPage — owner reads own files via vault browser
- [Phase 51-01]: CAS ConflictException (409) check placed before S1 BadRequestException (400) sequence check so concurrent-modification signals remain authoritative; S1 reuses anti-rollback incomingParsed to avoid double parse
- [Phase 51-03]: resolve_folder_key_cached cache left as HashMap<String, Vec<u8>> (not Zeroizing); cache is short-lived, cleared on replay_for_vault drop — only BFS queue and get_folder_key return changed
- [Phase 51-03]: verify_ipns_resolve_signature absent-fields path returns Ok(None) + warn (D-03), not error; verify gate in resolve_folder_key BFS only (not fetch_merge_publish_parent replay path)
- [Phase 51-04]: updateFolderMetadataAndPublish SKIP zeroing — all client.ts call sites pass live session keys from folderTree state reused across session lifetime; caller retains ownership (T-47-01 documented skip with guard test)
- [Phase ?]: CBOR import: cborg decode used in sdk-core; parseCborData from ipns unavailable
