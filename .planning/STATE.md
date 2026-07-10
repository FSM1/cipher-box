---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Metadata and Sharing Refactor
current_phase: 73
status: executing
stopped_at: Completed 72-10-PLAN.md
last_updated: "2026-07-10T23:36:09.597Z"
last_activity: 2026-07-10
last_activity_desc: Phase 73 complete
progress:
  total_phases: 22
  completed_phases: 15
  total_plans: 189
  completed_plans: 188
  percent: 68
current_phase_name: shared-write-navigation-correctness-web
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-06-27)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 73 — shared-write-navigation-correctness-web

## Current Position

Phase: 73
Plan: Not started
Status: Executing Phase 73
Last activity: 2026-07-10 — Phase 73 complete

Progress: `██████████` 79 / 79 plans (100%)

## Deferred Items

Items acknowledged and deferred at v1.1 milestone close on 2026-06-27. None are unsatisfied requirements (the close-out audit confirmed 77/77 requirements code-satisfied, integration 12/12, flows 4/4). Full enumeration via `node .claude/gsd-core/bin/gsd-tools.cjs query audit-open`.

| Category | Item | Status | Disposition |
| --- | --- | --- | --- |
| Verification | Phase 39 — 39-VERIFICATION.md | gaps_found | D-02 (no permanent-delete confirmation) captured as todo `2026-06-27-add-permanent-delete-confirmation-dialog-in-web-app.md`; D-06 (residual server `RECYCLE_BIN_RETENTION_DAYS` surface) + D-04 (cosmetic) documented in v1.1-MILESTONE-AUDIT.md |
| Verification | Phase 59 — 59-VERIFICATION.md | human_needed | HARD-10/11 staging operational smoke-test (D-12 lockstep) — operational gate, code complete |
| UAT | Phase 21 — 21-UAT.md | diagnosed | BYO-IPFS UI browser-verification items; all BYO requirements code-satisfied |
| UAT | Phase 59 — 59-UAT.md | testing | 3 pending scenarios tied to the staging smoke-test above |
| Context | Phase 49 — 49-CONTEXT.md | open questions (3) | Shared-folder move design Qs answered in implementation; left as historical record |
| Quick tasks | 26 legacy quick-tasks (`001-*`..`023-*`, `260327-2ab`, `260401-5ft`, `260401-kyv`) | unknown | Mostly old UI/staging tasks of indeterminate status; not v1.1-blocking — triage in next milestone |
| Todos | 17 pending todos (ERC-1271 wallet auth, CRDT IPNS inbox research, async search index, alt MFA factors, web logger redaction/Faro, route-shared-folder-writes, etc.) | pending | Forward-looking/research + tech-debt; carry to v1.2 / Milestone 4 backlog |
| Seeds | SEED-001 (Phala TEE on-demand cost reduction) | dormant | Will auto-surface on next `/gsd-new-milestone` |

## Performance Metrics

**Velocity (v1.1):**

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
| Phase 26 P01    | 5min     | 3 tasks | 6 files   |
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
| Phase 45 P03    | 7min     | 2 tasks | 4 files   |
| Phase 45 P04    | 8min     | 1 tasks | 2 files   |
| Phase 45 P05    | 12min    | 2 tasks | 1 files   |
| Phase 45 P06    | 90min    | - tasks | - files   |
| Phase 48 P01    | 15min    | 3 tasks | 4 files   |
| Phase 48 P02    | 2min     | 2 tasks | 5 files   |
| Phase 48 P03    | 6min     | 3 tasks | 7 files   |
| Phase 48 P05    | 8min     | 3 tasks | 145 files |
| Phase 48 P06    | 18min    | 3 tasks | 5 files   |
| Phase 49 P01    | 13min    | 2 tasks | 5 files   |
| Phase 49 P02    | 15min    | 1 tasks | 1 files   |
| Phase 49 P03    | 11min    | 4 tasks | 7 files   |
| Phase 49 P04    | 26min    | 3 tasks | 5 files   |
| Phase 49 P05    | 12min    | 2 tasks | 2 files   |
| Phase 51 P01    | 9min     | 3 tasks | 2 files   |
| Phase 51 P03    | 45min    | 4 tasks | 12 files  |
| Phase 51 P04    | 12min    | 3 tasks | 6 files   |
| Phase 56 P01    | 45min    | 3 tasks | 5 files   |
| Phase 56 P02    | 90min    | 3 tasks | 8 files   |
| Phase 58 P01    | 45min    | 5 tasks | 10 files  |
| Phase 58 P02    | 30min    | 3 tasks | 2 files   |
| Phase 58 P04    | 25min    | 3 tasks | 4 files   |
| Phase 59 P01    | 35min    | 2 tasks | 2 files   |
| Phase 59 P02    | 4min     | 2 tasks | 6 files   |
| Phase 59 P03    | 12min    | 2 tasks | 6 files   |
| Phase 59 P04    | 15min    | 2 tasks | 7 files   |
| Phase 60 P01    | 35min    | 2 tasks | 9 files   |
| Phase 60 P02    | 4min     | 2 tasks | 7 files   |
| Phase 60 P03    | 9min     | 2 tasks | 3 files   |
| Phase 60 P04    | 15min    | 2 tasks | 11 files  |
| Phase 60 P05    | 16min    | - tasks | - files   |
| Phase 60 P06    | 14min    | 2 tasks | 7 files   |
| Phase 61 P01 | 18m | 2 tasks | 9 files |
| Phase 61 P61-02 | 12 | 2 tasks | 6 files |
| Phase 61-aad-bound-seal-primitive-and-cross-language-kat P03 | 11 | 2 tasks | 7 files |
| Phase 61 P04 | 8 | 2 tasks | 2 files |
| Phase 61 P05 | 10 | 2 tasks | 4 files |
| Phase 62 P01 | 10m | 3 tasks | 4 files |
| Phase 62 P02 | 75 | 2 tasks | 4 files |
| Phase 62 P04 | 14 minutes | 2 tasks | 3 files |
| Phase 62 P05 | 10m | 3 tasks | 9 files |
| Phase 62-unified-node-codec-core-keystone P06 | 2700 | 2 tasks | 11 files |
| Phase 62 P07 | 90m | 2 tasks | 18 files |
| Phase 62-unified-node-codec-core-keystone P08a | 180 | 1 tasks | 26 files |
| Phase 62-unified-node-codec-core-keystone P08b | 240 | 1 tasks | 22 files |
| Phase 63 P01 | 17 | 2 tasks | 4 files |
| Phase 63 P02 | 13 | 2 tasks | 2 files |
| Phase 63-read-chain-navigation-and-rotation-core P05 | 12m | 2 tasks | 5 files |
| Phase 63 P06 | 45 | 2 tasks | 9 files |
| Phase 63 P07 | 25 | 1 tasks | 4 files |
| Phase 64-rotation-soundness-revocation-guarantees P01 | 90 | 3 tasks | 13 files |
| Phase 64 P02 | 3min | 2 tasks | 2 files |
| Phase 64 P03 | 2min | 2 tasks | 2 files |
| Phase 64 P04 | 60 | 4 tasks | 2 files |
| Phase 64 P06 | 13 | 2 tasks | 3 files |
| Phase 64 P07 | 40m | 4 tasks | 2 files |
| Phase 64 P08 | 45 | 3 tasks | 1 files |
| Phase 67 P01 | 5m | 2 tasks | 2 files |
| Phase 67 P02 | 8 | 2 tasks | 4 files |
| Phase 67 P03 | 102 | 1 tasks | 2 files |
| Phase 67-tee-lease-renewer-contract-rewrite P04 | 140 | 1 tasks | 2 files |
| Phase 67 P05 | 171 | 2 tasks | 4 files |
| Phase 67 P06 | 20m | 1 tasks | 2 files |
| Phase 68 P11 | 25min | 3 tasks | 6 files |
| Phase 68 P12 | 4min | 2 tasks | 6 files |
| Phase 68.1 P01 | 28min | 3 tasks | 10 files |
| Phase 68.1 P02 | 35min | 3 tasks | 2 files |
| Phase 68.1 P03 | 10min | 1 tasks | 1 files |
| Phase 68.1 P05 | 40min | 2 tasks | 1 files |
| Phase 68.1 P07 | 16min | 3 tasks | 6 files |
| Phase 68.1 P08 | 25min | 2 tasks | 2 files |
| Phase 68.1 P13 | 240min | 2 tasks | 8 files |
| Phase 68.1 P17 | 45min | 2 tasks | 1 files |
| Phase 68.1 P18 | 12min | 2 tasks | 4 files |
| Phase 68.1 P19 | 11min | 2 tasks | 7 files |
| Phase 68.2 P01 | 25min | 2 tasks | 2 files |
| Phase 68.2 P02 | 25min | 3 tasks | 5 files |
| Phase 68.2 P03 | 20min | 2 tasks | 5 files |
| Phase 68.2 P05 | 15min | 1 tasks | 1 files |
| Phase 68.2 P04 | 20min | 2 tasks | 4 files |
| Phase 68.2 P06 | 65min | 3 tasks | 12 files |
| Phase 68.2 P07 | 35min | 2 tasks | 11 files |
| Phase 68.2 P08 | 90min | 2 tasks | 10 files |
| Phase 68.2 P09 | 40min | 2 tasks | 13 files |
| Phase 68.2 P10 | 45min | 2 tasks | 12 files |
| Phase 68.2 P11 | 45min | 3 tasks | 16 files |
| Phase 68.2 P12 | 130 | - tasks | - files |
| Phase 68.2 P13 | 8min | 2 tasks | 2 files |
| Phase 68.2 P14 | 50min | 2 tasks | 3 files |
| Phase 70 P01 | 12min | 2 tasks | 3 files |
| Phase 70 P02 | 45min | 3 tasks | 3 files |
| Phase 70 P03 | 20min | 2 tasks | 2 files |
| Phase 70 P04 | 10min | 3 tasks | 3 files |
| Phase 70 P05 | 20min | 2 tasks | 2 files |
| Phase 70 P06 | 55min | 3 tasks | 4 files |
| Phase 70 P07 | 13min | 3 tasks | 2 files |
| Phase 70 P08 | 55min | 2 tasks | 1 files |
| Phase 72 P01 | 20min | 1 tasks | 1 files |
| Phase 72 P02 | 25min | 2 tasks | 2 files |
| Phase 72 P03 | 25min | 2 tasks | 3 files |
| Phase 72 P04 | 15min | 2 tasks | 3 files |
| Phase 72 P05 | 25min | 3 tasks | 5 files |
| Phase 72 P06 | 20min | 2 tasks | 3 files |
| Phase 72 P07 | 8min | 2 tasks | 3 files |
| Phase 72 P08 | 15min | 2 tasks | 1 files |
| Phase 72 P09 | 8min | 1 tasks | 5 files |
| Phase 72 P10 | 10min | 2 tasks | 3 files |

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
- DB crypto columns (encrypted_root_folder_key, encrypted_root_ipns_private_key, migrated_at) fully dropped -- no fallback paths
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
- BYO config stored as encrypted IPNS entry using rootFolderKey -- no server-side credential storage (zero-knowledge preserved)
- Dedicated IPNS key derived via HKDF with context string byo-ipfs-config from vault keypair
- BYO benchmark execution (21-07 Task 4) deferred -- requires external IPFS provider infrastructure; test scenarios ready to run when provider available
- BYO config loaded at login via IPNS resolve with graceful fallback to cipherbox-only mode
- Source unpin is best-effort and non-fatal after verified CID transfer to destination
- Cargo workspace with centralized deps at repo root; cipherbox-crypto crate as foundation for all Rust SDK extraction
- Module re-export pattern in desktop crypto/mod.rs preserves all existing crate::crypto::* paths without touching call sites
- cipherbox-core crate layered on cipherbox-crypto: folder, file, bin, vault_blob, ipns, registry, decrypt, error modules
- File module re-exports FileMetadata types from folder.rs (shared AES encryption context with parent folder key)
- decrypt module moved from fuse to crypto re-export (domain logic, not FUSE-specific)
- Hand-structured API client crate rather than openapi-generator (modest API surface, proven code, no Java/Docker CI dependency)
- critical-section std feature required for standalone ecies linking (Tauri provides it in desktop builds)
- Shared test vectors in tests/vectors/ JSON files loadable by both Rust and TypeScript for CI parity gates
- SyncDaemon uses Arc<dyn Fn(SyncStatus)> generic callback instead of Tauri AppHandle for testability
- Desktop api/client.rs re-exports cipherbox_api_client::ApiClient as type alias to unify types across modules
- Desktop AppState wraps Arc<KeyState> from SDK; all key material accessed via state.sdk.*
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
- FilePointer async resolution: 500ms base * 2^attempt exponential backoff (1s, 2s, 4s) with 3 retries
- Removed custom dstack-sdk.d.ts since @phala/dstack-sdk@0.5.7 ships own TypeScript types
- Defensive CVM key derivation handles both key (v0.5+) and asUint8Array (legacy) SDK return types
- TEE worker Prometheus metrics use `cipherbox_tee_*` prefix for Grafana dashboard coexistence with API metrics
- TEE worker structured JSON logger has zero external dependencies (JSON.stringify to stdout/stderr)
- [Phase 48-05] Share itemName encrypted at rest via additive nullable item_name_encrypted bytea on BOTH shares and share_invites (decision A3 includes invite flow); migration is additive-only with NO data UPDATE (server zero-knowledge cannot re-encrypt legacy plaintext); itemNameEncrypted optional hex DTO on create-share/create-invite/claim-invite; claim re-wraps ephemeral→recipient ciphertext onto the Share; web encrypt/decrypt/lazy-backfill deferred to 48-06
- [Phase 48-06] Web ECIES-wraps itemName on share/invite create (recipient pubkey for direct, ephemeral pubkey for invite) and sends ciphertext-only (itemName: '' + itemNameEncrypted) -- no plaintext display name at rest for new rows; recipient decrypts itemNameEncrypted into the store's plaintext projection on received-share load so display sites are unchanged; owner sent-list uses plaintext fallback (zero-knowledge: name wrapped for recipient, owner can't decrypt -- T-48-18 accept). API GAP: no update endpoint accepts itemNameEncrypted, so the legacy lazy-backfill (A2) is detect+re-wrap only; persist blocked pending a follow-up API plan (PATCH itemNameEncrypted)

### Roadmap Evolution

- Phase 19.1 inserted after Phase 19: Extract core crypto SDK as shared package (URGENT)
- Phase 19.2 inserted after Phase 19: IPFS Upload Performance Optimization (URGENT)
- Phase 23 added: Rust SDK Extraction
- Phase 27 added: Writable Shares (PoC)
- Phase 36 added: Inline upload progress
- Phase 37 added: Parallel batch upload pipeline
- Phase 41 added: Package and app versioning and release cycles
- Phase 42 added: API unpin integrity
- Phase 43 added: FUSE write durability
- Phase 44 added: IPNS conflict handling
- Phase 45 added: Desktop FUSE write-durability cleanup
- Phase 46 added 2026-06-15: Desktop FUSE data-loss bugs + replay hardening
- Phase 47 added 2026-06-15: SDK folder-state and publish-path consolidation
- Phase 48 added 2026-06-16: SDK self-bootstrap regression fix + shared-folder/metadata consolidation
- Phase 49 added 2026-06-18: Shared-folder intra-share move + useFolderNavigation unwrap consolidation
- Milestone v1.1 REOPENED 2026-06-19 with hardening block (Phases 50–55)
- Phase 56 added 2026-06-21: FUSE & IPNS Durability Hardening
- Phase 57 added 2026-06-21: API CID/Provider Hardening & Module Dedup
- Phase 58 added 2026-06-21: IPNS Signature-Verify Coverage
- Phase 59 added 2026-06-23: FUSE IPNS Verify/Publish Hardening & Cleanup
- Phase 60 added 2026-06-23: IPNS Verification Cross-Layer Closeout -- Desktop + API
- **v2.0 Phases 61–69 added 2026-06-27**: Metadata and Sharing Refactor — read key-chaining + rotation soundness + write-revocation + TEE contract rewrite + schema cutover + web/FUSE integration
- Phase 68.2 inserted after Phase 68: SDK-Owned Read Chain and Resolved Folder Listings (URGENT)
- Phase 69 edited: added Rust SDK-owned read chain scope (Phase 68.2 parity)
- Phase 74 added: M4 v2.0 closeout phase (from pending-todo triage)
- Phase 75 added: M4 v2.0 closeout phase (from pending-todo triage)
- Phase 76 added: M4 v2.0 closeout phase (from pending-todo triage)
- Phase 77 added: M4 v2.0 closeout phase (from pending-todo triage)
- Phase 78 added: M4 v2.0 closeout phase (from pending-todo triage)
- Phase 79 added: Web kind-discrimination completion + deferred test revival (from TODO(phase 63/65) marker triage)

### Open Concerns

- 6 LOW-priority tech debt items remain from M2 audit: Settings URL param parsing, OCC coverage, addManyFiles atomicity, conflict telemetry, lazy rotation, desktop E2E (see `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`)
- Recovery tool subfolder recovery limited by IPNS DHT propagation (root-level fully operational; per-file IPNS records may not be resolvable if not propagated -- architectural limitation, not a bug)
- **v2.0 open questions** (to resolve during respective phases):
  - Q1 (Phase 68): Co-writer offline during write-key rotation -- accept explicit re-fetch requirement or add grace/notification?
  - Q2 (Phase 63): Rotation host for pure-web users -- is a long chunked multi-session web rotation acceptable for large revokes, or is desktop the only host?
  - Q3 (Phases 65, 68, 69): Write-recipient-vs-owner sub-share authority -- when C (write recipient) deletes a node the owner independently sub-shared to D, who controls revocation of D?

### Pending Todos

**2026-06-27:** Captured Phase 39 D-02 data-safety gap: web app performs permanent/hard delete with no confirmation dialog. See `2026-06-27-add-permanent-delete-confirmation-dialog-in-web-app.md`.

**2026-06-23:** Captured high-severity storage/quota bug -- bin delete + empty-bin never unpin content/version CIDs. See `2026-06-23-bin-delete-and-empty-bin-leak-content-and-version-cid-pins.md`.

See `/gsd:check-todos` for the full pending list.

### Resolved

All M2 blockers resolved. See `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`.

All v1.1 requirements code-satisfied (77/77). See `.planning/milestones/v1.1-MILESTONE-AUDIT.md`.

### Quick Tasks Completed

| #          | Description                                                   | Date       | Commit     | Directory                                                                                                           |
| ---------- | ------------------------------------------------------------- | ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------- |
| 260327-2ab | Extract shared-write operations from web UI into SDK packages | 2026-03-27 | see branch | [260327-2ab-extract-shared-write-operations-from-web](./quick/260327-2ab-extract-shared-write-operations-from-web/) |
| 260401-5ft | Expose the API version on the /health endpoint                | 2026-04-01 | ba5e9de    | [260401-5ft-expose-the-api-version-on-the-api-health](./quick/260401-5ft-expose-the-api-version-on-the-api-health/) |
| 260401-kyv | Fix sidebar icons to be consistent                            | 2026-04-01 | 749065d    | [260401-kyv-fix-sidebar-icons-to-be-consistent](./quick/260401-kyv-fix-sidebar-icons-to-be-consistent/)             |

---

Last activity: 2026-06-27

Last session: 2026-06-28T18:09:45.156Z

## Decisions

- [Phase 59-04]: F.1 next_file_publish_sequence(is_first_publish=true) returns 1; unified with TS SDK first-publish convention
- [Phase 59-04]: F.2 replay.rs child-folder first-publish embeds seq=1; record_publish seeds at 1 for coordinator consistency
- [Phase 59-04]: F.3 verify.rs skew allowance (resp_seq==1 && embedded_seq==0) removed; strict embedded_seq == resp_seq (T-59-10)
- [Phase 59-04]: F.4 ipns_verify_vectors case-8 expected_result changed valid->invalid; classify_vector uses strict equality
- [Phase 59-04]: TEE re-sign path confirmed NOT hitting upsertFolderIpns embedded-seq gate (T-59-11 accepted); no API/TS change needed
- [Phase 59-03]: D.1 journal_entry if/else body collapsed to single Err; param kept with D-01a TODO
- [Phase 59-03]: D.3 current_seq_for_cas replaced by direct if current_seq.is_none() guard (same error text)
- [Phase 59-03]: E.1 VerifiedResolve::signature_verified field removed; was never read, only written
- [Phase 59-03]: E.4 bytesToHex helper removed alongside the unused public_key/private_key vector fields
- [Phase 59-02]: VerifyError::Legacy carries { cid: String, sequence_number: String } from bind_verified -- no second resolve_ipns in any Legacy arm (T-59-04 TOCTOU eliminated)
- [Phase 59-02]: Display for VerifyError::Legacy includes cid and seq: 'legacy record: all signature fields absent (cid={cid}, seq={sequence_number})'
- [Phase 59-02]: events.rs synthetic VerifiedResolve keeps signature_verified: false until Finding E.1 (plan 03) removes the field
- [Phase 45-04]: IpnsResolveOutcome lives in error.rs with #[derive(Debug)] only -- not thiserror, it is an outcome not an error
- [Phase 45-04]: resolve_ipns_for_replay preserves both contains(not found) and contains(404) predicates to avoid classification regression
- [Phase 51-01]: CAS ConflictException (409) check placed before S1 BadRequestException (400) sequence check so concurrent-modification signals remain authoritative; S1 reuses anti-rollback incomingParsed to avoid double parse
- [Phase 51-03]: resolve_folder_key_cached cache left as HashMap<String, Vec<u8>> (not Zeroizing); cache is short-lived, cleared on replay_for_vault drop -- only BFS queue and get_folder_key return changed
- [Phase 51-03]: verify_ipns_resolve_signature absent-fields path returns Ok(None) + warn (D-03), not error; verify gate in resolve_folder_key BFS only (not fetch_merge_publish_parent replay path)
- [Phase 51-04]: updateFolderMetadataAndPublish SKIP zeroing -- all client.ts call sites pass live session keys from folderTree state reused across session lifetime; caller retains ownership (T-47-01 documented skip with guard test)
- [Phase 60-01]: decode_ipns_cbor_validity companion fn chosen over 3-tuple return; all 9 FUSE Legacy arms folded to Invalid; manual RFC3339 parse with 5-min skew buffer (D-04/D-07)
- [Phase 60-02]: D-02 all 9 first-publish producers unified to embed sequence 1; coordinator.record_publish updated to match; vault-settings.service.ts forward-publish increment path unchanged
- [Phase 60-04]: All 9 FUSE Legacy arms were pre-folded by 60-01 (compiler-forced); Task 1 re-pointed imports and deleted verify.rs only
- [Phase 60-04]: sync.rs poll(): Invalid verify returns Err to skip poll cycle (not warn-and-proceed)
- [Phase 60-04]: registry.rs VerifyError::Invalid maps to SdkError::RegistryError (fail-closed)
- [Phase 60-04]: prepopulate.rs and vault.rs: scoped per-operation fail-closed (D-09)
- [Phase 60-06]: D-11 go decision: per-op verify cost (mean 0.105 ms) justifies a short-TTL cache; cache key = ipnsName + base64(recordBytes); TEE republish and resolve paths never populate cache
- [Phase 60-05]: D-03 first-publish gate changed from {0n,1n} to strict {1n} only; embedded-0 now returns 400
- [Phase 60-05]: D-06 parseCachedRecord null-signedRecord path returns null; CID mismatch discards cached result
- [Phase 60-05]: D-06 withCachedPublicKey enrich and equal-seq signatureV2 enrich removed from resolveRecord
- [Phase 60-05]: api:generate NOT required; changes are internal service/codec logic with no OpenAPI surface change
- [Phase ?]: seal_vectors KAT asserts exact ciphertext byte-for-byte via serde_json::Value pull + NodeSealVector; !seal_vectors.is_empty() guard prevents vacuous pass
- [Phase ?]: ADR 0003 freezes the 45-byte AAD encoding; doc links replace inline restatement
- [Phase ?]: [Phase 62-01]
- [Phase ?]: [Phase 62-01]
- [Phase ?]: Role 0x01 used for both readSealed and writeSealed bodies (ADR 0003 §2.5)
- [Phase ?]: D-09: never zero caller-supplied key buffers in seal.ts — caller is terminal owner
- [Phase ?]: [62-05] nodeRef replaces filePointer/folderEntry/originalFolderKeyEncrypted in BinEntry; Phase 65 owns bin re-link behavior
- [Phase ?]: [62-05] No describe.skip needed in bin.test.ts - all remaining tests are pure ECIES round-trip or schema validation
- [Phase ?]: vault adapted to v3 two-key format; sdk-core compile gate passes with zero retired-type references
- [Phase ?]: vault.store: rootFolderKey split to rootReadKey+rootWriteKey for v3 vault
- [Phase ?]: useAuth.ts vault load: unwrapKey x2 + deriveVaultIpnsKeypair (IPNS keypair derived, not in v3 blob)
- [Phase ?]: Phase-63 kind-discrimination stubs: isFolder=true, fileCount=0 across file-browser until Node.kind available
- [Phase ?]: ShareDialog.handleShare + handleUpgrade fully stubbed with throw phase-65; legacy FolderEntry key-wrapping path removed
- [Phase ?]: Transport-decoupled insertShareFn callback (D-05): grant issuance unit-tested against mocked API; real shares persistence deferred to Phase 66
- [Phase ?]: reWrapKey used for claimInviteReadKey to delegate intermediate zeroization (T-63-05)
- [Phase ?]: hasCoveringGrant pure predicate (D-08): both relay set and localGrantRecord cross-checked; injectable deps.rotate for SC#4 zero-rotation invariant
- [Phase ?]: BFS in rotateReadFromNode must derive child readKeys via unsealChildReadKey with parent OLD readKey before enqueuing
- [Phase ?]: Bypass Phase-65 createFileMetadata by manually building file node: sealNode+addToIpfs+createAndPublishIpnsRecord in sdk-e2e
- [Phase ?]: mergeChildren union semantics: local first, remote overwrites (ROT-05 concurrent-add)
- [Phase ?]: D-02 re-seal out-of-band in BFS caller
- [Phase ?]: ParentTrackingState Map keyed by IPNS name for D-09 batched parent republish
- [Phase ?]: cas.ts merge callback accepts sync|Promise union — backward-compat
- [Phase ?]: Crash at call 4
- [Phase ?]: Resume job seeded with crash-time completedNodeIds (not empty set) — empty set causes double-bump on the committed root node
- [Phase ?]: 67-02
- [Phase ?]: renewIpnsRecord sources value and sequence exclusively from parseIpnsRecord — structurally prevents CID repoint and sequence increment (TEE-01/TEE-02)
- [Phase ?]: ECIES-wrap done in createSubfolder itself, matching vault-settings.service.ts pattern
- [Phase ?]: tee-worker build context is repo root not apps/tee-worker dir
- [Phase ?]: TEE_WORKER_URL=http://localhost:3002 active not commented in .env.example
- [Phase ?]: TEE route is verify-in-enclave lease renewer: parse→verify→decrypt→bind→re-sign same CID+seq→zero (D-01/TEE-01/TEE-02/TEE-06)
- [Phase 68-11]: reconcileFolderSequence sources enforceResolved's generation param from the in-memory folderTree nodeGeneration (never the resolved envelope's own generation)
- [Phase 68-11]: handleSync's ResolveRotationContext.generation hardcoded to 0 (useFolderStore carries no root generation field), matching the SDK client's own default
- [Phase 68-11]: rotation-durability.spec.ts SC#4 proof now drives two real UI renames (seed+bump, then a rejected rename after stale-bytes replay) instead of direct module invocation; RenameDialog does not close on a failed mutation so the spec drives the form fields directly for the rejection step
- [Phase 68-12]: rotateReadFromNode returns are keyed off rootResult.skipped (checked once at the end), not job-record status; both clean-resume and dirty-resume paths correctly return undefined since neither mints a fresh root key
- [Phase 68-12]: performScopeExitRotation zeroes the OLD folderTree folderKey only AFTER the Map.set() swap and only post-flight (rotateReadFromNode has already returned) -- never zeroes rotationResult.readKey or the caller-supplied rootReadKey mid-flight
- [Phase ?]: [Phase 68.1-01]: CipherBoxClientConfig.rootWriteKey optional — self-bootstrap requires rootIpnsKeypair AND rootWriteKey; host wiring lands 68.1-03
- [Phase ?]: [Phase 68.1-01]: legacy zero-fallback writeKey publishes WITHOUT a write-body (never seal under zero key — T-68.1-01-03 structural mitigation)
- [Phase ?]: [Phase 68.1-01]: deleteToBin/restoreFromBin write-body threading lives in bin/index.ts where the actual updateFolderMetadataAndPublish calls are
- [Phase 68.1-02]: createFolder throws when the parent has no real writeKey — fail-closed instead of sealing WriteChildRef under a zero key
- [Phase 68.1-02]: collectRemovedItemIpnsNames gained a required parentReadKey parameter to unseal the removed item's readKeySealed (deleteItem passes folder.folderKey)
- [Phase ?]: [Phase 68.1-03]: publishEmptyRootNode derives+returns rootIpnsName internally -- useAuth consumes the returned name instead of a separate deriveIpnsName call
- [Phase ?]: [Phase 68.1-03]: new-user publishEmptyRootNode call omits teeKeys (undefined) -- brand-new users have no TEE enrollment state yet
- [Phase 68.1-05]: navigateReadChain cannot render an intermediate folder (forces kind:'file' leaf) -- folder nav uses a parallel low-level web-layer walk reusing the same sdk-core/core primitives
- [Phase 68.1-05]: ReceivedShare.readDescriptorRef is hex on the API DTO wire; navigateReadChain expects base64 -- downloadSharedFile bridges hex-decoded bytes to base64 before calling it
- [Phase 68.1-05]: single-file shares (root Node kind:'file') switch currentView to 'file', activating SharedFileBrowser's pre-existing synthetic-ref download effect for the first time
- [Phase ?]: [Phase 68.1-07]: createFileMetadata builds but does not publish the file's first IPNS record (caller batch-publishes via batchPublishIpnsRecords) -- matches the pre-existing UploadResult.ipnsRecord contract already wired in client.ts
- [Phase ?]: [Phase 68.1-07]: updateFileMetadata is a single-shot direct republish (no CAS retry/merge) -- mirrors shared-write.ts updateSharedFile, not the legacy quarantined CAS+merge flow
- [Phase ?]: [Phase 68.1-07]: replaceFileInFolder is a thin registration.ts delegate to file/index.ts updateFileMetadata, kept for API symmetry with addFileToFolder/addFilesToFolder
- [Phase ?]: [Phase 68.1-08]: getFileIpnsKeyFn is a fallback ONLY for fileIpnsPrivateKey in updateSharedFile — fileWriteKey always comes from the write-chain walk, fails closed if no WriteChildRef exists
- [Phase ?]: [Phase 68.1-08]: moveInSharedFolder resolves destFolderKey/destIpnsPrivateKey from share_keys (folder + folder-ipns entries), passing the folder-ipns-wrapped value as SharedWriteContext.writeKey — fails closed via AEAD auth error if incompatible with the destination's actual write-body seal; 68.1-13 web-e2e is the empirical confirmation point
- [Phase 68.1-13]: createFolder wrapped in runWithFailureUx (was the only folder mutation missing retry-on-ReconcileStaleError)
- [Phase 68.1-13]: useFolderMutations.handleCreate keys new FolderNode by ipnsName not write-body UUID -- fixes folder-store id desync that silently dropped folder:updated events on nested-folder-creation
- [Phase 68.1-13]: FileListItem.isFolder and ContextMenu.isFile now read fileTypes.ts isFileRef(item) kind cache -- both were hardcoded phase-63 stubs
- [Phase 68.1-17]: GAP-1 root cause was a seal-side fileKey/fileReadKey field-confusion bug in uploadFiles, not an AAD/generation divergence -- fixed at the seal site only, read side untouched
- [Phase ?]: [Phase 68.1-18]: resolveShareWriteDescriptor mirrors resolveFileWriteChainKeys' write-key walk; returns hex-wrapped writeDescriptorRef only, raw writeKey never leaves the SDK
- [Phase ?]: [Phase 68.1-18]: resolveParentIpnsName translates useFolderNavigation's 'root' sentinel to the real root IPNS name for SDK write-chain calls
- [Phase ?]: [Phase 68.1-19]: UpdateGrantDto write-toggle uses explicit clearWriteDescriptor boolean (not empty-string sentinel) as the downgrade clear-signal; mutually exclusive with writeDescriptorRef (BadRequestException if both supplied); omitting both leaves writeDescriptorRef untouched for existing read-only-rotation callers (owner-reconcile)
- [Phase ?]: 68.2-01: read-path gate mirrors write-path gate but sources generation from childRef.generation (parent SealedChildRef mirror) for children, and in-memory folderTree nodeGeneration for root (no parent mirror exists)
- [Phase ?]: 68.2-01: getWriteBodyParams intentionally left ungated per D-05 -- this plan is read-path only
- [Phase ?]: [Phase 68.2-02]: gatedResolveChild is a NEW standalone per-child listing gate distinct from dfsFindFolder's tree-descent gate; resolveChildren catches ALL per-child resolve/unseal failures (widened from absent-record-only) since the already-loaded target folder remains gated via Plan 01, so an unresolvable sibling is simply omitted, not rendered stale/tampered
- [Phase ?]: [Phase 68.2-02]: listingCache is keyed by plain ipnsName (not namespaced per owned/shared path) and invalidated by sequenceNumber; updateSharedFile explicitly invalidates the cache entry on file-only republish since that doesn't bump the parent's own sequence
- [Phase ?]: [Phase 68.2-03]: uploadBytes/downloadBytes/unpin added as new standalone facade methods (not extensions to pinWithMode) -- mediate the web's direct raw-IPFS-transport call sites orthogonal to uploadFile/uploadFiles orchestration
- [Phase ?]: [Phase 68.2-03]: getFolderMetadata returns the full decrypted Node (matching sdkCore.fetchAndDecryptMetadata's shape) by delegating entirely to the gated ensureFolderLoaded -- listFolder remains the resolved-children-only entrypoint
- [Phase ?]: [Phase 68.2-03]: pure structural utils (getDepth/isDescendantOf/calculateSubtreeDepth/selectEncryptionMode) re-exported directly from @cipherbox/sdk-core's own barrel, not re-implemented
- [Phase ?]: [Phase 68.2-05]: shared-folder-desync.spec.ts asserts against FileListItem.tsx's raw em-dash/epoch placeholder values directly (not FileListPage.getFileItem/getFolderItem's dash-based type filters, a pre-existing unrelated selector quirk) -- avoids coupling the new SC#5 spec to that mismatch
- [Phase ?]: [Phase 68.2-04]: serializeVault/deserializeVault combine encryptVaultKeys+serializeVaultBlobV3 and deserializeVaultBlobV3+unwrapKey x2 into single facade calls mirroring useAuth.ts's exact sequences
- [Phase ?]: [Phase 68.2-04]: deserializeVault zeroes the already-unwrapped rootReadKey if the paired unwrapKey call for rootWriteKey fails (T-68.2-09)
- [Phase ?]: [Phase 68.2-04]: resolveConfigBlob/publishConfigBlob deliberately skip rotationHighWater.enforceResolved -- BYO config blob is user-configured, not a rotation-governed node
- [Phase 68.2-06]: handleSync/resyncFolder call BOTH client.listFolder and client.getFolderMetadata -- FolderNode.children stays SealedChildRef[] (write-path crypto identity), a store-level ResolvedChild[] projection is Plan 09's job
- [Phase 68.2-06]: isFileRef widened to SealedChildRef | ResolvedChild union (not narrowed) after finding 6 live call sites outside this plan's scope that would break -- deliberate, documented exception to the plan's literal kind-cache-removal wording
- [Phase 68.2-06]: FileListItem.tsx dual-prop pattern: item stays SealedChildRef (identity/crypto carrier for callbacks), new resolved: ResolvedChild prop drives kind/size/modifiedAt display
- [Phase 68.2-07]: client.resolveChildIdentity added as a new SDK facade method (Rule 2) -- key-wrapping.ts's resolveChildNodeIdentity delegates to it, mirroring folder-listing.ts's resolveChildren per-child readKey-recovery step
- [Phase 68.2-07]: DetailsDialog.tsx drops the kind-cache fallback entirely (folderStore membership only); folder metadataCid always renders as unavailable since client.getFolderMetadata does not expose the raw resolve CID
- [Phase ?]: [Phase 68.2-08]: resolveShareRoot/descendSharedChild/downloadSharedFile added as Rule-2 SDK facades to complete the share-nav rewire; downloadSharedFile returns a revoked/behind-retry/ok union instead of throwing
- [Phase ?]: [Phase 68.2-08]: SharedFolderRow keeps item:SealedChildRef and adds a new resolved?:ResolvedChild prop (dual-prop pattern, mirrors Plan 06 FileListItem) rather than a straight type swap, since SharedFileBrowser.tsx's unowned dialog consumers still need readKeySealed
- [Phase ?]: [Phase 68.2-09]: FolderNode gained optional rawChildren?: SealedChildRef[] alongside the retyped children: ResolvedChild[] -- the SDK event no longer carries raw identity, and ~9 write-path files needed it
- [Phase ?]: [Phase 68.2-09]: shared-folder-projection.ts re-reads raw children from client.getSharedFolderState at event-apply time instead of the now-resolved sharedFolder:updated event payload
- [Phase ?]: [Phase 68.2-10]: sdk-provider.createBootstrapClient() added (deviation) -- throwaway CipherBoxClient for facade calls that must run before rootIpnsName/rootFolderKey exist (useAuth.ts vault-bootstrap/BYO-load pre-login path)
- [Phase ?]: [Phase 68.2-10]: DEFAULT_VAULT_SETTINGS/validateVaultSettings/VaultSettings re-exported from @cipherbox/sdk (deviation) -- closes the literal-wording D-07 gap PATTERNS.md flagged for vault-settings
- [Phase ?]: [Phase 68.2-10]: vault-settings.service.ts loadVaultSettings/saveVaultSettings take an injected CipherBoxClient param (bootstrap pre-login, real client post-login) instead of reaching for a module-level client
- [Phase ?]: [Phase 68.2-10]: device-registry.service.ts uses getSdkClient() unconditionally (no bootstrap client) since both exported functions only ever run post-login
- [Phase ?]: [Phase 68.2-11]: client.resolveFileMetadata added as new SDK facade method (Rule 2) mirroring downloadFromIpns's resolve+unseal steps -- read-only counterpart replacing the deleted web-native file-metadata.service.ts
- [Phase ?]: [Phase 68.2-11]: FileList.tsx repointed from dead kind-cache adapter to folder store's real children: ResolvedChild[] via resolvedByIpnsName lookup (mirrors 68.2-08 SharedFileBrowser pattern) -- closes STATE.md-flagged FileList/FileBrowser ownership gap
- [Phase ?]: [Phase 68.2-11]: download.service.ts was a 9th residual file-metadata.service.ts importer not in the orchestrator's 8-file audit -- discovered via grep sweep, migrated alongside the listed 8
- [Phase ?]: SealedChildRef mirror reverted to frozen NODE-03 5-field set; size/modifiedAt now come exclusively from ResolvedChild (D-08)
- [Phase ?]: Fixed 2 pre-existing e2e-blocking bugs (SharedFileBrowser empty-nav row, e2e em-dash selector mismatch) found while running the phase gate
- [Phase ?]: SDK-READ-03 NOT marked complete: ensureFolderLoaded never re-resolves an already-loaded folder from the network, so the SC#5 desync fix is still incomplete -- root-caused, recommend dedicated gap-closure plan
- [Phase 68.2-13]: doReresolveFolderInPlace sources RotationHighWater generation from existing.nodeGeneration (never the freshly relay-served envelope generation) and gates versionFloor:0, mirroring ensureRootFolderState/dfsFindFolder
- [Phase 68.2-13]: reresolveFolderInPlace/doReresolveFolderInPlace split into two private methods so the reresolveInFlight dedup map is registered synchronously before the first await, making concurrent forceResolve calls observe the same in-flight promise
- [Phase ?]: [Phase 68.2-14]: SDK-READ-03 marked [x] on the strength of shared-folder-desync.spec.ts step 3.1 passing cleanly (4/4 isolated); full-web-e2e-green portion documented as CI-fresh-container-authoritative-pending, not force-passed
- [Phase 70]: mergeRotatedChildren is a wholly separate exported function from folder/merge.ts mergeChildren, not a flag -- closes merge-downgrade Elevation-of-Privilege gap T-70-01
- [Phase ?]: Corrupt-sidecar fail-closed via a bounded i64::MAX sentinel within the existing HighWaterStore trait shape, avoiding a Result-returning trait change that would ripple into out-of-scope listing.rs/adapter.rs
- [Phase ?]: TS idbPut verified already max-preserving atomic; no functional TS change needed for SC#5, only a docstring parity note
- [Phase 70-03]: progress('rotated'/'complete') defers to persistJob's terminal branch for per-root Set drain (no rootNodeId on that callback); only resets the badge when the set is already empty
- [Phase ?]: [Phase 70-04]: mergeConcurrentChildren (site A) swapped from remote-wins mergeChildren to local-wins mergeRotatedChildren and returns { published, mergedChildren }; rotateOne captures mergedChildrenForReturn so its final return uses the CAS-merged children
- [Phase ?]: [Phase 70-04]: updateFolderMetadataAndPublish gained optional mergeChildrenFn param defaulting to mergeChildren (remote-wins unchanged for non-rotation callers); both D-09 batched-republish call sites pass mergeRotatedChildren plus a baseChildrenSnapshot captured at parentTracking.set time; concurrently-added children diffed from publishedChildren are enqueued onto the BFS frontier
- [Phase ?]: verifySubtreeClean recursion stops below a dirty edge (no crypto recovery path for a key lost to an interrupted prior run); returns key-bearing DirtyFrontierItem shape, consumption wiring deferred to plan 70-06
- [Phase ?]: Missing root record returns isDirty:true with empty frontier; downstream rotateReadFromNode already re-resolves root and throws a descriptive error on that path
- [Phase ?]: rotateReadFromNode entry gate probes root-unseal viability before deciding fresh rotateOne(root) vs dirty-tail recovery; RootKeyStaleError is the distinct stale-key error; ROT-06 no-double-bump convergence guard removed in favor of safe double-rotation (design 4.5)
- [Phase ?]: grantCallbacks/innerGrants threaded through RotationParams into every rotateOne call site (root + BFS loop) so reMintGrantsRootedAt is reachable in the real walk (SC#4)
- [Phase ?]: Dirty-resume-republish path returns a fresh-copy readKey (new Uint8Array), never aliasing the caller-owned rootReadKey (SC#6/T-70-10)
- [Phase ?]: performScopeExitRotation is the terminal owner of rotationResult.readKey; zeroes unconditionally once a rotation ran (70-07)
- [Phase ?]: RootKeyStaleError catch does not retry rotateReadFromNode after re-nav recovery; deferred rotation picked up by the next covered mutation (70-07)
- [Phase ?]: Pure-revoke never triggers rotation eagerly and rotation never re-seals its own root's ancestor mirror -- accepted residual, documented not fixed (70-07 Open Question 2)
- [Phase ?]: Test 3's strengthened assertion derives subfolder3's key via unsealChildReadKey against the new root key and unseals its ACTUAL published body, proving local-wins keeps the D-02 re-seal intact
- [Phase ?]: Test 4 uses a deliberately childless (single file node) rotation root — a traced D-02/D-09 timing analysis shows any multi-level tree crash before the walk's final persist hits an unrecoverable AEAD mismatch via this suite's persistCallback-only fault-injection model
- [Phase ?]: Test 4 crashes on the FIRST persistCallback call and resumes with EMPTY completedNodeIds plus the CURRENT valid rootReadKey (captured via the existing spy), converging via safe double-rotation
- [Phase 70 post-gate fix]: 70-04's enqueueConcurrentlyAddedChildren over-reached ROT-05 by pushing a concurrently-added child onto the BFS queue for its own rotateOne pass (requires an IPNS write key the rotating party may not hold) and ran after parentTracking teardown so the re-seal never reached the parent's published SealedChildRef; replaced with createConcurrentAddResealingMerge, an async mergeChildrenFn wrapper invoked inside the D-09 CAS-409 merge that re-seals only the concurrent child's readKeySealed wrapper (trying both the parent's old and already-current key) without rotating the child's own node -- commit 7faa0e82835d56368ea87f969d57b083d43ea9a3; sdk-e2e rotation-crash-safety 4/4 green, sdk-core unit 355/355 green
- [Phase 72-01]: Rewrote 13-test skipped legacy suite into 1 live test of the reachable write-chain branch instead of modernizing legacy-branch tests slated for deletion in Plan 07 — 72-RESEARCH.md Critical Finding 3: SC#5 had zero regression coverage; modernizing dead-branch tests is wasted effort
- [Phase 72-02]: write-chain-rotation.test.ts: identify rotated seeds via a scoped vi.spyOn(cryptoModule, 'generateEd25519Keypair') read-back in guaranteed child-first call order, not fixed capturedKeys[0]/[2] offsets — capturedKeys mixed Ed25519 seeds with writeKey/ephemeral randoms at unstable positions; the spy observes the exact minting call and works across the sdk-core dist bundle boundary since @cipherbox/crypto is externalized, unlike createAndPublishIpnsRecord which is bundled internally and not spy-able from outside
- [Phase ?]: 72-03: Write-plane base-aware merge treats a childId absent from LOCAL (relative to base) as an intentional delete regardless of remote — stricter than the read-plane mergeChildren, required for SC#1's resurrection guard
- [Phase ?]: 72-03: baseWriteChildren is optional on updateFolderMetadataAndPublish; omitting it falls back to the legacy naive union (back-compat for moveItem/restoreFromBin, not yet threaded)
- [Phase ?]: 72-03: deleteItem's UUID-resolve-and-drop step fails OPEN (never aborts the already-succeeded read-plane delete)
- [Phase ?]: [72-04] getWriteBodyParams split: transient-miss with real writeKey throws (fail-closed); structurally-absent writeSealed stays fail-open (unchanged)
- [Phase 72-05]: restoreFromBin re-homing only runs when sourceFolder.ipnsName !== targetFolderIpnsName (same-parent restore is a write-body no-op)
- [Phase 72-05]: permanentDeleteFromBin drops the lingering original-parent WriteChildRef by BinEntry.nodeRef.id (captured UUID witness), never a fresh resolve
- [Phase 72]: [Phase 72-06]: SC#4 reframed per Critical Finding 1 -- fix is listingCache.delete(folderIpnsName) gated on a caller-computed fileContentChanged boolean (size/cid comparison), not a SealedChildRef schema change
- [Phase 72]: [Phase 72-06]: updateSharedSingleFile's two unwrapKey calls moved inside the existing try/finally so a throw on the second unwrap still zeroes the already-unwrapped first key
- [Phase 72]: Removed the unreachable moveInSharedFolder legacy share-keys branch and getShareKeysFn param; updated the Plan 01 regression test call site to match (Rule 3 blocking fix, not in plan file list)
- [Phase ?]: [Phase 72-08]: walkChildWriteKey mode controls ONLY the missing-WriteChildRef lookup; an AEAD unseal failure is NEVER swallowed by any mode (deviates from RESEARCH.md's literal 'nullable' table wording, confirmed by resolveSharedSubfolderWriteKey's own throw-on-tamper regression tests) — Preserving RESEARCH's literal table wording would have converted a security-critical AEAD tamper-detection throw into a silent null return, breaking 2 existing tests and introducing a fail-open regression
- [Phase ?]: [Phase 72-08]: updateSharedFile's inline write-chain walk (site 5) left as a documented, not-folded exception -- getFileIpnsKeyFn fallback confirmed LIVE via apps/web/src/hooks/useSharedWriteOps.ts resolveFileIpnsKey
- [Phase ?]: 72-09: only the shared TEE-wrap sequence (hexToBytes -> wrapKey -> bytesToHex) extracted into wrapIpnsKeyForTee; each site's own fail-closed validation throws (per-site error messages) left in place at call sites
- [Phase ?]: 72-09: vault/index.ts's two root-key wraps (wrapKey(rootReadKey/rootWriteKey, userPublicKey)) left untouched — only the TEE ipns-key wrap was extracted
- [Phase ?]: runFileVersionOp is not wrapped in withOperation itself -- each public method keeps its own withOperation(name) call for correct per-op telemetry attribution
- [Phase ?]: write-body-params.ts standardizes the IPNS-resolve path on inline resolveIpnsRecord+fetchFromIpfs+JSON.parse (bin's pre-existing style) rather than client.ts's resolvePublishedNode wrapper, since the extra signatureVerified field was never consumed by getWriteBodyParams

## Operator Next Steps

- Run `/gsd-plan-phase 61` to begin Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT

## Session

**Last session:** 2026-07-10T15:32:28.115Z
**Stopped at:** Completed 72-10-PLAN.md
**Resume file:** 

None

- GAP-2 (68.1-13): full-workflow.spec.ts 3.8 cold-reload multi-level IPNS DFS resolve times out -- needs retry-budget tuning or propagation investigation
- 68.2-06 gap: FileList.tsx/FileBrowser.tsx/SelectionActionBar.tsx/ContextMenu.tsx/SharedFileBrowser.tsx are not owned by any of the 12 phase-68.2 plans, yet consume the SealedChildRef-vs-ResolvedChild data this phase's D-02/SC#1/#2 goals govern -- assign ownership (Plan 09 or a fast-follow) before Plan 11's kind-cache.ts deletion / allowlist-free grep gate
- SC#5 desync (partially closed by 68.2-13): CipherBoxClient.ensureFolderLoaded/listFolder now support a gated `{forceResolve:true}` re-resolve for an already-loaded folder, proven by folder-reresolve.test.ts -- but apps/web's two D-03 freshness call sites (useFolderNavigation.ts nav re-resolve, useSyncPolling.ts poll invalidation) do not yet pass forceResolve, so shared-folder-desync.spec.ts step 3.1 is still expected red until Plan 14 wires the web + proves the e2e
