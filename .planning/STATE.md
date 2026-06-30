---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Metadata and Sharing Refactor
current_phase: 67
current_phase_name: TEE Lease-Renewer Contract Rewrite
status: executing
stopped_at: Phase 67 context gathered
last_updated: "2026-06-30T23:15:07.114Z"
last_activity: 2026-06-30
last_activity_desc: Phase 67 planning complete
progress:
  total_phases: 9
  completed_phases: 6
  total_plans: 45
  completed_plans: 45
  percent: 67
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-06-27)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 66 — api-schema-cutover-publish-gate-and-tombstone

## Current Position

Phase: 67 — TEE Lease-Renewer Contract Rewrite
Plan: Not started
Status: Ready to execute
Last activity: 2026-06-30 — Phase 67 planning complete

Progress: `░░░░░░░░░░` 0 / 9 phases (0%)

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

## Operator Next Steps

- Run `/gsd-plan-phase 61` to begin Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT

## Session

**Last session:** 2026-06-30T22:16:08.298Z
**Stopped at:** Phase 67 context gathered
**Resume file:** .planning/phases/67-tee-lease-renewer-contract-rewrite/67-CONTEXT.md
