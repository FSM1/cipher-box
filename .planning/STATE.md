---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: unknown
last_updated: '2026-03-24T11:07:09.945Z'
progress:
  total_phases: 8
  completed_phases: 5
  total_plans: 27
  completed_plans: 25
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-07)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 23 — rust-sdk-extraction

## Current Position

Phase: 23 (rust-sdk-extraction) — EXECUTING
Plan: 5 of 7

## Performance Metrics

**Velocity:**

- Total plans completed: 160 (72 M1 + 83 M2 + 5 M3)
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
| 23    | 01   | 13min    | 2     | 26    |
| 23    | 02   | 10min    | 2     | 33    |
| 23    | 03   | 11min    | 2     | 23    |
| 23    | 05   | 12min    | 2     | 24    |
| 23    | 04   | 22min    | 2     | 17    |

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

### Roadmap Evolution

- Phase 19.1 inserted after Phase 19: Extract core crypto SDK as shared package (URGENT)
- Phase 19.2 inserted after Phase 19: IPFS Upload Performance Optimization (URGENT) — concurrent pins, Kubo worker tuning, pin batching to address ~95% bottleneck in upload path identified by Phase 19 baselines
- Phase 23 added: Rust SDK Extraction — extract shared cipherbox-core crate, replace duplicated logic in desktop FUSE code, enable unit testing parity with TypeScript

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

---

Last updated: 2026-03-24 after completing 23-05 (cipherbox-sdk crate extraction)
