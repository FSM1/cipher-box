---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: unknown
last_updated: '2026-03-20T01:52:39.076Z'
progress:
  total_phases: 6
  completed_phases: 2
  total_plans: 10
  completed_plans: 8
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-07)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 19.1 — extract-core-crypto-sdk-as-shared-package

## Current Position

Phase: 19.1 (extract-core-crypto-sdk-as-shared-package) — EXECUTING
Plan: 4 of 6

## Performance Metrics

**Velocity:**

- Total plans completed: 157 (72 M1 + 83 M2 + 2 M3)
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

### Roadmap Evolution

- Phase 19.1 inserted after Phase 19: Extract core crypto SDK as shared package (URGENT)

### Open Concerns

- 9 LOW-priority tech debt items from M2 audit (see `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`)
- rootFolderKey migration dual-write window duration TBD (forced migration strategy for dormant accounts)
- BYO-IPFS auth token storage model needs explicit acceptance (server sees token but not plaintext content)
- Kubo v0.34.0 -> v0.40.1 upgrade decision (recommended before Phase 19, not blocking)
- Recovery tool independence must be verified after Phases 19+20 changes

### Resolved

All M2 blockers resolved. See `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`.

---

Last updated: 2026-03-20 after completing 19.1-04 (SDK package with CipherBoxClient, bin/share, event system)
