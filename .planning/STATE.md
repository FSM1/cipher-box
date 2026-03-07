# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-07)

**Core value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Current focus:** Phase 18 - Performance Instrumentation (v1.1 IPFS Infrastructure)

## Current Position

Phase: 18 (first of 5 in v1.1 milestone)
Plan: 1 of 2 complete
Status: Executing
Last activity: 2026-03-07 -- Completed 18-01 (Prometheus duration histograms)

Progress: [██░░░░░░░░░░░░░░░░░░░░░░░] M3 5%

## Performance Metrics

**Velocity:**

- Total plans completed: 156 (72 M1 + 83 M2 + 1 M3)
- Average duration: 5.5 min
- Total execution time: ~16.5 hours

## Accumulated Context

### Key Decisions

See PROJECT.md Key Decisions table for full list with outcomes.

Recent for v1.1:

- DB-first with async Kubo DHT verification adopted as IPNS resolution strategy (not Kubo-only or PubSub)
- rootFolderKey DB copy kept as permanent fallback (never drop column, IPFS copy for recovery independence)
- BYO-IPFS affects pinning only, all IPNS publishes still route through CipherBox API
- PERF requirements split across Phase 18 (server-side, pre-change) and Phase 22 (client + load testing, post-change)
- IPFS/IPNS histogram buckets: 1ms-30s exponential (14 buckets); republish batch: 1s-120s (10 buckets)
- Source label (db/network) only for resolve operations; empty string for pin/cat/publish

### Open Concerns

- 9 LOW-priority tech debt items from M2 audit (see `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`)
- rootFolderKey migration dual-write window duration TBD (forced migration strategy for dormant accounts)
- BYO-IPFS auth token storage model needs explicit acceptance (server sees token but not plaintext content)
- Kubo v0.34.0 -> v0.40.1 upgrade decision (recommended before Phase 19, not blocking)
- Recovery tool independence must be verified after Phases 19+20 changes

### Resolved

All M2 blockers resolved. See `.planning/milestones/m2/m2-v1.0-production-MILESTONE-AUDIT.md`.

---

Last updated: 2026-03-07 after 18-01 plan execution
