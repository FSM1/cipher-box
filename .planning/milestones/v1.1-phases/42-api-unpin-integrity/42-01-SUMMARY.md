---
phase: 42-api-unpin-integrity
plan: "01"
subsystem: api
tags:
  - typeorm
  - migrations
  - prometheus
  - unpin-integrity
dependency_graph:
  requires: []
  provides:
    - PendingUnpin entity
    - pending_unpins table migration
    - idx_pinned_cids_cid index migration
    - MetricsService unpin audit metrics
  affects:
    - apps/api/src/app.module.ts
    - apps/api/src/metrics/metrics.service.ts
tech_stack:
  added: []
  patterns:
    - TypeORM entity with unique column index
    - additive-only IF NOT EXISTS migrations
    - prom-client unlabeled Counter and Gauge
key_files:
  created:
    - apps/api/src/vault/entities/pending-unpin.entity.ts
    - apps/api/src/migrations/1749000000000-AddPendingUnpins.ts
    - apps/api/src/migrations/1749100000000-AddPinnedCidCidIndex.ts
  modified:
    - apps/api/src/vault/entities/index.ts
    - apps/api/src/app.module.ts
    - apps/api/src/metrics/metrics.service.ts
decisions:
  - "PendingUnpin has no userId column per D-05: pure Kubo work queue outbox, not user-scoped"
  - "Unique index on cid in both entity and migration enables orIgnore idempotent concurrent inserts"
  - "idx_pinned_cids_cid added to pinned_cids for O(log n) refcount WHERE cid=? queries"
  - "Three metrics added unlabeled following existing cipherbox_* convention"
metrics:
  duration: "11 minutes"
  completed_date: "2026-06-12"
  tasks_completed: 2
  files_changed: 6
---

# Phase 42 Plan 01: Schema and Metrics Foundation Summary

PendingUnpin TypeORM entity with unique-cid outbox semantics, two additive migrations for the pending_unpins table and pinned_cids CID index, plus three Prometheus metrics for cross-user audit, drift detection, and outbox depth.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | Create PendingUnpin entity, migrations, and register in app.module | 44f865781 | pending-unpin.entity.ts, index.ts, 1749000000000-AddPendingUnpins.ts, 1749100000000-AddPinnedCidCidIndex.ts, app.module.ts |
| 2 | Add cross-user, drift, and pending-unpins metrics to MetricsService | 920ab0831 | metrics.service.ts |

## What Was Built

### PendingUnpin Entity

`apps/api/src/vault/entities/pending-unpin.entity.ts` — minimal outbox entity with:

- `id` (UUID primary key)
- `cid` (varchar 255, unique index `idx_pending_unpins_cid`)
- `createdAt` (created_at timestamp)
- No `userId` column per D-05: the outbox is a pure Kubo work queue

### Migrations

- `1749000000000-AddPendingUnpins.ts`: `CREATE TABLE IF NOT EXISTS pending_unpins` with `CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_unpins_cid`. The unique CID index makes concurrent `.orIgnore()` inserts idempotent.
- `1749100000000-AddPinnedCidCidIndex.ts`: `CREATE INDEX IF NOT EXISTS idx_pinned_cids_cid ON pinned_cids(cid)`. Needed because `pinned_cids` only indexed `user_id`; the refcount query is `WHERE cid = ?`.

Both migrations are additive-only (IF NOT EXISTS) with matching class name = name property per DATABASE_EVOLUTION_PROTOCOL.

### App Module Registration

`PendingUnpin` added to `app.module.ts` entities array import and array entry, preventing EntityMetadataNotFoundError at startup (T-42-03 mitigation).

### MetricsService

Three new metrics in `apps/api/src/metrics/metrics.service.ts`:

- `unpinCrossUserAttempts` (`cipherbox_unpin_cross_user_attempts_total`) — Counter, D-02 cross-user audit
- `driftOrphanedPinsTotal` (`cipherbox_drift_orphaned_pins_total`) — Counter, D-06 Kubo drift report
- `pendingUnpinsGauge` (`cipherbox_pending_unpins_total`) — Gauge, D-05 outbox depth

All unlabeled, `registers: [this.registry]`, following existing cipherbox_* convention.

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None. This plan produces schema artifacts and metric declarations only — no data flow, no UI, no stubs.

## Threat Surface Scan

No new network endpoints or auth paths introduced. Metrics are unlabeled aggregate counts with no CID or user material (T-42-02: accepted). DDL is additive-only (T-42-01: mitigated). Entity registered in app.module (T-42-03: mitigated).

## Self-Check: PASSED

- `apps/api/src/vault/entities/pending-unpin.entity.ts` — FOUND
- `apps/api/src/migrations/1749000000000-AddPendingUnpins.ts` — FOUND
- `apps/api/src/migrations/1749100000000-AddPinnedCidCidIndex.ts` — FOUND
- commit 44f865781 — FOUND
- commit 920ab0831 — FOUND
