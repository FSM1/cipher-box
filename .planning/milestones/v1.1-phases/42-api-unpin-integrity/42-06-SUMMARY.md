---
phase: 42-api-unpin-integrity
plan: "06"
subsystem: api
tags:
  - bullmq
  - typeorm
  - prometheus
  - unpin-integrity
  - tdd
dependency_graph:
  requires:
    - 42-01 (PendingUnpin entity + metrics)
    - 42-04 (guardedUnpin outbox semantics)
  provides:
    - PendingUnpinProcessor WorkerHost drain and drift handlers
    - PendingUnpinModule BullMQ queue + two repeating schedulers
    - PendingUnpinModule registered in app.module.ts
  affects:
    - apps/api/src/app.module.ts
tech_stack:
  added: []
  patterns:
    - BullMQ WorkerHost processor with job.name dispatch
    - upsertJobScheduler repeating cron in OnModuleInit
    - IPFS_PROVIDER locally provided to avoid circular import
    - Kubo NDJSON pin/ls parsed line-by-line
    - Error-isolated per-row retry with gauge publish
key_files:
  created:
    - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
    - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts
  modified:
    - apps/api/src/app.module.ts
decisions:
  - "IPFS_PROVIDER provided locally in PendingUnpinModule via same useFactory as IpfsModule to avoid IpfsModule->VaultModule circular import"
  - "drainPendingUnpins calls ipfsProvider.unpinFile (never raw Kubo) to inherit local.provider.ts:94 not-pinned swallow behavior"
  - "runDriftReport is strictly read-only per D-06: increments counter and warn-logs, no delete or pin/rm path"
  - "Kubo pin/ls parsed as NDJSON line-by-line per Pitfall 6; per-line errors log and skip rather than throw"
  - "Two schedulers registered in same try/catch non-fatal block mirroring RepublishModule pattern"
metrics:
  duration: "18 minutes"
  completed_date: "2026-06-12"
  tasks_completed: 2
  files_changed: 4
---

# Phase 42 Plan 06: Pending-Unpins BullMQ Drain Worker and Drift Report Summary

BullMQ `PendingUnpinProcessor` WorkerHost with drain retry and read-only drift report, plus `PendingUnpinModule` registering two repeating schedulers wired into `app.module.ts`.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | RED — drain + drift processor behavior spec | 322dde512 | pending-unpin.processor.spec.ts |
| 2 | GREEN — implement processor + module, register in app.module | 07ec593d5 | pending-unpin.processor.ts, pending-unpin.module.ts, app.module.ts |

## What Was Built

### PendingUnpinProcessor

`apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` — `@Processor('pending-unpins')` class extending `WorkerHost`:

- `process(job)` dispatches on `job.name` to `drainPendingUnpins()` or `runDriftReport()`; unknown names are no-ops.
- `drainPendingUnpins()`: loads up to 50 rows, for each calls `ipfsProvider.unpinFile(cid)` (D-05: provider call, never raw Kubo, inheriting local.provider.ts:94 "not pinned" swallow). On success deletes the row. On failure logs and leaves the row for the next run. After the pass, calls `pendingUnpinsGauge.set(count)`.
- `runDriftReport()`: fetches `${apiUrl}/api/v0/pin/ls?type=recursive` (POST), reads `.text()`, splits on newlines, JSON-parses each non-empty line (NDJSON per Pitfall 6 — never `.json()`), collects CIDs from `Keys`. Builds DB accounted set as `pinned_cids ∪ pending_unpins`. For each Kubo pin not in DB set: increments `driftOrphanedPinsTotal` and `logger.warn`. **Never deletes** (D-06). Kubo fetch failure logs and returns early.

### PendingUnpinModule

`apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` — `@Module` implementing `OnModuleInit`:

- Imports: `BullModule.registerQueue({ name: 'pending-unpins' })`, `TypeOrmModule.forFeature([PendingUnpin, PinnedCid])`, `ConfigModule`.
- Provides `IPFS_PROVIDER` locally via `LocalProvider(apiUrl, gatewayUrl)` useFactory — avoids importing `IpfsModule` (which imports `VaultModule`, creating a cycle).
- `onModuleInit()` registers two schedulers in a non-fatal try/catch:
  - `pending-unpins-drain` every 5 minutes (`*/5 * * * *`) dispatching `drain-pending-unpins`
  - `pin-drift-report` every hour (`0 * * * *`) dispatching `drift-report`

### app.module.ts Registration

`PendingUnpinModule` added to `app.module.ts` imports array alongside `RepublishModule` and `MigrationModule`. `PendingUnpin` entity was already in the global entities array from 42-01.

## TDD Gate Compliance

RED gate: `test(42-06)` commit 322dde512 — seven failing specs written before implementation.

GREEN gate: `feat(42-06)` commit 07ec593d5 — all 9 new processor tests pass (878 total, 44 suites).

## Deviations from Plan

None - plan executed exactly as written.

## Known Stubs

None. All behaviors are implemented and tested.

## Threat Surface Scan

No new network endpoints or auth paths. The drift report makes an outbound Kubo `pin/ls` HTTP call (same trust boundary as all other Kubo calls). The BullMQ queue adds a `pending-unpins` entry to Redis (same Redis instance used by all queues). T-42-18 mitigated: `runDriftReport` has zero `.delete(` calls. T-42-20 mitigated: drain calls `ipfsProvider.unpinFile` (provider handles "not pinned"). T-42-21 mitigated: per-line parse with try/catch, Kubo outage logs and skips.

## Self-Check: PASSED

- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` — FOUND
- `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` — FOUND
- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` — FOUND
- commit 322dde512 — FOUND
- commit 07ec593d5 — FOUND
- grep `\.delete(` in runDriftReport body: 0 matches
- grep `PendingUnpinModule` in app.module.ts: 2 matches (import + imports array)
- grep IpfsModule in pending-unpin.module.ts: 0 matches
