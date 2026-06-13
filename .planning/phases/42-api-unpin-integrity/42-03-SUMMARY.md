---
phase: 42-api-unpin-integrity
plan: "03"
subsystem: api
tags:
  - typeorm
  - security
  - tdd
  - advisory-lock
  - refcount
  - outbox
dependency_graph:
  requires:
    - 42-01 (PendingUnpin entity + pending_unpins migration)
  provides:
    - VaultService.guardedUnpin(userId, cid)
    - per-CID pg_advisory_xact_lock serialization (D-04)
    - in-transaction row delete as quota decrement (D-03)
    - refcount-gated pending_unpins outbox insert (D-05)
    - cross-user audit via unpinCrossUserAttempts metric (D-02)
    - ownership enforcement with no-oracle silent success (D-01)
  affects:
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.module.ts
tech_stack:
  added: []
  patterns:
    - TypeORM dataSource.transaction with manager.getRepository
    - pg_advisory_xact_lock via raw manager.query (abs(hashtext) to avoid bigint overflow)
    - orIgnore insert into outbox for concurrent insert idempotency
    - post-commit best-effort Kubo call (never inside transaction)
    - NestJS local IPFS_PROVIDER useFactory to break circular IpfsModule dependency
key_files:
  created: []
  modified:
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.module.ts
    - apps/api/src/vault/vault.service.spec.ts
decisions:
  - "IPFS_PROVIDER provided locally in VaultModule via useFactory mirroring IpfsModule, avoiding circular import (IpfsModule already imports VaultModule)"
  - "Kubo call is post-commit best-effort: transaction failure never rolls back the Kubo call; Kubo failure never rolls back the row delete (D-03)"
  - "abs(hashtext(cid)) for advisory lock key to prevent bigint-out-of-range on negative hashtext (Pitfall 2)"
  - "orIgnore on pending_unpins insert dedupes concurrent deleters racing to insert the same CID outbox row (Pitfall 5)"
  - "recordUnpin method left in place (existing tests; guardedUnpin supersedes its controller use)"
metrics:
  duration: "25 minutes"
  completed_date: "2026-06-12"
  tasks_completed: 2
  files_changed: 3
---

# Phase 42 Plan 03: guardedUnpin Security Core Summary

VaultService.guardedUnpin with pg_advisory_xact_lock as first statement, in-transaction row delete and refcount, outbox insert gated on refcount 0, post-commit best-effort Kubo unpin, and cross-user audit telemetry.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | RED - guardedUnpin behavior spec with DataSource and IPFS provider mocks | 7b2ebac7e | vault.service.spec.ts |
| 2 | GREEN - implement guardedUnpin and wire vault.module | 9c9f95b38 | vault.service.ts, vault.module.ts |

## What Was Built

### guardedUnpin Method

`VaultService.guardedUnpin(userId: string, cid: string): Promise<void>` in `apps/api/src/vault/vault.service.ts`:

1. Opens a TypeORM transaction via `this.dataSource.transaction(async (manager) => { ... })`.
2. First statements: `SELECT abs(hashtext($1))::bigint AS h` then `SELECT pg_advisory_xact_lock($1)` — serializes all concurrent deleters for the same CID (D-04). `abs()` prevents bigint overflow on negative hashtext values.
3. Ownership check: `pinnedCidRepo.findOne({ where: { userId, cid } })`. If no row, checks for cross-user existence and emits `logger.warn` + `metricsService.unpinCrossUserAttempts.inc()` if found. Either no-row path returns silently — identical 2XX to caller (D-01, no oracle).
4. Owned path: `pinnedCidRepo.delete({ userId, cid })` — this row delete IS the quota decrement (D-03).
5. Refcount: `manager.createQueryBuilder(PinnedCid, 'pc').select('COUNT(*)','count').where('pc.cid = :cid',{cid}).getRawOne()` — counts all users' rows for the CID (D-07: no origin filtering).
6. If `refcount === 0`: `pendingUnpinRepo.createQueryBuilder().insert().into(PendingUnpin).values({ cid }).orIgnore().execute()` — sets `outboxRowInserted = true`.
7. Post-commit (outside transaction): if `outboxRowInserted`, `try { await ipfsProvider.unpinFile(cid); await pendingUnpinRepository.delete({ cid }); } catch { /* leave for worker */ }`. LocalProvider already swallows "not pinned" so BYO-only rows resolve as success.
8. `metricsService.fileUnpins.inc()` at the end.

### vault.module.ts

- Added `PendingUnpin` to `TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User, PendingUnpin])`.
- Registered `IPFS_PROVIDER` locally via `useFactory` mirroring `ipfs.module.ts` (`IPFS_LOCAL_API_URL` / `IPFS_LOCAL_GATEWAY_URL` from ConfigService, `new LocalProvider(apiUrl, gatewayUrl)`). No `IpfsModule` import — `IpfsModule` already imports `VaultModule`, so re-importing would be circular.
- `MetricsService` is `@Global()` so no explicit import needed.

### Test Spec (TDD Gate Compliance)

RED commit (`7b2ebac7e`) precedes GREEN commit (`9c9f95b38`) in git history.

Six guardedUnpin cases in `vault.service.spec.ts`:
- `no-row, CID unknown`: both findOne null — no transaction ops, no Kubo, no metric
- `no-row, cross-user`: own findOne null, any-user findOne returns row — `unpinCrossUserAttempts.inc()` called, no delete, no Kubo
- `owned, refcount > 0`: delete called, no outbox insert, no Kubo
- `owned, refcount === 0`: delete + orIgnore insert in transaction, then Kubo + outbox delete post-commit
- `owned, refcount === 0, Kubo throws`: guardedUnpin still resolves, outbox row left for worker
- `advisory lock ordering`: `pg_advisory_xact_lock` call precedes `pinnedCidRepo.delete` by call order assertion

## Deviations from Plan

None - plan executed exactly as written.

## TDD Gate Compliance

- RED gate: `test(42-03)` commit `7b2ebac7e` — PRESENT
- GREEN gate: `feat(42-03)` commit `9c9f95b38` — PRESENT (after RED)
- REFACTOR gate: not required, implementation was clean

## Known Stubs

None. guardedUnpin is fully wired with real dependencies injected.

## Threat Surface Scan

No new network endpoints or auth paths introduced. guardedUnpin is an internal service method; the controller entry point is 42-05. The method mitigates T-42-06 (cross-tenant unpin via CID knowledge), T-42-07 (CID-existence oracle), T-42-08 (refcount race), T-42-09 (quota inflation) as specified in the threat register.

## Self-Check: PASSED

- `apps/api/src/vault/vault.service.ts` guardedUnpin method — FOUND (line 231)
- `apps/api/src/vault/vault.module.ts` PendingUnpin in forFeature — FOUND (line 14)
- `apps/api/src/vault/vault.module.ts` no IpfsModule import — CONFIRMED (grep returns 0)
- commit 7b2ebac7e (RED) — FOUND
- commit 9c9f95b38 (GREEN) — FOUND
- vault.service.spec.ts 58/58 tests passing — CONFIRMED
