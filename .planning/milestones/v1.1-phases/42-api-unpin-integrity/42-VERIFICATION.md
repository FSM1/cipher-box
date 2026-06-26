---
phase: 42-api-unpin-integrity
verified: 2026-06-12T00:00:00Z
status: passed
score: 8/8 must-haves verified
overrides_applied: 0
human_verification:
  - test: 'Confirm pending_unpins table and indexes exist in live dev Postgres'
    expected: 'to_regclass returns non-null for pending_unpins, idx_pending_unpins_cid, and idx_pinned_cids_cid'
    result: 'RESOLVED 2026-06-12 by orchestrator — to_regclass returned pending_unpins|idx_pending_unpins_cid|idx_pinned_cids_cid; \d pending_unpins shows id uuid PK (gen_random_uuid), cid varchar(255) with UNIQUE idx_pending_unpins_cid, created_at timestamp, no user_id column; pg_indexes lists idx_pinned_cids_cid on pinned_cids'
    why_human: 'Dev Postgres was not reachable from the verifier sandbox; the orchestrator ran the exact query against the cipherbox-postgres container and confirmed all expectations'
---

# Phase 42: API Unpin Integrity Verification Report

**Phase Goal:** Close the unpin-path gaps in `apps/api`: verify caller owns a `pinned_cids(userId, cid)` row before unpinning, reference-count CIDs across users before issuing global Kubo `pin/rm`, delete the caller's row, and decrement quota so deletes stop leaking quota.
**Verified:** 2026-06-12
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Caller ownership checked before any Kubo call | VERIFIED | `guardedUnpin` checks `pinnedCidRepo.findOne({ where: { userId, cid } })` and returns silently (no Kubo, no delete) when no row found — `vault.service.ts:261-268` |
| 2 | Cross-user attempt returns silent 2XX with audit telemetry | VERIFIED | No-row path returns void unconditionally; `metricsService.unpinCrossUserAttempts.inc()` + `logger.warn` only when cross-user CID row found — `vault.service.ts:263-268`. Controller returns constant `{ success: true }` for all outcomes — `ipfs.controller.ts:149-151` |
| 3 | CIDs reference-counted across ALL users before global Kubo pin/rm issued | VERIFIED | `COUNT(*)` query on `pinned_cids WHERE cid = ?` (no user filter, no BYO filter) — `vault.service.ts:275-280`. Kubo `pin/rm` only triggered when `refcount === 0` |
| 4 | Caller's pinned_cids row deleted inside transaction (row delete = quota decrement) | VERIFIED | `pinnedCidRepo.delete({ userId, cid })` inside `this.dataSource.transaction(...)` callback — `vault.service.ts:272`. The old `recordUnpin` is not called separately; the in-transaction delete is the quota decrement |
| 5 | Per-CID advisory xact lock is FIRST statement in transaction | VERIFIED | `SELECT abs(hashtext($1))::bigint AS h` then `SELECT pg_advisory_xact_lock($1)` as first two `manager.query` calls inside transaction callback — `vault.service.ts:255-258`. Advisory lock ordering test in `vault.service.spec.ts:988` asserts this by call-order |
| 6 | When refcount reaches zero, CID inserted into pending_unpins outbox in the SAME transaction; Kubo called post-commit best-effort | VERIFIED | orIgnore insert into `pending_unpins` sets `outboxRowInserted = true` inside transaction — `vault.service.ts:284-292`. Kubo `ipfsProvider.unpinFile` called AFTER `});` closing the transaction — `vault.service.ts:298-304`. Comment explicitly documents ordering |
| 7 | Web client fires fetchQuota() after local removeUsage() (D-12) | VERIFIED | `quotaStore.fetchQuota().catch((err) => logger.warn('quota reconcile failed', err))` as fire-and-forget directly after `removeUsage()` — `apps/web/src/services/delete.service.ts:21-22` |
| 8 | Upload compensation path routes through guardedUnpin (not raw unpinFile) with D-13 comment | VERIFIED | `this.vaultService.guardedUnpin(req.user.id, result.cid).catch(() => undefined)` at `ipfs.controller.ts:126`, preceded by D-13 race window comment at lines 122-125. `ipfsProvider.unpinFile` does not appear in the controller at all (grep returns 0 matches for `ipfsProvider.unpinFile` in controller) |

**Score:** 8/8 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `apps/api/src/vault/entities/pending-unpin.entity.ts` | PendingUnpin TypeORM entity with `@Entity('pending_unpins')`, unique cid index, no userId column | VERIFIED | `@Entity('pending_unpins')`, `@Index({ unique: true })` on cid, `@PrimaryGeneratedColumn('uuid')`, `@CreateDateColumn` — confirmed no userId/user_id column |
| `apps/api/src/migrations/1749000000000-AddPendingUnpins.ts` | CREATE TABLE pending_unpins + unique index on cid | VERIFIED | `CREATE TABLE IF NOT EXISTS pending_unpins` + `CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_unpins_cid`. Class name equals `name` property |
| `apps/api/src/migrations/1749100000000-AddPinnedCidCidIndex.ts` | CREATE INDEX idx_pinned_cids_cid on pinned_cids(cid) | VERIFIED | `CREATE INDEX IF NOT EXISTS idx_pinned_cids_cid ON pinned_cids(cid)`. Class name equals `name` property |
| `apps/api/src/app.module.ts` | PendingUnpin in entities array; PendingUnpinModule in imports | VERIFIED | Line 101: `PendingUnpin` in entities array; line 125: `PendingUnpinModule` in imports; line 22: import of `PendingUnpinModule` |
| `apps/api/src/metrics/metrics.service.ts` | Three new metrics: cross-user counter, drift counter, pending-unpins gauge | VERIFIED | `unpinCrossUserAttempts` (Counter, `cipherbox_unpin_cross_user_attempts_total`), `driftOrphanedPinsTotal` (Counter, `cipherbox_drift_orphaned_pins_total`), `pendingUnpinsGauge` (Gauge, `cipherbox_pending_unpins_total`) — all declared as `readonly` fields and instantiated in constructor with `registers: [this.registry]` |
| `apps/api/src/vault/vault.service.ts` | `guardedUnpin(userId, cid)` method | VERIFIED | Method at line 246, fully implementing D-01..D-05/D-07 with advisory lock, ownership check, in-transaction row delete, refcount, outbox insert, post-commit Kubo call |
| `apps/api/src/vault/vault.module.ts` | PendingUnpin in forFeature; IPFS_PROVIDER locally without IpfsModule import | VERIFIED | `TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User, PendingUnpin])` at line 14; local `useFactory` providing `LocalProvider` at lines 23-33; no `IpfsModule` import anywhere in file |
| `apps/api/src/ipfs/ipfs.controller.ts` | `unpin()` delegates to `vaultService.guardedUnpin(req.user.id, ...)`, no raw `ipfsProvider.unpinFile` | VERIFIED | `unpin(@Request() req, @Body() dto)` at line 148; delegates to `guardedUnpin` at line 149; zero occurrences of `ipfsProvider.unpinFile` in `unpin()` handler |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` | `@Processor('pending-unpins')` WorkerHost with drain and drift handlers | VERIFIED | `PendingUnpinProcessor extends WorkerHost` with `drainPendingUnpins()` (calls provider, not raw Kubo) and `runDriftReport()` (read-only; no `.delete(` calls in drift path) |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` | BullMQ module with two repeating schedulers in `onModuleInit` | VERIFIED | `upsertJobScheduler` for `pending-unpins-drain` (*/5 * * * *) and `pin-drift-report` (0 * * * *); non-fatal try/catch mirrors RepublishModule pattern |
| `apps/web/src/services/delete.service.ts` | `fetchQuota()` fire-and-forget after `removeUsage()` | VERIFIED | Line 22: `quotaStore.fetchQuota().catch((err) => logger.warn('quota reconcile failed', err))` — no `await`, not blocking |
| `scripts/backfill-pinned-cids.ts` | One-shot non-BYO quota repair script with dry-run and empty-Kubo guard | VERIFIED | `process.argv.includes('--dry-run')` flag; `process.exit(1)` on empty/unreachable Kubo; BYO exclusion via `WHERE v.is_byo_user = false`; `BATCH_SIZE = 10` batched deletes |
| `apps/api/src/scripts/backfill-helpers.ts` | Pure `selectRowsToDelete` + `parseKuboPinLs` functions | VERIFIED | `selectRowsToDelete` filters on `!row.isByoUser && !kuboPinSet.has(row.cid)` (D-09 predicate); `parseKuboPinLs` handles NDJSON line-by-line |
| `docker/grafana/alerts/unpin-cross-user-attempts.json` | Grafana alert on `cipherbox_unpin_cross_user_attempts_total` with threshold gt 0 | VERIFIED | `rate(cipherbox_unpin_cross_user_attempts_total[5m])` with `noDataState: "OK"`, `execErrState: "OK"`, threshold gt 0; CipherBox Security rule group |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `ipfs.controller.ts` | `VaultService.guardedUnpin` | `unpin()` handler with `req.user.id` | WIRED | Line 149: `this.vaultService.guardedUnpin(req.user.id, dto.cid)` |
| `ipfs.controller.ts` | `VaultService.guardedUnpin` | Upload compensation path | WIRED | Line 126: `this.vaultService.guardedUnpin(req.user.id, result.cid).catch(() => undefined)` |
| `vault.service.ts` | `pg_advisory_xact_lock` | First raw SQL in `dataSource.transaction` | WIRED | Lines 255-258: hashtext SELECT then advisory lock SELECT as first two manager.query calls |
| `vault.service.ts` | `pending_unpins` outbox | orIgnore insert when `refcount === 0` | WIRED | Lines 284-291: `pendingUnpinRepo.createQueryBuilder().insert().into(PendingUnpin).values({ cid }).orIgnore().execute()` inside transaction |
| `vault.service.ts` | `MetricsService.unpinCrossUserAttempts` | `inc()` on cross-user detection | WIRED | Line 266: `this.metricsService.unpinCrossUserAttempts.inc()` |
| `vault.module.ts` | `PendingUnpin` | `TypeOrmModule.forFeature` | WIRED | Line 14: array includes `PendingUnpin` |
| `vault.module.ts` | `IPFS_PROVIDER` | Local `useFactory` (no circular IpfsModule import) | WIRED | Lines 23-33: `useFactory` returning `new LocalProvider(...)` |
| `app.module.ts` | `PendingUnpin` | Global entities array | WIRED | Line 101 |
| `app.module.ts` | `PendingUnpinModule` | Imports array | WIRED | Line 125 |
| `delete.service.ts` | `useQuotaStore.fetchQuota` | Fire-and-forget call after `removeUsage` | WIRED | Line 22 |
| `pending-unpin.processor.ts` | `ipfsProvider.unpinFile` | Via injected `IPFS_PROVIDER` (inherits "not pinned" swallow) | WIRED | Line 54: `await this.ipfsProvider.unpinFile(row.cid)` |

---

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|--------------|--------|-------------------|--------|
| `vault.service.ts guardedUnpin` | `outboxRowInserted` | In-transaction refcount query + delete | Yes — refcount is a live COUNT(*) from the DB; delete is a real row removal | FLOWING |
| `pending-unpin.processor.ts drainPendingUnpins` | `rows` | `pendingUnpinRepository.find({...})` | Yes — DB query with ORDER BY and LIMIT | FLOWING |
| `pending-unpin.processor.ts runDriftReport` | `kuboPins` | Kubo `pin/ls` HTTP call, NDJSON parsed | Yes — real Kubo fetch; handles failure gracefully | FLOWING |
| `delete.service.ts` | `quotaStore` (post-delete reconcile) | `useQuotaStore.getState()` + `.fetchQuota()` | Yes — fetchQuota calls server `/vault/quota` endpoint | FLOWING |

---

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `guardedUnpin` advisory lock is first in transaction | `grep -n "pg_advisory_xact_lock" vault.service.ts` — line 258; `pinnedCidRepo.delete` at line 272 | Lock at line 258 < delete at line 272 | PASS |
| Controller has no direct `ipfsProvider.unpinFile` | `grep -c "ipfsProvider.unpinFile" ipfs.controller.ts` | 0 occurrences | PASS |
| `fetchQuota` in delete.service.ts is fire-and-forget | No `await` before `fetchQuota()` call at line 22 | Confirmed: no `await` | PASS |
| Kubo call outside transaction | `ipfsProvider.unpinFile` at line 299, `this.dataSource.transaction` closes at line 294 | Line 299 > 294 | PASS |
| Drift report has no delete calls | `grep "\.delete(" pending-unpin.processor.ts` excluding drain method | 0 delete calls in `runDriftReport` body | PASS |
| Pending-unpin entity has no userId column | `grep "user_id\|userId" pending-unpin.entity.ts` | 0 matches | PASS |
| BYO exclusion in backfill | `grep "is_byo_user" scripts/backfill-pinned-cids.ts` | `WHERE v.is_byo_user = false` present | PASS |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| TODO-unpin-ownership (`2026-06-11-ipfs-unpin-missing-ownership-check`) | 42-01, 42-03, 42-05 | Any authenticated user could unpin any CID | SATISFIED | `guardedUnpin` enforces ownership check; controller passes `req.user.id`; compensation path uses `guardedUnpin` |
| TODO-quota-decrement (`2026-06-11-server-quota-never-decremented-on-unpin`) | 42-01, 42-02, 42-03 | `recordUnpin` had zero callers; quota monotonically grew | SATISFIED | In-transaction `pinnedCidRepo.delete` is the quota decrement (D-03); web `fetchQuota` reconciles client state (D-12) |
| UNPIN-OWN | 42-03, 42-05 | Ownership check via pinned_cids row before any Kubo call | SATISFIED | `guardedUnpin` — ownership check lines 261-268 |
| UNPIN-REFCOUNT | 42-03 | Only issue global pin/rm when refcount across all users = 0 | SATISFIED | COUNT(*) query without user filter; Kubo only if refcount = 0 |
| UNPIN-QUOTA | 42-03 | Row delete in transaction = quota decrement | SATISFIED | `pinnedCidRepo.delete` inside `dataSource.transaction` callback |
| UNPIN-OUTBOX | 42-01, 42-03, 42-06 | pending_unpins outbox + BullMQ retry worker | SATISFIED | Entity, migration, orIgnore insert in guardedUnpin, PendingUnpinProcessor drain job |
| UNPIN-DRIFT | 42-06 | Periodic read-only drift report | SATISFIED | `runDriftReport` in PendingUnpinProcessor — read-only, no deletes |
| UNPIN-BACKFILL | 42-07 | One-shot non-BYO quota repair script | SATISFIED | `scripts/backfill-pinned-cids.ts` with BYO exclusion and dry-run |
| UNPIN-WEB | 42-02 | fetchQuota reconcile after removeUsage | SATISFIED | `delete.service.ts:22` |
| UNPIN-AUDIT | 42-01, 42-03, 42-08 | Warn log + Prometheus counter for cross-user attempts | SATISFIED | `unpinCrossUserAttempts.inc()` in guardedUnpin; Grafana alert in `unpin-cross-user-attempts.json` |

Note: both source todos (`2026-06-11-ipfs-unpin-missing-ownership-check.md` and `2026-06-11-server-quota-never-decremented-on-unpin.md`) remain in `.planning/todos/pending/` — they have not been moved to `done/`. This is a documentation gap (the todos were solved but not closed), not a code gap. The implementation fully satisfies both requirements.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| No unresolved TBD/FIXME/XXX markers found in any phase-modified file | — | — | — | — |

No stub patterns, placeholder returns, empty handlers, or debt markers were found in any of the 14 artifacts verified. All `return null`/`return {}` patterns that exist are in unrelated parts of the codebase, not in phase-modified code.

---

### Human Verification Required

#### 1. Live Database Schema Confirmation

**Test:** From `apps/api`, run:
```sql
SELECT
  to_regclass('public.pending_unpins') AS t,
  to_regclass('public.idx_pending_unpins_cid') AS uniq_idx,
  to_regclass('public.idx_pinned_cids_cid') AS refcount_idx;
```
Then run `\d pending_unpins` to confirm column shape.

**Expected:** All three identifiers resolve to non-null. `pending_unpins` has columns `id` (uuid PK), `cid` (varchar 255, unique), `created_at` (timestamp) and NO `user_id` column. `\d pinned_cids` lists `idx_pinned_cids_cid` among indexes.

**Why human:** Dev Postgres was not reachable from the verifier sandbox (connection refused). Plan 42-04 documented the migration run and its `to_regclass` output as confirmed, but independent live-DB verification is required to close the schema gate.

**Resolution (2026-06-12):** Orchestrator ran the query against the `cipherbox-postgres` container (`psql -U postgres -d cipherbox`):

- `to_regclass` returned `pending_unpins|idx_pending_unpins_cid|idx_pinned_cids_cid` (all non-null)
- `\d pending_unpins`: `id` uuid PK default `gen_random_uuid()`, `cid` varchar(255) NOT NULL with UNIQUE index `idx_pending_unpins_cid`, `created_at` timestamp NOT NULL default `now()`, no `user_id` column
- `pg_indexes` for `pinned_cids` lists `idx_pinned_cids_cid`

All expectations confirmed. Schema gate closed.

---

### Gaps Summary

No code gaps. All 8 observable truths are VERIFIED against the codebase. The live-DB confirmation that the two migrations applied by plan 42-04 are reflected in the physical schema was completed by the orchestrator on 2026-06-12 (see Resolution above) — this phase is `passed`.

The two source todos (`2026-06-11-ipfs-unpin-missing-ownership-check.md` and `2026-06-11-server-quota-never-decremented-on-unpin.md`) remain in `pending/` but the implementation fully satisfies them. They should be moved to `done/` as a cleanup step.

---

_Verified: 2026-06-12_
_Verifier: Claude (gsd-verifier)_
