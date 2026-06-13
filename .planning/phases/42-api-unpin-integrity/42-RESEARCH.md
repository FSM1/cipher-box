# Phase 42: API Unpin Integrity - Research

**Researched:** 2026-06-12
**Domain:** NestJS/TypeORM Postgres transaction safety, BullMQ outbox pattern, IPFS Kubo pin lifecycle, Prometheus/Grafana alert provisioning
**Confidence:** HIGH

---

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** No-row unpin returns silent `{success: true}`, touches nothing. Uniform for ALL no-row calls — never distinguish "CID unknown" from "CID owned by another user".
- **D-02:** Emit audit telemetry in the no-row case: warn log + Prometheus metric when CID exists under another user's row (abuse visibility). Benign races (CID unknown entirely) may be logged at lower severity or counted separately.
- **D-03:** Row first, Kubo best-effort: transactionally delete caller's `pinned_cids` row + compute refcount, commit, then attempt Kubo `pin/rm`.
- **D-04:** Close concurrent-delete refcount race with per-CID Postgres advisory xact lock on `hash(cid)`.
- **D-05:** Outbox pattern: when refcount hits zero, insert CID into `pending_unpins` in SAME transaction as row delete. After commit, attempt `pin/rm`; on success delete outbox row. BullMQ retry job (mirrors Phase 21 `pin-migration` queue) drains failures. Kubo "not pinned" = success everywhere.
- **D-06:** Drift report: read-only periodic job diffs Kubo `pin ls` against `pinned_cids ∪ pending_unpins`, reports unaccounted pins (metric + log). Never deletes.
- **D-07:** All `pinned_cids` rows count equally in refcount — no `origin` column. BYO over-retention is accepted and self-heals.
- **D-08:** External-only BYO deletes work for free under new semantics: row delete + quota decrement succeed, Kubo "not pinned" swallowed.
- **D-09:** One-shot backfill in scope: maintenance script diffs non-BYO `pinned_cids` rows against Kubo `pin ls`, deletes rows whose CID is no longer pinned. BYO users excluded entirely.
- **D-10:** No dedicated `@Throttle` on unpin — global `BypassableThrottlerGuard` stays. Add Grafana alert on cross-user-attempt audit metric (Phase 26 alerting patterns).
- **D-11:** `UnpinResponseDto` stays opaque `{success: true}` — no DTO change, no api-client churn.
- **D-12:** `apps/web/src/services/delete.service.ts`: keep instant local `removeUsage()` decrement, then fire `fetchQuota()` to reconcile with server.
- **D-13:** Upload/unpin race accepted + documented, not closed. Document window in code comments at compensation path.

### Claude's Discretion

- Exact metric names/labels for audit telemetry and drift report (follow `cipherbox_*` Prometheus conventions, Phase 18 patterns).
- `pending_unpins` table schema and BullMQ job naming/scheduling details.
- Backfill script vehicle (standalone script vs admin maintenance command) and batch sizing.
- Lower-severity handling of "CID unknown entirely" no-row calls vs the cross-user audit case.

### Deferred Ideas (OUT OF SCOPE)

- Wire `provider.unpin` into BYO client delete flows (external-only BYO pins on user's own node).
- Writable-share version-prune leak (`packages/sdk/src/share/shared-write.ts:450`).
- Upload/unpin race hardening (per-CID lock + pin verify in upload path) — revisit only if drift report shows row-but-no-pin occurrences.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID             | Description                                                                      | Research Support                                                                 |
| -------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| UNPIN-OWN      | Caller must own a `pinned_cids(userId, cid)` row before any Kubo unpin is issued | D-01: no-row = silent 2XX; D-04: advisory lock guards concurrent delete+refcount |
| UNPIN-REFCOUNT | Only issue global Kubo `pin/rm` when refcount across all users reaches zero      | D-04/D-05: lock + outbox ensures exactly-once Kubo call                          |
| UNPIN-QUOTA    | `recordUnpin` called on every successful row delete so quota sum decrements      | D-03: transactional row delete makes `recordUnpin` atomic with refcount          |
| UNPIN-OUTBOX   | `pending_unpins` outbox table retried by BullMQ worker for Kubo failures         | D-05: mirrors Phase 21 `pin-migration` queue pattern                             |
| UNPIN-DRIFT    | Periodic drift report job diffs Kubo vs DB, reports orphans, never GCs           | D-06: read-only, metric + log                                                    |
| UNPIN-BACKFILL | One-shot maintenance script repairs historical quota inflation for non-BYO users | D-09: standalone script, BYO excluded                                            |
| UNPIN-WEB      | `delete.service.ts` fires `fetchQuota()` after local `removeUsage()`             | D-12: pattern already used post-upload                                           |
| UNPIN-AUDIT    | Warn log + Prometheus counter when cross-user attempt detected                   | D-02/D-10: Grafana alert on new metric                                           |

</phase_requirements>

---

## Summary

This phase closes two critical security/correctness gaps in the unpin path. Currently `POST /ipfs/unpin` ignores `req.user` entirely, lets any authenticated user unpin any CID from the shared Kubo node (cross-tenant data destruction), and never calls `recordUnpin`, so `SUM(pinned_cids.size_bytes)` monotonically grows until the user locks themselves out.

The fix layers three concerns: (1) an ownership check via `pinned_cids(userId, cid)` row lookup before any Kubo call, (2) a reference-count gate that delays global Kubo `pin/rm` until no other user's row still references the CID, and (3) a transactional `recordUnpin` call that decrements quota atomically with the row delete. An outbox table (`pending_unpins`) + BullMQ retry job handles Kubo failures after the DB commit. A read-only drift report job provides ongoing visibility into orphaned pins.

The implementation touches four layers: `VaultService` gains the guarded unpin logic (transaction + advisory lock + outbox insert), `IpfsController.unpin` gains `req.user` and delegates to the service, `MetricsService` gains two new counters for audit/drift, and `apps/web/src/services/delete.service.ts` adds a `fetchQuota()` reconcile call after local decrement. Two TypeORM migrations are needed: one for `pending_unpins` and one for a `cid` index on `pinned_cids` (required by the refcount `WHERE cid = ?` query).

**Primary recommendation:** Implement all guarded logic in a new `VaultService.guardedUnpin()` method injected with `DataSource` for transaction management. Mirror the Phase 21 `pin-migration` BullMQ queue pattern exactly for the `pending-unpins` retry queue.

---

## Architectural Responsibility Map

| Capability               | Primary Tier                                    | Secondary Tier | Rationale                                                                        |
| ------------------------ | ----------------------------------------------- | -------------- | -------------------------------------------------------------------------------- |
| Ownership check          | API / Backend (`VaultService`)                  | —              | Requires DB row lookup against `pinned_cids`; client cannot be trusted           |
| Refcount + advisory lock | API / Backend (`VaultService` + Postgres)       | —              | Requires serialized DB transaction; Postgres advisory lock scoped to transaction |
| Outbox insert + commit   | API / Backend (`VaultService` transaction)      | —              | Must be atomic with row delete                                                   |
| Kubo `pin/rm` call       | API / Backend (`LocalProvider`)                 | —              | Server-side Kubo API call, already abstracted behind `IpfsProvider`              |
| Outbox retry worker      | API / Backend (BullMQ `PendingUnpinsProcessor`) | —              | Same process as other BullMQ workers; mirrors `MigrationProcessor`               |
| Drift report             | API / Backend (BullMQ repeating job)            | —              | Read-only Kubo + DB comparison; no client involvement                            |
| Quota audit telemetry    | API / Backend (`MetricsService`)                | —              | Prometheus counters, follows `cipherbox_*` convention                            |
| Grafana alert            | Ops (`docker/grafana/alerts/`)                  | —              | JSON alert file, provisioned via existing `provision-alerts.sh`                  |
| Backfill script          | API / Backend (standalone Node script)          | —              | One-shot, uses same `DataSource` config as `run-migrations.ts`                   |
| Web quota reconcile      | Browser / Client (`delete.service.ts`)          | —              | `fetchQuota()` already exists; one-liner addition                                |

---

## Standard Stack

### Core (no new packages — uses existing dependencies)

| Library          | Version           | Purpose                                                                                  | Why Standard                                                                                        |
| ---------------- | ----------------- | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `typeorm`        | already installed | Transaction manager, `DataSource.transaction()`, `queryRunner.query()` for advisory lock | Project ORM; `dataSource.transaction(manager => ...)` pattern established in `TeeKeyStateService`   |
| `@nestjs/bullmq` | already installed | `@Processor`, `WorkerHost`, `InjectQueue`, `upsertJobScheduler`                          | Phase 21 `MigrationProcessor` is the canonical pattern; `RepublishModule` shows repeating job setup |
| `prom-client`    | already installed | `Counter` for audit/drift metrics                                                        | `MetricsService` already owns all counters; add two new ones following `cipherbox_*` naming         |

### Supporting

No new npm packages needed. All required capabilities (Postgres transactions, BullMQ, Prometheus counters) are already in the dependency tree. [ASSUMED: prom-client, typeorm, @nestjs/bullmq versions — verified as already installed in the codebase]

### Alternatives Considered

| Instead of                               | Could Use                                  | Tradeoff                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pg_advisory_xact_lock(hash(cid))`       | SELECT FOR UPDATE on the `pinned_cids` row | Advisory lock avoids locking the actual row; with SELECT FOR UPDATE, two concurrent deletes on different users' rows for the same CID would not serialize (different row keys); advisory lock with a CID-derived key correctly serializes all concurrent deletes for a given CID regardless of which user's row |
| BullMQ outbox retry job                  | NestJS `@Cron`                             | BullMQ retry is already the established pattern (Phase 21); persistence across restarts via Redis; backpressure and concurrency control built in                                                                                                                                                                |
| `DataSource.transaction(manager => ...)` | `queryRunner` directly                     | `dataSource.transaction()` is cleaner; `TeeKeyStateService.rotateEpoch()` uses it; `manager.getRepository(Entity)` inside the callback gives transaction-scoped repos                                                                                                                                           |

**Installation:** No new installation needed.

---

## Package Legitimacy Audit

No new npm packages are introduced by this phase. All required libraries (`typeorm`, `@nestjs/bullmq`, `prom-client`) are already present in `apps/api/package.json`.

**Packages removed due to SLOP verdict:** none
**Packages flagged as suspicious SUS:** none

---

## Architecture Patterns

### System Architecture Diagram

```
POST /ipfs/unpin (req.user.id, dto.cid)
        |
        v
IpfsController.unpin()
        |
        v
VaultService.guardedUnpin(userId, cid)
        |
        +--> [1] pg_advisory_xact_lock(cid_hash) -----+
        |                                              |
        +--> [2] DELETE pinned_cids WHERE userId=?     |  (transaction)
        |         AND cid=?  →  rowDeleted?            |
        |                                              |
        |    if !rowDeleted → return (no-op path)      |
        |    check if cid exists under other userId    |
        |    if cross-user → warn log + counter        |
        |                                              |
        +--> [3] COUNT(*) pinned_cids WHERE cid=?      |
        |         refcount                             |
        |                                              |
        +--> [4] if refcount==0:                       |
        |         INSERT pending_unpins(cid, ...)      |
        |                                              |
        +--> [5] COMMIT  <-----------------------------+
        |
        +--> [6] attempt ipfsProvider.unpinFile(cid)  (post-commit, best-effort)
        |         if ok → DELETE pending_unpins WHERE cid=?
        |         if fail → leave for BullMQ retry worker
        |
        v
    {success: true}

BullMQ PendingUnpinsProcessor (repeating, e.g. every 5 min):
    SELECT * FROM pending_unpins ORDER BY created_at LIMIT batch
    FOR EACH row:
        attempt unpinFile(cid)
        if ok / "not pinned" → DELETE row
        else → leave (retry next run)

BullMQ DriftReportProcessor (repeating, e.g. every hour):
    Kubo pin/ls (stream full pin set)
    DB: SELECT DISTINCT cid FROM pinned_cids UNION SELECT cid FROM pending_unpins
    DIFF: kubo_pins - db_cids → unaccounted (report metric + warn log)
         db_cids - kubo_pins → orphaned rows (report metric + warn log)
         (never delete anything)
```

### Recommended Project Structure

New files for this phase:

```
apps/api/src/
├── ipfs/
│   └── pending-unpin/
│       ├── pending-unpin.entity.ts        # PendingUnpin entity
│       ├── pending-unpin.module.ts        # BullMQ queue + processor
│       └── pending-unpin.processor.ts    # WorkerHost retry + drift processors
├── migrations/
│   ├── 1749000000000-AddPendingUnpins.ts  # CREATE TABLE pending_unpins
│   └── 1749100000000-AddPinnedCidIndex.ts # CREATE INDEX idx_pinned_cids_cid ON pinned_cids(cid)
docker/
└── grafana/
    └── alerts/
        └── unpin-cross-user-attempts.json  # Grafana alert on cipherbox_unpin_cross_user_attempts_total
scripts/
└── backfill-pinned-cids.ts               # One-shot maintenance script
```

### Pattern 1: Postgres Advisory Xact Lock + Transaction

**What:** Obtain a per-CID advisory lock inside a TypeORM transaction, preventing concurrent deletes of the same CID from racing on the refcount.

**When to use:** Any time a delete + aggregate-count must be serialized across concurrent requests on the same logical key (CID) but the DB rows being deleted have different primary keys (different users).

**Example:**

```typescript
// Source: TeeKeyStateService.rotateEpoch() pattern — dataSource.transaction(manager => ...)
// Combined with Postgres advisory lock via raw SQL inside the transaction

async guardedUnpin(userId: string, cid: string): Promise<void> {
  await this.dataSource.transaction(async (manager) => {
    const pinnedCidRepo = manager.getRepository(PinnedCid);
    const pendingUnpinRepo = manager.getRepository(PendingUnpin);

    // Advisory xact lock on abs(hashtext(cid)) — released automatically at transaction end
    const hash = await manager.query(
      `SELECT abs(hashtext($1))::bigint AS h`, [cid]
    ) as [{ h: string }];
    await manager.query(`SELECT pg_advisory_xact_lock($1)`, [BigInt(hash[0].h)]);

    // Check caller ownership
    const row = await pinnedCidRepo.findOne({ where: { userId, cid } });
    if (!row) {
      // Determine if CID exists under another user (for audit telemetry)
      const otherRow = await pinnedCidRepo.findOne({ where: { cid } });
      if (otherRow) {
        this.logger.warn(`Cross-user unpin attempt: userId=${userId} cid=${cid}`);
        this.metricsService.unpinCrossUserAttempts.inc();
      }
      return; // Silent 2XX (D-01)
    }

    // Delete caller's row
    await pinnedCidRepo.delete({ userId, cid });

    // Check remaining refcount
    const result = await manager
      .createQueryBuilder(PinnedCid, 'pc')
      .select('COUNT(*)', 'count')
      .where('pc.cid = :cid', { cid })
      .getRawOne<{ count: string }>();

    const refcount = parseInt(result?.count ?? '0', 10);

    if (refcount === 0) {
      // Insert outbox row — same transaction, so atomic with row delete
      await pendingUnpinRepo
        .createQueryBuilder()
        .insert()
        .into(PendingUnpin)
        .values({ cid })
        .orIgnore()
        .execute();
    }
    // Transaction commits here — advisory lock released
  });

  // Post-commit: best-effort inline Kubo call (D-03 ordering)
  const pending = await this.pendingUnpinRepo.findOne({ where: { cid } });
  if (pending) {
    try {
      await this.ipfsProvider.unpinFile(cid);
      await this.pendingUnpinRepo.delete({ cid });
    } catch {
      // Leave in outbox for retry worker — not a request failure
    }
  }

  this.metricsService.fileUnpins.inc();
}
```

### Pattern 2: BullMQ Repeating Job (mirrors Phase 21 + RepublishModule)

**What:** Register a repeating BullMQ job in `onModuleInit` via `queue.upsertJobScheduler()`. Processor is `@Processor('pending-unpins')` extending `WorkerHost`.

**When to use:** Any background retry or periodic scan that must survive application restarts.

**Example:**

```typescript
// Source: apps/api/src/republish/republish.module.ts — upsertJobScheduler pattern
// Source: apps/api/src/migration/migration.processor.ts — WorkerHost pattern

// In PendingUnpinModule.onModuleInit():
await this.queue.upsertJobScheduler(
  'pending-unpins-drain',
  { pattern: '*/5 * * * *' }, // every 5 minutes
  { name: 'drain-pending-unpins' }
);

await this.queue.upsertJobScheduler(
  'pin-drift-report',
  { pattern: '0 * * * *' }, // every hour
  { name: 'drift-report' }
);

// PendingUnpinProcessor extends WorkerHost:
@Processor('pending-unpins')
export class PendingUnpinProcessor extends WorkerHost {
  async process(job: Job<Record<string, never>>): Promise<void> {
    if (job.name === 'drain-pending-unpins') {
      await this.drainPendingUnpins();
    } else if (job.name === 'drift-report') {
      await this.runDriftReport();
    }
  }
}
```

### Pattern 3: Grafana Alert JSON (mirrors Phase 26 format)

**What:** New JSON alert file in `docker/grafana/alerts/` provisioned via `provision-alerts.sh`. Follows exact format of existing alerts (`ipfs-pin-latency.json`).

**When to use:** Any new Prometheus counter that needs production visibility.

**Example:**

```json
// Source: docker/grafana/alerts/ipfs-pin-latency.json — structure to mirror
{
  "title": "Unpin Cross-User Attempt Rate",
  "ruleGroup": "CipherBox Security",
  "folderUID": "GRAFANA_ALERTS_FOLDER_UID",
  "noDataState": "OK",
  "execErrState": "OK",
  "for": "5m",
  "condition": "B",
  "annotations": {
    "summary": "Unpin cross-user attempts detected",
    "description": "cipherbox_unpin_cross_user_attempts_total rate > 0 — potential abuse of POST /ipfs/unpin with a CID owned by another user."
  },
  "labels": { "severity": "warning", "service": "cipherbox", "operation": "unpin-security" }
}
```

### Pattern 4: Migration File (mirrors AddPinMigrations pattern)

**What:** Two additive migrations using `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`.

**Timestamps to use:** Latest existing is `1743300000000`. Use `1749000000000` (AddPendingUnpins) and `1749100000000` (AddPinnedCidCidIndex) — well after existing migrations, before any future ones.

**Example:**

```typescript
// Source: apps/api/src/migrations/1742000000000-AddPinMigrations.ts — exact pattern to follow
export class AddPendingUnpins1749000000000 implements MigrationInterface {
  name = 'AddPendingUnpins1749000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS pending_unpins (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        cid VARCHAR(255) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `);
    // CID is the natural idempotency key — unique constraint prevents duplicate outbox rows
    await queryRunner.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_unpins_cid ON pending_unpins(cid)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS pending_unpins`);
  }
}
```

```typescript
// Second migration — add cid index to pinned_cids for refcount query performance
export class AddPinnedCidCidIndex1749100000000 implements MigrationInterface {
  name = 'AddPinnedCidCidIndex1749100000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS idx_pinned_cids_cid ON pinned_cids(cid)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP INDEX IF EXISTS idx_pinned_cids_cid`);
  }
}
```

### Anti-Patterns to Avoid

- **Calling `recordUnpin` outside the transaction:** If the transaction is committed but `recordUnpin` is called separately afterward, a crash between commit and `recordUnpin` produces a quota leak. The quota decrement must happen as part of the `pinnedCidRepo.delete()` inside the transaction (the delete IS the recordUnpin — `VaultService.recordUnpin` is just `pinnedCidRepository.delete({userId, cid})`; the guarded logic replaces it with an in-transaction delete).
- **Using SELECT FOR UPDATE to serialize concurrent deletes:** Different users' rows for the same CID have different primary keys; SELECT FOR UPDATE only locks the individual row, not the CID namespace. `pg_advisory_xact_lock(hash(cid))` is required to serialize all concurrent deletes for a given CID.
- **Issuing Kubo `pin/rm` inside the transaction:** Kubo is an external service; holding a DB transaction open while waiting for an HTTP call can exhaust the connection pool. Per D-03: commit first, then attempt Kubo.
- **Treating Kubo "not pinned" as an error:** `local.provider.ts:94` already handles this — `if (errorText.includes('not pinned')) { return; }`. The outbox worker must use the same provider method, not raw Kubo API calls, to get this behavior for free.
- **Leaving `IpfsModule` not importing `DataSource`:** `IpfsModule` is a dynamic module (`forRootAsync()`). If `guardedUnpin` moves to `VaultService`, `VaultModule` already registers the Postgres entities but does NOT currently inject `DataSource`. Follow `TeeKeyStateService` — inject `DataSource` via the constructor (TypeORM auto-provides it when registered in the module).
- **Not registering `PendingUnpin` entity in `app.module.ts`:** Every new `@Entity()` must be added to the `entities` array in `app.module.ts`. Missing this causes `relation "pending_unpins" does not exist` on startup (incident 9.1 in DATABASE_EVOLUTION_PROTOCOL.md).

---

## Don't Hand-Roll

| Problem                         | Don't Build                          | Use Instead                                        | Why                                                                                                                         |
| ------------------------------- | ------------------------------------ | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Per-CID serialization           | Custom in-memory lock or Redis SETNX | `pg_advisory_xact_lock` inside TypeORM transaction | Postgres advisory lock is scoped to the transaction lifecycle, releases on commit/rollback automatically, needs no cleanup  |
| Outbox retry backoff            | Custom retry loop with sleep         | BullMQ job scheduler with `pattern` cron           | BullMQ persists jobs across restarts, handles concurrency limits, retries natively; identical to existing `republish` queue |
| Kubo "not pinned" detection     | String parsing the HTTP body         | `LocalProvider.unpinFile()` already handles it     | Line 94 of `local.provider.ts` has the check; call the provider, not Kubo directly                                          |
| Prometheus counter registration | Custom metrics object                | Extend `MetricsService` constructor                | All counters live in `MetricsService`; adding there ensures consistent registry, default labels, and access across modules  |
| Grafana alert provisioning      | Manual Grafana UI                    | JSON file + `provision-alerts.sh`                  | All Phase 26 alerts follow this pattern; the script handles UID substitution                                                |

**Key insight:** The entire concurrency problem is solved by a two-line Postgres advisory lock. Everything else is plumbing wires.

---

## Common Pitfalls

### Pitfall 1: Refcount Window Without Advisory Lock

**What goes wrong:** Without `pg_advisory_xact_lock`, two concurrent users deleting the same deduped CID both read refcount=1 after deleting their own row, both see zero, both insert into `pending_unpins`, and Kubo receives two `pin/rm` calls. The second call hits "not pinned" (handled gracefully), but if two outbox rows exist, both workers retry unnecessarily.

**Why it happens:** TypeORM's default transaction isolation (`READ COMMITTED`) does not serialize the delete+count sequence across concurrent transactions on different rows.

**How to avoid:** Acquire `pg_advisory_xact_lock(abs(hashtext(cid))::bigint)` as the FIRST statement inside the transaction before the DELETE.

**Warning signs:** Duplicate rows in `pending_unpins` for the same CID; `cipherbox_unpin_cross_user_attempts_total` showing false positives where the second caller actually owned the CID.

### Pitfall 2: Advisory Lock Integer Overflow

**What goes wrong:** `hashtext(cid)` returns a Postgres `int4` (signed 32-bit). If passed directly as a `bigint` argument to `pg_advisory_xact_lock`, negative values cause `ERROR: bigint out of range` on some Postgres versions.

**Why it happens:** Postgres advisory lock functions take `bigint`. Negative `int4` values are valid `bigint` values, but TypeORM parameterization may coerce incorrectly.

**How to avoid:** Use `abs(hashtext($1))::bigint` in the raw SQL — ensures the lock key is always positive. Alternatively use `hashtext($1)::bigint` (which IS valid since int4 fits in bigint); the `abs()` is defensive.

**Warning signs:** Test with CIDs that produce negative `hashtext` values in unit tests.

### Pitfall 3: Missing Entity Registration

**What goes wrong:** `PendingUnpin` entity is created but not added to `app.module.ts` entities array — app starts, migration runs, but TypeORM can't build queries for the entity.

**Why it happens:** NestJS TypeORM module requires explicit entity registration in `TypeOrmModule.forRootAsync` AND `TypeOrmModule.forFeature([PendingUnpin])` in each module that uses it.

**How to avoid:** Follow DATABASE_EVOLUTION_PROTOCOL.md checklist §4.2 exactly: (1) entity file, (2) `app.module.ts` global entities array, (3) `TypeOrmModule.forFeature` in the using module.

**Warning signs:** `EntityMetadataNotFoundError` or `relation "pending_unpins" does not exist` on startup.

### Pitfall 4: DataSource Not Available in VaultModule

**What goes wrong:** `VaultService.guardedUnpin` needs `DataSource` for transactions, but `VaultModule` only injects repositories. Injecting `DataSource` without importing the TypeORM module at the root level causes DI resolution failure.

**Why it happens:** TypeORM's `DataSource` is provided at the module root. Nested modules get access only if they import `TypeOrmModule.forFeature(...)` — that implicitly makes `DataSource` injectable in the same module context.

**How to avoid:** Add `DataSource` to `VaultService` constructor injection. `VaultModule` already imports `TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User])`, so `DataSource` will be available via NestJS DI. Pattern confirmed in `TeeKeyStateService` (same structure).

**Warning signs:** `Nest can't resolve dependencies of VaultService` at startup — DI error naming `DataSource`.

### Pitfall 5: `pending_unpins` Unique Constraint Race

**What goes wrong:** Two transactions both delete different users' rows for the same CID, both compute refcount=0, both try to INSERT into `pending_unpins` with the same CID — the second insert fails with a unique constraint violation.

**Why it happens:** Even with the advisory lock, if the lock hash collides (unlikely but possible) or the advisory lock is not the first statement.

**How to avoid:** Use `.orIgnore()` on the `pending_unpins` insert (same as `recordPin` uses for `pinned_cids`). The unique constraint on `cid` ensures at most one row exists; the ignore clause makes the second insert a no-op.

**Warning signs:** `duplicate key value violates unique constraint "idx_pending_unpins_cid"` in error logs.

### Pitfall 6: Kubo `pin/ls` Streaming for Drift Report

**What goes wrong:** Kubo `pin/ls` with no `arg` parameter returns ALL pins as a streaming newline-delimited JSON response (not a single JSON object). Attempting to parse it as a single `response.json()` call fails with a JSON parse error.

**Why it happens:** Kubo's HTTP API returns NDJSON (newline-delimited JSON) for list endpoints.

**How to avoid:** Read the response as text, split on newlines, parse each line independently. Or use the `stream=true` query param and read chunks. The drift report doesn't need to be real-time, so batch reading is fine.

**Warning signs:** `SyntaxError: Unexpected token` when parsing `pin/ls` response.

---

## Code Examples

### Advisory Lock + Transaction (exact TypeORM idiom)

```typescript
// Source: apps/api/src/tee/tee-key-state.service.ts:85 — dataSource.transaction pattern
// Combined with pg_advisory_xact_lock raw SQL

await this.dataSource.transaction(async (manager) => {
  // 1. Acquire per-CID advisory lock (released automatically on commit/rollback)
  const [{ h }] = (await manager.query(`SELECT abs(hashtext($1))::bigint AS h`, [cid])) as [
    { h: string },
  ];
  await manager.query(`SELECT pg_advisory_xact_lock($1)`, [h]);

  // 2. Use transaction-scoped repository
  const repo = manager.getRepository(PinnedCid);
  // ... delete, count, insert outbox
});
```

### BullMQ Repeating Job Registration

```typescript
// Source: apps/api/src/republish/republish.module.ts:34
await this.queue.upsertJobScheduler(
  'pending-unpins-drain', // scheduler id (idempotent)
  { pattern: '*/5 * * * *' }, // every 5 minutes
  { name: 'drain-pending-unpins' } // job name matched in processor
);
```

### BullMQ Processor (WorkerHost)

```typescript
// Source: apps/api/src/migration/migration.processor.ts
@Processor('pending-unpins')
export class PendingUnpinProcessor extends WorkerHost {
  async process(job: Job<Record<string, never>>): Promise<void> {
    // job.name dispatch
  }
}
```

### Kubo pin/ls NDJSON Parsing (drift report)

```typescript
// [ASSUMED] Kubo pin/ls returns NDJSON; parse line-by-line
const response = await fetch(`${this.apiUrl}/api/v0/pin/ls?type=recursive`, { method: 'POST' });
const text = await response.text();
const pins = new Set<string>();
for (const line of text.split('\n').filter(Boolean)) {
  const obj = JSON.parse(line) as { Keys?: Record<string, unknown> };
  if (obj.Keys) {
    for (const cid of Object.keys(obj.Keys)) pins.add(cid);
  }
}
```

### Web Quota Reconcile (D-12)

```typescript
// Source: apps/web/src/services/delete.service.ts
// Add after removeUsage():
const quotaStore = useQuotaStore.getState();
quotaStore.removeUsage(sizeBytes);
quotaStore.fetchQuota().catch((err) => logger.warn('quota reconcile failed', err));
```

### Metrics Counter Addition

```typescript
// Source: apps/api/src/metrics/metrics.service.ts — add to constructor
this.unpinCrossUserAttempts = new client.Counter({
  name: 'cipherbox_unpin_cross_user_attempts_total',
  help: 'Unpin requests where the CID exists but belongs to another user',
  registers: [this.registry],
});

this.pendingUnpinsTotal = new client.Gauge({
  name: 'cipherbox_pending_unpins_total',
  help: 'CIDs in the pending_unpins outbox awaiting Kubo pin/rm',
  registers: [this.registry],
});

this.driftOrphanedPins = new client.Counter({
  name: 'cipherbox_drift_orphaned_pins_total',
  help: 'Kubo pins not tracked in pinned_cids or pending_unpins (drift report)',
  registers: [this.registry],
});
```

---

## State of the Art

| Old Approach               | Current Approach                                        | When Changed      | Impact                                                                                                                                |
| -------------------------- | ------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `BullMQ.addRepeatableJob`  | `queue.upsertJobScheduler`                              | BullMQ v5         | `addRepeatableJob` is deprecated; `upsertJobScheduler` is idempotent and the current API — confirmed in `republish.module.ts` line 34 |
| `synchronize: true` in dev | `synchronize: false` everywhere + `migrationsRun: true` | Phase 14 incident | Missing migrations now surface immediately in dev/test                                                                                |

**Deprecated/outdated:**

- `addRepeatableJob`: replaced by `upsertJobScheduler` in BullMQ v5+ (codebase already uses v5.67.3).
- `QueueScheduler` (BullMQ v1-3): removed in v4+; no longer needed with the `upsertJobScheduler` API.

---

## Assumptions Log

| #   | Claim                                                                                                                                | Section                      | Risk if Wrong                                                                                                       |
| --- | ------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| A1  | Kubo `pin/ls` returns NDJSON (newline-delimited JSON), not a single JSON object                                                      | Code Examples (drift report) | Drift report parsing fails; need to adapt to actual Kubo response format                                            |
| A2  | `abs(hashtext($1))::bigint` produces a stable non-colliding lock key for CID strings at realistic scale                              | Pattern 1 / Pitfall 2        | Lock collisions would allow concurrent deletes on different CIDs to block each other (performance, not correctness) |
| A3  | `prom-client` Counter/Gauge instantiation in `MetricsService` constructor is the correct extension point (no factory pattern needed) | Code Examples                | Additional setup needed if MetricsService uses a factory — unlikely given current pattern                           |
| A4  | `IpfsProvider` will be accessible in the pending-unpin processor via DI through the `IpfsModule` export                              | Architecture Patterns        | Module wiring may need adjustment if `IPFS_PROVIDER` token isn't exported                                           |

---

## Open Questions (RESOLVED)

1. **`pending_unpins` FK to `users`?**
   - What we know: `pin_migrations` has no FK to `users` (uses `user_id varchar`-equivalent). `pinned_cids` does have `ON DELETE CASCADE`.
   - What's unclear: Should `pending_unpins` have a `user_id` column at all? D-05 only stores the CID (the last user deleted their row, so user context is no longer relevant for the physical Kubo call).
   - Recommendation: No `user_id` column in `pending_unpins` — the table is a pure Kubo work queue, not user-scoped. This simplifies schema and avoids FK concerns.

2. **Backfill script vehicle**
   - What we know: The codebase has `scripts/` (shell + TS) and `run-migrations.ts` (standalone TypeORM DataSource). No existing admin maintenance endpoint pattern found.
   - What's unclear: Standalone `.ts` script (like `run-migrations.ts`) vs NestJS admin controller endpoint.
   - Recommendation: Standalone TS script at `scripts/backfill-pinned-cids.ts` following `run-migrations.ts` pattern — creates a `DataSource`, runs the backfill, exits. Does not need to be in the running app; easier to run ad-hoc via `ts-node`.

3. **Drift report Kubo `pin/ls` pagination**
   - What we know: Kubo `pin/ls` returns all pins; at scale this could be a large response.
   - What's unclear: Does Kubo support cursor pagination for `pin/ls`?
   - Recommendation: Treat as a full stream for now (drift report is hourly and for ops visibility only). Add pagination if production pin count grows large — not a correctness concern.

---

## Environment Availability

| Dependency | Required By                   | Available                                            | Version                    | Fallback                                                     |
| ---------- | ----------------------------- | ---------------------------------------------------- | -------------------------- | ------------------------------------------------------------ |
| PostgreSQL | Advisory lock, migrations     | Already used by the app                              | 15+ (required by protocol) | —                                                            |
| Redis      | BullMQ `pending-unpins` queue | Already used by `pin-migration` + `republish` queues | any                        | Warn and skip (non-fatal, per `republish.module.ts` pattern) |
| Kubo API   | `pin/rm`, `pin/ls`            | Already used by `LocalProvider`                      | v0.40+                     | "not pinned" errors swallowed; drift report skips gracefully |

**Missing dependencies with no fallback:** None.

---

## Validation Architecture

### Test Framework

| Property           | Value                                                                                         |
| ------------------ | --------------------------------------------------------------------------------------------- |
| Framework          | Jest (configured in `apps/api/package.json`)                                                  |
| Config file        | `apps/api/jest.config.js` (implied by `"test": "jest --passWithNoTests"`)                     |
| Quick run command  | `pnpm --filter api test -- --testPathPattern="ipfs.controller\|vault.service\|pending-unpin"` |
| Full suite command | `pnpm --filter api test`                                                                      |

### Phase Requirements to Test Map

| Req ID         | Behavior                                                                      | Test Type              | Automated Command                                               | File Exists?                              |
| -------------- | ----------------------------------------------------------------------------- | ---------------------- | --------------------------------------------------------------- | ----------------------------------------- |
| UNPIN-OWN      | No-row call returns `{success: true}` and calls no Kubo                       | unit                   | `pnpm --filter api test -- --testPathPattern="ipfs.controller"` | Extend existing `ipfs.controller.spec.ts` |
| UNPIN-OWN      | Cross-user attempt: warn log + counter, no Kubo, `{success: true}`            | unit                   | same                                                            | Extend `ipfs.controller.spec.ts`          |
| UNPIN-REFCOUNT | refcount > 0 after delete: Kubo NOT called, no outbox row                     | unit                   | `pnpm --filter api test -- --testPathPattern="vault.service"`   | New cases in `vault.service.spec.ts`      |
| UNPIN-REFCOUNT | refcount == 0 after delete: outbox row inserted                               | unit                   | same                                                            | New cases in `vault.service.spec.ts`      |
| UNPIN-QUOTA    | `pinnedCidRepo.delete` called inside transaction on owned row                 | unit                   | same                                                            | New cases in `vault.service.spec.ts`      |
| UNPIN-OUTBOX   | Inline Kubo success deletes outbox row                                        | unit                   | `pnpm --filter api test -- --testPathPattern="pending-unpin"`   | New `pending-unpin.processor.spec.ts`     |
| UNPIN-OUTBOX   | Inline Kubo failure leaves outbox row for worker                              | unit                   | same                                                            | New spec                                  |
| UNPIN-OUTBOX   | Worker retry: "not pinned" counted as success                                 | unit                   | same                                                            | New spec                                  |
| UNPIN-OUTBOX   | Worker retry: Kubo failure leaves row for next run                            | unit                   | same                                                            | New spec                                  |
| UNPIN-DRIFT    | Drift report logs/counts orphaned pins, never deletes                         | unit                   | same                                                            | New spec                                  |
| UNPIN-BACKFILL | Backfill skips BYO users, deletes orphan rows for non-BYO                     | unit                   | `ts-node scripts/backfill-pinned-cids.ts --dry-run` (manual)    | New script                                |
| UNPIN-WEB      | `fetchQuota()` called after `removeUsage()`                                   | unit                   | `pnpm --filter web test -- --testPathPattern="delete.service"`  | New or extend web spec                    |
| UNPIN-AUDIT    | Counter `cipherbox_unpin_cross_user_attempts_total` defined in MetricsService | unit                   | `pnpm --filter api test -- --testPathPattern="metrics"`         | Extend or new                             |
| D-04           | Advisory lock SQL issued first in transaction                                 | unit (mock DataSource) | `pnpm --filter api test -- --testPathPattern="vault.service"`   | New cases                                 |

### Sampling Rate

- **Per task commit:** `pnpm --filter api test -- --testPathPattern="ipfs.controller|vault.service|pending-unpin"`
- **Per wave merge:** `pnpm --filter api test`
- **Phase gate:** `pnpm --filter api test && pnpm --filter web test` — full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` — covers UNPIN-OUTBOX, UNPIN-DRIFT (new file)
- [ ] Extend `apps/api/src/ipfs/ipfs.controller.spec.ts` — add `req.user` to `unpin()` mock setup; add no-row and cross-user cases
- [ ] Extend `apps/api/src/vault/vault.service.spec.ts` — add `DataSource` mock; add guardedUnpin cases
- [ ] `apps/web/src/services/delete.service.spec.ts` — add fetchQuota reconcile assertion (new file or existing)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category         | Applies        | Standard Control                                                                                          |
| --------------------- | -------------- | --------------------------------------------------------------------------------------------------------- |
| V2 Authentication     | yes (indirect) | `JwtAuthGuard` already on `IpfsController`; this phase adds `req.user.id` usage                           |
| V3 Session Management | no             | —                                                                                                         |
| V4 Access Control     | yes            | Ownership check: caller must own `pinned_cids(userId, cid)` row; silent 2XX for non-owned prevents oracle |
| V5 Input Validation   | yes (existing) | `UnpinDto` uses `@IsString @IsNotEmpty`; no change needed                                                 |
| V6 Cryptography       | no             | —                                                                                                         |

### Known Threat Patterns for this Stack

| Pattern                                                          | STRIDE                 | Standard Mitigation                                                                          |
| ---------------------------------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------- |
| Cross-tenant data destruction via CID knowledge                  | Tampering              | Ownership check on `pinned_cids(userId, cid)` before any Kubo call                           |
| CID existence oracle (distinguish "not mine" vs "doesn't exist") | Information Disclosure | D-01: uniform silent 2XX for all no-row cases                                                |
| Concurrent delete race allowing double-unpin                     | Tampering              | D-04: `pg_advisory_xact_lock(hash(cid))` serializes all concurrent deletes for a given CID   |
| Quota inflation via failed deletes                               | Denial of Service      | D-03/D-05: transactional row delete + outbox ensures quota decrements atomically             |
| Abuse probe via bulk unpin of foreign CIDs                       | Denial of Service      | D-10: global throttler (~10/s); Grafana alert on `cipherbox_unpin_cross_user_attempts_total` |

---

## Project Constraints (from CLAUDE.md)

- **`pnpm api:generate` required** after touching any controller, DTO, or entity that affects the OpenAPI spec. D-11 says `UnpinResponseDto` stays unchanged, so the only concern is the new `IpfsController.unpin()` signature adding `@Request()`. The pre-commit hook (`scripts/check-api-client.sh`) enforces that the generated client is staged alongside API changes. Plans must include a `pnpm api:generate` step after controller changes.
- **TypeScript string literals over enums:** `pending_unpins` has no status column (pure work queue), so no enum needed. If a `status` field is added, use string literals (`'pending' | 'done'` style), not `enum Status`.
- **`Uint8Array` for binary data:** Not applicable here — CIDs are strings.
- **camelCase API fields, snake_case DB columns:** All new entity fields must follow this convention (e.g., `created_at` column, `createdAt` property).
- **Never log sensitive keys:** Audit log messages must not include user private keys or encrypted content; CID + userId in warn logs is acceptable.
- **Security rule: server never has plaintext keys:** The guarded unpin path operates entirely on CIDs (public identifiers) and `pinned_cids` row presence — no key material involved. Zero-knowledge constraint is preserved.

---

## Sources

### Primary (HIGH confidence)

- `apps/api/src/ipfs/ipfs.controller.ts` — verified current unpin handler; confirmed `req.user` not used
- `apps/api/src/vault/vault.service.ts` — verified `recordUnpin` exists with zero callers; `recordPin` orIgnore pattern
- `apps/api/src/vault/entities/pinned-cid.entity.ts` — verified `@Unique(['userId', 'cid'])`, index on `userId` only (no `cid` index)
- `apps/api/src/ipfs/providers/local.provider.ts` — verified "not pinned" detection at line 94
- `apps/api/src/migration/migration.processor.ts` + `migration.module.ts` — BullMQ `WorkerHost` + queue registration pattern
- `apps/api/src/republish/republish.module.ts` — `upsertJobScheduler` repeating job pattern (BullMQ v5)
- `apps/api/src/tee/tee-key-state.service.ts` — `dataSource.transaction(manager => ...)` pattern
- `apps/api/src/metrics/metrics.service.ts` — `cipherbox_*` counter convention, `@Global()` module
- `apps/api/src/migrations/1742000000000-AddPinMigrations.ts` — migration DDL template
- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — migration naming, timestamp rules, checklist
- `docker/grafana/alerts/ipfs-pin-latency.json` — Grafana alert JSON format
- `apps/web/src/services/delete.service.ts` — current delete flow (no fetchQuota)
- `apps/web/src/stores/quota.store.ts` — `fetchQuota()` and `removeUsage()` implementations

### Secondary (MEDIUM confidence)

- `apps/api/src/ipfs/ipfs.controller.spec.ts` — existing test structure and mock patterns
- `apps/api/src/vault/vault.service.spec.ts` — existing test structure, `mockQueryBuilder` pattern, `DataSource` mock not yet present

### Tertiary (LOW confidence)

- Kubo NDJSON format for `pin/ls` — [ASSUMED] based on training knowledge of Kubo HTTP API behavior; verify by testing against local Kubo during implementation

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all libraries are already in the codebase; patterns verified from existing source files
- Architecture: HIGH — core pattern (`dataSource.transaction` + advisory lock) verified from `TeeKeyStateService`; BullMQ pattern verified from `MigrationProcessor` + `RepublishModule`
- Migration discipline: HIGH — verified from `DATABASE_EVOLUTION_PROTOCOL.md` and existing migration files
- Pitfalls: HIGH — based on direct codebase inspection; advisory lock integer overflow and NDJSON parsing are the two subtle ones
- Kubo `pin/ls` NDJSON format: LOW — [ASSUMED]; verify during implementation

**Research date:** 2026-06-12
**Valid until:** 2026-07-12 (stable domain; only stale if BullMQ or TypeORM major version changes)
