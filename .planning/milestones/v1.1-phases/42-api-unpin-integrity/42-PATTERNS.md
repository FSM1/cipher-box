# Phase 42: API Unpin Integrity - Pattern Map

**Mapped:** 2026-06-12
**Files analyzed:** 10
**Analogs found:** 10 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `apps/api/src/ipfs/ipfs.controller.ts` | controller | request-response | `apps/api/src/ipfs/ipfs.controller.ts` (existing, modified) | exact |
| `apps/api/src/vault/vault.service.ts` | service | CRUD + transaction | `apps/api/src/tee/tee-key-state.service.ts` | exact |
| `apps/api/src/vault/entities/pending-unpin.entity.ts` | model | CRUD | `apps/api/src/migration/migration.entity.ts` | role-match |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` | module | event-driven | `apps/api/src/republish/republish.module.ts` | exact |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` | service | event-driven + batch | `apps/api/src/migration/migration.processor.ts` | exact |
| `apps/api/src/migrations/1749000000000-AddPendingUnpins.ts` | migration | — | `apps/api/src/migrations/1742000000000-AddPinMigrations.ts` | exact |
| `apps/api/src/migrations/1749100000000-AddPinnedCidCidIndex.ts` | migration | — | `apps/api/src/migrations/1742000000000-AddPinMigrations.ts` | exact |
| `apps/api/src/metrics/metrics.service.ts` | service | — | `apps/api/src/metrics/metrics.service.ts` (existing, modified) | exact |
| `docker/grafana/alerts/unpin-cross-user-attempts.json` | config | — | `docker/grafana/alerts/ipfs-pin-latency.json` | exact |
| `scripts/backfill-pinned-cids.ts` | utility | batch | `apps/api/src/run-migrations.ts` | role-match |
| `apps/web/src/services/delete.service.ts` | service | request-response | `apps/web/src/services/delete.service.ts` (existing, modified) | exact |

---

## Pattern Assignments

### `apps/api/src/ipfs/ipfs.controller.ts` (controller, request-response) — modified

**Analog:** `apps/api/src/ipfs/ipfs.controller.ts` lines 130-148 (current `unpin` handler)

**Current unpin handler** (lines 144-148) — replace entirely:

```typescript
async unpin(@Body() dto: UnpinDto): Promise<UnpinResponseDto> {
  await this.ipfsProvider.unpinFile(dto.cid);
  this.metricsService.fileUnpins.inc();
  return { success: true };
}
```

**New handler — copy `@Request()` injection from `upload` handler** (lines 94-96):

```typescript
async upload(
  @Request() req: RequestWithUser,
  @UploadedFile(...) file: Express.Multer.File
): Promise<UploadResponseDto> {
```

**New `unpin` signature** — delegate to `VaultService.guardedUnpin`, remove direct `ipfsProvider` call:

```typescript
async unpin(
  @Request() req: RequestWithUser,
  @Body() dto: UnpinDto
): Promise<UnpinResponseDto> {
  await this.vaultService.guardedUnpin(req.user.id, dto.cid);
  return { success: true };
}
```

**Upload compensation path** (lines 119-123) — replace `this.ipfsProvider.unpinFile(result.cid)` with the same guarded call to avoid the compensation path bypassing ownership:

```typescript
try {
  await this.vaultService.recordPin(req.user.id, result.cid, result.size);
} catch (err) {
  // RACE WINDOW NOTE (D-13): a concurrent deleter of the same deduped CID could
  // have refcounted to zero between the Kubo pin above and recordPin here,
  // leaving this uploader with a row-but-no-pin. Cryptographically negligible
  // (requires identical ciphertext + sub-second window). Drift report detects.
  await this.vaultService.guardedUnpin(req.user.id, result.cid).catch(() => undefined);
  throw err;
}
```

**Imports to add:** `DataSource` is NOT needed in controller. `VaultService` already injected (line 39).

---

### `apps/api/src/vault/vault.service.ts` — new `guardedUnpin` method

**Analog:** `apps/api/src/tee/tee-key-state.service.ts`

**Constructor injection pattern** (lines 14-23 of tee-key-state.service.ts) — add `DataSource` to `VaultService`:

```typescript
import { DataSource, Repository } from 'typeorm';

constructor(
  // ... existing @InjectRepository injections ...
  private readonly dataSource: DataSource
) {}
```

`VaultModule` already imports `TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User])`, so `DataSource` is available in this module context without extra wiring.

**Transaction pattern** (lines 85-120 of tee-key-state.service.ts):

```typescript
return this.dataSource.transaction(async (manager) => {
  const keyStateRepo = manager.getRepository(TeeKeyState);
  const rotationLogRepo = manager.getRepository(TeeKeyRotationLog);
  // ... operations using transaction-scoped repos
});
```

**orIgnore upsert pattern** (vault.service.ts lines 207-218) — mirror for `pending_unpins` insert:

```typescript
await this.pinnedCidRepository
  .createQueryBuilder()
  .insert()
  .into(PinnedCid)
  .values({ userId, cid, sizeBytes: sizeBytes.toString() })
  .orIgnore()
  .execute();
```

**Raw query pattern** (vault.service.ts lines 164-169) — for refcount and advisory lock:

```typescript
const result = await this.pinnedCidRepository
  .createQueryBuilder('pin')
  .select('COALESCE(SUM(pin.size_bytes), 0)', 'total')
  .where('pin.user_id = :userId', { userId })
  .getRawOne<{ total: string }>();
const usedBytes = parseInt(result?.total ?? '0', 10);
```

**`guardedUnpin` full structure** (use these exact patterns together):

```typescript
async guardedUnpin(userId: string, cid: string): Promise<void> {
  let outboxRowInserted = false;

  await this.dataSource.transaction(async (manager) => {
    const pinnedCidRepo = manager.getRepository(PinnedCid);
    const pendingUnpinRepo = manager.getRepository(PendingUnpin);

    // 1. Advisory xact lock — MUST be first statement (D-04)
    const [{ h }] = (await manager.query(
      `SELECT abs(hashtext($1))::bigint AS h`, [cid]
    )) as [{ h: string }];
    await manager.query(`SELECT pg_advisory_xact_lock($1)`, [h]);

    // 2. Ownership check (D-01)
    const row = await pinnedCidRepo.findOne({ where: { userId, cid } });
    if (!row) {
      const otherRow = await pinnedCidRepo.findOne({ where: { cid } });
      if (otherRow) {
        this.logger.warn(`Cross-user unpin attempt userId=${userId} cid=${cid}`);
        this.metricsService.unpinCrossUserAttempts.inc();
      }
      return; // silent 2XX (D-01)
    }

    // 3. Delete caller's row — this IS the recordUnpin (D-03)
    await pinnedCidRepo.delete({ userId, cid });

    // 4. Refcount (D-05)
    const result = await manager
      .createQueryBuilder(PinnedCid, 'pc')
      .select('COUNT(*)', 'count')
      .where('pc.cid = :cid', { cid })
      .getRawOne<{ count: string }>();
    const refcount = parseInt(result?.count ?? '0', 10);

    if (refcount === 0) {
      await pendingUnpinRepo
        .createQueryBuilder()
        .insert()
        .into(PendingUnpin)
        .values({ cid })
        .orIgnore() // unique constraint on cid — concurrent insert is no-op
        .execute();
      outboxRowInserted = true;
    }
    // Transaction commits; advisory lock released automatically
  });

  // 5. Post-commit best-effort Kubo call (D-03 ordering: never inside transaction)
  if (outboxRowInserted) {
    try {
      await this.ipfsProvider.unpinFile(cid);
      await this.pendingUnpinRepository.delete({ cid });
    } catch {
      // Leave for BullMQ retry worker — not a request failure
    }
  }

  this.metricsService.fileUnpins.inc();
}
```

---

### `apps/api/src/vault/entities/pending-unpin.entity.ts` (model, CRUD) — new

**Analog:** `apps/api/src/migration/migration.entity.ts`

**Entity structure pattern** (migration.entity.ts lines 1-56):

```typescript
import {
  Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index,
} from 'typeorm';

@Entity('pin_migrations')
export class PinMigration {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;
  // ...
  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
```

**`PendingUnpin` entity** — minimal (no userId column per D-05: pure Kubo work queue):

```typescript
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm';

@Entity('pending_unpins')
export class PendingUnpin {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true }) // matches idx_pending_unpins_cid in migration
  @Column({ type: 'varchar', length: 255 })
  cid!: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
```

Note: Register in `app.module.ts` entities array AND `TypeOrmModule.forFeature` in the using module (DATABASE_EVOLUTION_PROTOCOL.md §4.2).

---

### `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` (module, event-driven) — new

**Analog:** `apps/api/src/republish/republish.module.ts`

**Full module pattern** (republish.module.ts lines 1-50):

```typescript
import { Module, Logger, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Queue } from 'bullmq';

@Module({
  imports: [
    BullModule.registerQueue({ name: 'republish' }),
    TypeOrmModule.forFeature([IpnsRepublishSchedule, FolderIpns]),
    // ...
  ],
  providers: [RepublishService, RepublishProcessor],
})
export class RepublishModule implements OnModuleInit {
  constructor(@InjectQueue('republish') private readonly queue: Queue) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.queue.upsertJobScheduler(
        'republish-cron',
        { pattern: '0 */6 * * *' },
        { name: 'republish-batch' }
      );
      this.logger.log('Republish cron scheduler registered: every 6 hours (0 */6 * * *)');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Failed to register republish cron scheduler (non-fatal): ${message}`);
    }
  }
}
```

**`PendingUnpinModule` pattern** — two schedulers (drain + drift), wrap in same try/catch non-fatal pattern:

```typescript
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
```

---

### `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` (service, event-driven + batch) — new

**Analog:** `apps/api/src/migration/migration.processor.ts`

**WorkerHost pattern** (migration.processor.ts lines 1-30):

```typescript
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Job } from 'bullmq';

const BATCH_SIZE = 10;

@Processor('pin-migration')
export class MigrationProcessor extends WorkerHost {
  private readonly logger = new Logger(MigrationProcessor.name);

  constructor(
    @InjectRepository(PinMigration)
    private readonly migrationRepo: Repository<PinMigration>,
    // ...
  ) {
    super();
  }

  async process(job: Job<{ migrationId: string }>): Promise<void> {
    // job dispatch
  }
}
```

**Batch iteration + error isolation pattern** (migration.processor.ts lines 56-119):

```typescript
for (let i = 0; i < pinnedCids.length; i += BATCH_SIZE) {
  const batch = pinnedCids.slice(i, i + BATCH_SIZE);
  try {
    // ... process batch
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    this.logger.error(`Batch error at offset ${i}: ${message}`);
    // leave rows for next run
  }
}
```

**`PendingUnpinProcessor.process` dispatch** (matches two job names from module):

```typescript
async process(job: Job<Record<string, never>>): Promise<void> {
  if (job.name === 'drain-pending-unpins') {
    await this.drainPendingUnpins();
  } else if (job.name === 'drift-report') {
    await this.runDriftReport();
  }
}
```

**`LocalProvider.unpinFile` handles "not pinned"** — the processor must call the provider (which swallows "not pinned" at `local.provider.ts:94`), not raw Kubo. Both drain and drift handlers must inject `IpfsProvider` via `@Inject(IPFS_PROVIDER)`.

---

### `apps/api/src/migrations/1749000000000-AddPendingUnpins.ts` and `1749100000000-AddPinnedCidCidIndex.ts` — new

**Analog:** `apps/api/src/migrations/1742000000000-AddPinMigrations.ts`

**Migration structure** (AddPinMigrations1742000000000, lines 1-29):

```typescript
import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddPinMigrations1742000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS pin_migrations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        // ...
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `);
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS idx_pin_migrations_user_id ON pin_migrations(user_id)`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS pin_migrations`);
  }
}
```

**`AddPendingUnpins1749000000000`** — class name must match `name` property exactly (DATABASE_EVOLUTION_PROTOCOL.md):

```typescript
export class AddPendingUnpins1749000000000 implements MigrationInterface {
  name = 'AddPendingUnpins1749000000000';
  // CREATE TABLE pending_unpins + CREATE UNIQUE INDEX idx_pending_unpins_cid
}

export class AddPinnedCidCidIndex1749100000000 implements MigrationInterface {
  name = 'AddPinnedCidCidIndex1749100000000';
  // CREATE INDEX IF NOT EXISTS idx_pinned_cids_cid ON pinned_cids(cid)
}
```

---

### `apps/api/src/metrics/metrics.service.ts` — modified, add 3 metrics

**Analog:** `apps/api/src/metrics/metrics.service.ts` lines 96-120 (existing Counter block)

**Counter declaration pattern** (lines 96-101):

```typescript
this.fileUploads = new client.Counter({
  name: 'cipherbox_file_uploads_total',
  help: 'Total file uploads',
  registers: [this.registry],
});
```

**Gauge with no labels pattern** (lines 64-69):

```typescript
this.usersTotal = new client.Gauge({
  name: 'cipherbox_users_total',
  help: 'Total registered users',
  registers: [this.registry],
});
```

**Three new metrics to add** — add to constructor after existing counters (after line 167, before Histograms section):

```typescript
// --- Counters (unpin audit) ---
this.unpinCrossUserAttempts = new client.Counter({
  name: 'cipherbox_unpin_cross_user_attempts_total',
  help: 'Unpin requests where the CID exists but belongs to another user',
  registers: [this.registry],
});

this.driftOrphanedPinsTotal = new client.Counter({
  name: 'cipherbox_drift_orphaned_pins_total',
  help: 'Kubo pins not tracked in pinned_cids or pending_unpins (drift report)',
  registers: [this.registry],
});

// --- Gauges (unpin outbox) ---
this.pendingUnpinsGauge = new client.Gauge({
  name: 'cipherbox_pending_unpins_total',
  help: 'CIDs in the pending_unpins outbox awaiting Kubo pin/rm',
  registers: [this.registry],
});
```

Add corresponding `readonly` field declarations at top of class (lines 28-43 pattern):

```typescript
readonly unpinCrossUserAttempts: client.Counter;
readonly driftOrphanedPinsTotal: client.Counter;
readonly pendingUnpinsGauge: client.Gauge;
```

---

### `docker/grafana/alerts/unpin-cross-user-attempts.json` — new

**Analog:** `docker/grafana/alerts/ipfs-pin-latency.json`

**Full alert structure** (ipfs-pin-latency.json lines 1-104) — array wrapper, each alert is an object with these top-level keys: `title`, `ruleGroup`, `folderUID`, `noDataState`, `execErrState`, `for`, `condition`, `annotations`, `labels`, `data`.

**`data` array** — two refs: `A` (PromQL query), `B` (threshold expression referencing `A`). Use `rate()` over 5m window for a Counter:

```json
{
  "refId": "A",
  "model": {
    "expr": "rate(cipherbox_unpin_cross_user_attempts_total[5m])",
    "intervalMs": 15000,
    "maxDataPoints": 43200,
    "refId": "A"
  },
  "datasourceUid": "GRAFANA_CLOUD_DATASOURCE_UID",
  "queryType": "",
  "relativeTimeRange": { "from": 600, "to": 0 }
}
```

**labels** — follow `{"severity": "warning", "service": "cipherbox", "operation": "unpin-security"}`.

---

### `scripts/backfill-pinned-cids.ts` (utility, batch) — new

**Analog:** `apps/api/src/run-migrations.ts`

**DataSource bootstrap pattern** (run-migrations.ts lines 1-54):

```typescript
import { DataSource } from 'typeorm';
import { config } from 'dotenv';

config();

const dataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_DATABASE || 'cipherbox',
  entities: ['dist/**/*.entity.js'],
  migrations: ['dist/migrations/*.js'],
  logging: ['error', 'migration'],
});

async function run() {
  try {
    await dataSource.initialize();
    // ... work
    await dataSource.destroy();
    process.exit(0);
  } catch (error: unknown) {
    const err = error instanceof Error ? error : new Error(String(error));
    console.error('...', err.message);
    process.exit(1);
  }
}

run();
```

**Batch processing pattern** — use `LIMIT` + `OFFSET` loop from migration.processor.ts `BATCH_SIZE = 10`. Backfill excludes BYO users (WHERE `v.is_byo_user = false` JOIN on `vaults`). Accept `--dry-run` flag via `process.argv`.

---

### `apps/web/src/services/delete.service.ts` — modified, add `fetchQuota()` reconcile

**Analog:** `apps/web/src/stores/quota.store.ts` (shows `fetchQuota` and `removeUsage` on same store)

**Current `deleteFile`** (delete.service.ts lines 15-24):

```typescript
export async function deleteFile(cid: string, sizeBytes: number): Promise<void> {
  await unpinFromIpfs(cid);

  const quotaStore = useQuotaStore.getState();
  quotaStore.removeUsage(sizeBytes);
}
```

**Add after `removeUsage`** (D-12):

```typescript
quotaStore.fetchQuota().catch((err) => logger.warn('quota reconcile failed', err));
```

`logger` is already imported (line 3). No new imports needed. `fetchQuota` is async and fire-and-forget here — do NOT `await` it (would slow the delete path; local decrement already gives instant feedback).

---

## Shared Patterns

### TypeORM Transaction

**Source:** `apps/api/src/tee/tee-key-state.service.ts` lines 85-120
**Apply to:** `VaultService.guardedUnpin`, backfill script

```typescript
return this.dataSource.transaction(async (manager) => {
  const repo = manager.getRepository(Entity);
  // all reads/writes through manager-scoped repo
});
```

### BullMQ Queue Registration (non-fatal)

**Source:** `apps/api/src/republish/republish.module.ts` lines 31-48
**Apply to:** `PendingUnpinModule.onModuleInit`

```typescript
try {
  await this.queue.upsertJobScheduler(schedulerId, { pattern }, { name: jobName });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  this.logger.warn(`Failed to register scheduler (non-fatal): ${message}`);
}
```

### WorkerHost Processor

**Source:** `apps/api/src/migration/migration.processor.ts` lines 13-30
**Apply to:** `PendingUnpinProcessor`

```typescript
@Processor('queue-name')
export class MyProcessor extends WorkerHost {
  constructor(/* injections */) { super(); }
  async process(job: Job<...>): Promise<void> { ... }
}
```

### Prometheus Counter (cipherbox_* convention)

**Source:** `apps/api/src/metrics/metrics.service.ts` lines 97-102
**Apply to:** All three new metrics in `MetricsService`

```typescript
this.myCounter = new client.Counter({
  name: 'cipherbox_<noun>_<verb>_total',
  help: '...',
  registers: [this.registry],
});
```

### orIgnore Upsert

**Source:** `apps/api/src/vault/vault.service.ts` lines 207-218
**Apply to:** `pending_unpins` INSERT in `guardedUnpin`

```typescript
await repo
  .createQueryBuilder()
  .insert()
  .into(Entity)
  .values({ ... })
  .orIgnore()
  .execute();
```

### Error String Extraction

**Source:** `apps/api/src/republish/republish.module.ts` line 46 / `migration.processor.ts` line 116
**Apply to:** All catch blocks in new files

```typescript
const message = error instanceof Error ? error.message : String(error);
```

---

## No Analog Found

None. All files have close codebase analogs.

---

## Metadata

**Analog search scope:** `apps/api/src/`, `apps/web/src/`, `docker/grafana/alerts/`, `scripts/`
**Files scanned:** 14
**Pattern extraction date:** 2026-06-12
