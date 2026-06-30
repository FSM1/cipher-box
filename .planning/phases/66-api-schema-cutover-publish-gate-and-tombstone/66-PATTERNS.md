# Phase 66: API Schema Cutover, Publish Gate, and Tombstone - Pattern Map

**Mapped:** 2026-06-30
**Files analyzed:** 11 new/modified files
**Analogs found:** 11 / 11

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` | migration | batch | `apps/api/src/migrations/1749300000000-IpnsCacheKeyedByName.ts` | exact |
| `apps/api/src/ipns/entities/ipns-record.entity.ts` | model | CRUD | `apps/api/src/ipns/entities/folder-ipns.entity.ts` | exact |
| `apps/api/src/shares/entities/share.entity.ts` | model | CRUD | `apps/api/src/shares/entities/share-invite.entity.ts` | exact |
| `apps/api/src/shares/entities/share-invite.entity.ts` | model | CRUD | current file (drop one column) | exact |
| `apps/api/src/ipns/ipns.service.ts` | service | request-response | current file + `apps/api/src/auth/auth.service.ts` L244-248 | exact |
| `apps/api/src/ipns/ipns-record.codec.ts` | utility | transform | current file | exact |
| `apps/api/src/ipns/ipns.controller.ts` | controller | request-response | current file | exact |
| `apps/api/src/republish/republish.service.ts` | service | CRUD | current file (entity rename only) | exact |
| `apps/api/src/ipns/ipns.module.ts` | config | — | current file | exact |
| `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` | test | event-driven | `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` | exact |
| `packages/api-client/src/generated/` | config | — | existing generated files | exact |

---

## Pattern Assignments

### `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` (migration, batch)

**Analog:** `apps/api/src/migrations/1749300000000-IpnsCacheKeyedByName.ts`

**Class + name field pattern** (lines 1-19 of 1749300000000):
```typescript
import { MigrationInterface, QueryRunner } from 'typeorm';

export class ApiSchemaCutover1750000000000 implements MigrationInterface {
  name = 'ApiSchemaCutover1750000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // All DDL via raw queryRunner.query() with SQL string template literals
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // minimal/throw — greenfield waiver (D-01)
    throw new Error('down() not implemented: greenfield drop-recreate migration');
  }
}
```

**Raw DDL via queryRunner.query pattern** (1749300000000 lines 23-49):
```typescript
await queryRunner.query(`
  DELETE FROM "folder_ipns" f
  USING ( ... ) ranked
  WHERE f.id = ranked.id AND ranked.rn > 1
`);

await queryRunner.query(
  `ALTER TABLE "folder_ipns" DROP CONSTRAINT IF EXISTS "UQ_folder_ipns_user_ipns"`
);

await queryRunner.query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint WHERE conname = 'UQ_folder_ipns_ipns_name'
    ) THEN
      ALTER TABLE "folder_ipns"
        ADD CONSTRAINT "UQ_folder_ipns_ipns_name" UNIQUE ("ipns_name");
    END IF;
  END $$;
`);
```

**Simpler DROP COLUMN pattern** (1749400000000-DropFolderIpnsRecordType.ts lines 16-19):
```typescript
public async up(queryRunner: QueryRunner): Promise<void> {
  await queryRunner.query(`
    ALTER TABLE "folder_ipns" DROP COLUMN IF EXISTS "record_type"
  `);
}
```

**Full CREATE TABLE pattern with FK and indexes** (1700000000000-FullSchema.ts lines 29-116):
```typescript
await queryRunner.query(`
  CREATE TABLE "users" (
    "id"         uuid NOT NULL DEFAULT uuid_generate_v4(),
    "publicKey"  varchar NOT NULL,
    "createdAt"  TIMESTAMP NOT NULL DEFAULT now(),
    "updatedAt"  TIMESTAMP NOT NULL DEFAULT now(),
    CONSTRAINT "PK_users" PRIMARY KEY ("id"),
    CONSTRAINT "UQ_users_publicKey" UNIQUE ("publicKey")
  )
`);

// FK added separately after CREATE TABLE:
await queryRunner.query(`
  ALTER TABLE "vaults"
  ADD CONSTRAINT "FK_vaults_owner" FOREIGN KEY ("owner_id")
    REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
`);

// Indexes added separately:
await queryRunner.query(`CREATE UNIQUE INDEX "IDX_vaults_owner_id" ON "vaults" ("owner_id")`);
```

**Migration drop/recreate ordering for Phase 66** (from RESEARCH.md FK map):
1. `DROP TABLE share_keys CASCADE`
2. `DROP TABLE shares CASCADE`
3. `CREATE TABLE shares` (new schema)
4. `DROP TABLE folder_ipns CASCADE`
5. `CREATE TABLE ipns_records` (new schema)
6. `ALTER TABLE share_invites DROP COLUMN IF EXISTS encrypted_child_keys`

---

### `apps/api/src/ipns/entities/ipns-record.entity.ts` (model, CRUD)

**Analog:** `apps/api/src/ipns/entities/folder-ipns.entity.ts`

**Full current entity** (folder-ipns.entity.ts lines 1-93):
```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';

@Entity('folder_ipns')
@Unique(['ipnsName'])
export class FolderIpns {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ type: 'uuid', name: 'user_id' })
  userId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user!: User;

  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  @Column({ type: 'varchar', length: 255, name: 'latest_cid', nullable: true })
  latestCid!: string | null;

  @Column({ type: 'bigint', name: 'sequence_number', default: 0 })
  sequenceNumber!: string; // TypeORM returns bigint as string

  @Column({ type: 'bytea', name: 'signed_record', nullable: true })
  signedRecord!: Buffer | null;

  @Column({ type: 'bytea', name: 'public_key', nullable: true })
  publicKey!: Buffer | null;           // DROPPED in IpnsRecord

  @Column({ type: 'bytea', name: 'encrypted_ipns_private_key', nullable: true })
  encryptedIpnsPrivateKey!: Buffer | null;

  @Column({ type: 'int', name: 'key_epoch', nullable: true })
  keyEpoch!: number | null;

  @Column({ type: 'boolean', name: 'is_root', default: false })
  isRoot!: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt!: Date;
}
```

**Target `IpnsRecord` — delta from analog:**
- Change `@Entity('folder_ipns')` → `@Entity('ipns_records')`
- Change class name `FolderIpns` → `IpnsRecord`
- **Drop** `publicKey` column entirely (column + field)
- **Add** two columns following the same decorator style:
```typescript
@Column({ type: 'timestamptz', name: 'tombstoned_at', nullable: true })
tombstonedAt!: Date | null;

@Column({ type: 'bigint', name: 'generation', default: 0 })
generation!: string; // TypeORM returns bigint as string — matches sequenceNumber pattern
```

---

### `apps/api/src/shares/entities/share.entity.ts` (model, CRUD)

**Analog:** current `share.entity.ts` (full reshape — see current file, lines 1-106)

**Current imports + decorators pattern** (lines 1-18):
```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from '../../auth/entities/user.entity';
import { ShareKey } from './share-key.entity';

// Comment explaining the unique constraint strategy
@Entity('shares')
export class Share {
```

**Target Share entity — columns to keep, drop, and add:**

Keep: `id`, `sharerId`/sharer relation, `recipientId`/recipient relation, `itemNameEncrypted`, `hiddenByRecipient`, `createdAt`, `updatedAt`

Drop: `itemType`, `ipnsName`, `itemName`, `encryptedKey`, `permission`, `encryptedIpnsKey`, `revokedAt`, `shareKeys` (`OneToMany`), `ShareKey` import

Add (following existing `@Column` decorator style):
```typescript
@Column({ type: 'bytea', name: 'read_descriptor_ref' })
readDescriptorRef!: Buffer;

@Column({ type: 'bytea', name: 'write_descriptor_ref', nullable: true })
writeDescriptorRef!: Buffer | null;

@Column({ type: 'uuid', name: 'root_node_id' })
rootNodeId!: string;

@Column({ type: 'varchar', length: 255, name: 'root_ipns_name' })
rootIpnsName!: string;

@Column({ type: 'bigint', name: 'root_generation', default: 0 })
rootGeneration!: string; // TypeORM bigint → string, matches sequenceNumber pattern
```

Change class-level decorator from comment + `@Entity` only to:
```typescript
// Plain unique constraint — hard-delete on revoke means no revoked rows coexist (D-11)
@Entity('shares')
@Unique(['sharerId', 'recipientId', 'rootNodeId'])
export class Share {
```
Remove `OneToMany` and `JoinColumn` from imports since the `shareKeys` relation is deleted. Remove `ShareKey` import.

---

### `apps/api/src/shares/entities/share-invite.entity.ts` (model, CRUD)

**Analog:** current file (minimal change — drop one column)

**Column to drop** (lines 57-63 of current file):
```typescript
@Column({ type: 'jsonb', name: 'encrypted_child_keys', nullable: true })
encryptedChildKeys!: Array<{
  keyType: ChildKeyType;
  itemId: string;
  encryptedKey: string; // hex
}> | null;
```

Also drop the `import type { ChildKeyType } from '../types'` import (line 11) if `ChildKeyType` is only used for `encryptedChildKeys`. Verify `types.ts` usage before deleting the import.

`encryptedKey` at line 51 stays — semantics change to single ephemeral-wrapped root `readKey` (D-05), but the column shape (`bytea`, not nullable) is unchanged.

---

### `apps/api/src/ipns/ipns.service.ts` — `publishRecord`/`upsertFolderIpns` (service, request-response)

**Analog (existing non-atomic path):** current `upsertFolderIpns`, lines 214-353

**Current TOCTOU pattern to replace** (lines 228-344 — the findOne→gate→save sequence):
```typescript
// Step 1: read (not locked)
const existing = await this.folderIpnsRepository.findOne({ where: { ipnsName } });
// Step 3: in-memory CAS check — not DB-locked (TOCTOU gap)
if (existing && expectedSequenceNumber !== undefined) {
  const expected = BigInt(expectedSequenceNumber);
  const current = BigInt(existing.sequenceNumber);
  if (expected !== current) {
    throw new ConflictException({ statusCode: 409, ... });
  }
}
// Step 6: non-atomic write — second concurrent writer clobbers first
const saved = await this.folderIpnsRepository.save(existing);
```

**Analog for `result.affected` check** (`apps/api/src/auth/auth.service.ts` lines 244-248):
```typescript
const result = await this.userRepository.delete(userId);
if (result.affected === 0) {
  throw new BadRequestException('Account not found');
}
```

**Analog for `repository.delete()` returning `{ affected }` ** (`apps/api/src/republish/republish.service.ts` lines 256-267):
```typescript
const result = await this.scheduleRepository.delete({ userId, ipnsName });
const affected = result.affected ?? 0;
```

**Target atomic CAS pattern** (from RESEARCH.md Pattern 1 — `createQueryBuilder().update()`):
```typescript
const result = await this.ipnsRecordRepository
  .createQueryBuilder()
  .update(IpnsRecord)
  .set({
    latestCid: metadataCid,
    sequenceNumber: () => `sequence_number + 1`,
    signedRecord: Buffer.from(signedRecord),
    updatedAt: new Date(),
  })
  .where(
    'ipns_name = :ipnsName AND sequence_number = :expected AND generation <= :incoming AND tombstoned_at IS NULL',
    { ipnsName, expected: expectedSequenceNumber, incoming: incomingGeneration }
  )
  .execute();

if (result.affected === 0) {
  // Single follow-up read to distinguish 409 from 410
  const row = await this.ipnsRecordRepository.findOne({ where: { ipnsName } });
  if (!row) throw new NotFoundException('IPNS record not found');
  if (row.tombstonedAt) {
    throw new HttpException({ error: 'IPNS_TOMBSTONED', ipnsName }, HttpStatus.GONE);
  }
  throw new ConflictException({
    statusCode: 409,
    message: 'Sequence number mismatch or generation regression',
    currentSequenceNumber: row.sequenceNumber,
  });
}
```

**Note:** `createQueryBuilder().update()` returns `UpdateResult { affected: number | undefined }`. PostgreSQL always populates `affected`. Do NOT mix with `queryRunner.query()` (different return shape — see RESEARCH.md Pitfall 2).

**New `tombstoneRecord` method pattern** (modeled on `unenrollIpns` at republish.service.ts L256-267):
```typescript
async tombstoneRecord(userId: string, ipnsName: string): Promise<void> {
  const result = await this.ipnsRecordRepository
    .createQueryBuilder()
    .update(IpnsRecord)
    .set({ tombstonedAt: new Date() })
    .where('ipns_name = :ipnsName AND tombstoned_at IS NULL AND user_id = :userId', { ipnsName, userId })
    .execute();
  // Fire-and-forget: remove from republish schedule regardless of affected count
  await this.republishService.unenrollIpns(userId, ipnsName);
}
```

---

### `apps/api/src/ipns/ipns-record.codec.ts` (utility, transform)

**Analog:** current file — type import update only + case-split logic.

**Current undifferentiated null case** (ipns-record.codec.ts L57-64, from RESEARCH.md):
```typescript
parseCachedRecord(cached):
  if (!cached?.latestCid) → return null (→ 404)
  if (!cached.signedRecord) → return null (→ 404)   // undifferentiated — REPLACE
```

**Target case-split** (RESEARCH.md §parseCachedRecord Case-Split):
```typescript
if (!cached.signedRecord) {
  // Expected null: shared-folder row — apply seq floor rather than failing closed
  return { seqFloor: cached.sequenceNumber };  // new discriminant
}
```

**Import line to update** (L3 of current file):
```typescript
// Before:
import type { FolderIpns } from './entities/folder-ipns.entity';
// After:
import type { IpnsRecord } from './entities/ipns-record.entity';
```

**publicKey recovery** (existing at ~L96 of current file) — already uses `publicKeyFromIpnsName(cached.ipnsName)` as fallback. With `public_key` column dropped, the column fallback path (`cached.publicKey`) is removed entirely; `publicKeyFromIpnsName` is the only recovery path.

---

### `apps/api/src/ipns/ipns.controller.ts` (controller, request-response)

**Analog:** current file

**Existing `@ApiResponse` pattern for conflict** (lines 64-73):
```typescript
@ApiResponse({
  status: 409,
  description:
    'Conflict - expectedSequenceNumber does not match current server sequence number. ' +
    'Response body includes currentSequenceNumber for client re-sync.',
})
```

**New 410 `@ApiResponse` pattern** (from RESEARCH.md Pattern 2 — add to `publishRecord` and `resolveRecord`):
```typescript
@ApiResponse({
  status: 410,
  description: 'Gone — IPNS name has been tombstoned (rotated out; no longer publishable)',
  schema: {
    type: 'object',
    properties: {
      error: { type: 'string', example: 'IPNS_TOMBSTONED' },
      ipnsName: { type: 'string' },
    },
  },
})
```

**New tombstone endpoint** — follow existing `POST 'unenroll'` endpoint pattern (lines 125-145):
```typescript
@Post('tombstone')
@HttpCode(200)
@ApiOperation({ summary: 'Tombstone an IPNS record' })
@ApiResponse({ status: 200, description: 'Record tombstoned' })
@ApiResponse({ status: 404, description: 'Record not found' })
async tombstoneRecord(
  @Request() req: RequestWithUser,
  @Body() dto: TombstoneIpnsDto
): Promise<void> {
  await this.ipnsService.tombstoneRecord(req.user.id, dto.ipnsName);
}
```

**Import addition needed:**
```typescript
import { HttpException, HttpStatus } from '@nestjs/common';  // for service-layer throw
```
(The controller itself may only need a new DTO import; the `HttpException` throw lives in the service.)

---

### `apps/api/src/republish/republish.service.ts` (service, CRUD)

**Analog:** current file — entity rename only.

**Import to update** (L5 of current file):
```typescript
// Before:
import { FolderIpns } from '../ipns/entities/folder-ipns.entity';
// After:
import { IpnsRecord } from '../ipns/entities/ipns-record.entity';
```

**`@InjectRepository` to update** (pattern from current file):
```typescript
// Before:
@InjectRepository(FolderIpns)
private readonly folderIpnsRepository: Repository<FolderIpns>,
// After:
@InjectRepository(IpnsRecord)
private readonly ipnsRecordRepository: Repository<IpnsRecord>,
```

`unenrollIpns` method at lines 256-267 is correct as-is (deletes schedule row). No logic change needed.

---

### `apps/api/src/ipns/ipns.module.ts` (config)

**Analog:** current file

**`TypeOrmModule.forFeature` pattern to update**:
```typescript
// Before:
TypeOrmModule.forFeature([FolderIpns])
// After:
TypeOrmModule.forFeature([IpnsRecord])
```

---

### `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` (test, event-driven)

**Analog:** `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts`

**File header / docblock pattern** (rotation-crash-safety.test.ts lines 1-32):
```typescript
/**
 * [Suite name] suite ([requirement IDs] phase gate) — Phase [N].
 *
 * [What it proves]
 *
 * Prerequisites (live local stack):
 *   docker compose -f docker/docker-compose.yml up -d   (redis 6380, kubo, postgres)
 *   pnpm --filter @cipherbox/api dev                    (API on :3000)
 */
```

**Standard imports scaffold** (rotation-crash-safety.test.ts lines 34-57):
```typescript
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createAndPublishIpnsRecord,
  resolveIpnsRecord,
  type SdkContext,
  // ... other sdk-core exports as needed
} from '@cipherbox/sdk-core';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';

let fixture: MultiAccountFixture;
// aliceCtx / bobCtx extracted from fixture in beforeAll
```

**`persistCallback` injection pattern for race-forcing** (rotation-crash-safety.test.ts lines 627-683):
```typescript
let callCount = 0;
const racingCallback = async (_job: RotationJobRecord): Promise<void> => {
  callCount++;
  if (callCount !== 1) return; // only inject on first call

  // ... interpose the racing publish here using sdk-core functions
  await updateFolderMetadataAndPublish({ ..., ctx: aliceCtx });
};

const jobRecord: RotationJobRecord = {
  ...,
  persistCallback: racingCallback,
};

await rotateReadFromNode({ ..., jobRecord, ctx: aliceCtx });
```

**Concurrent publish pattern for Test 16** (from RESEARCH.md Pattern 3):
```typescript
// Both clients read same expectedSequenceNumber before racing
const [resultA, resultB] = await Promise.allSettled([
  publishWithCas({ ..., expectedSequenceNumber: '1', ctx: aliceCtx }),
  publishWithCas({ ..., expectedSequenceNumber: '1', ctx: aliceCtx }),
]);
// Assert exactly one fulfilled (200) and one rejected (409)
const fulfilled = [resultA, resultB].filter(r => r.status === 'fulfilled');
const rejected = [resultA, resultB].filter(r => r.status === 'rejected');
expect(fulfilled).toHaveLength(1);
expect(rejected).toHaveLength(1);
// Check the rejection is 409 ConflictException
```

**Test 20 tombstone pattern** (from RESEARCH.md Tombstone Flow §5.5):
```typescript
// 1. Tombstone the record via POST /ipns/tombstone
await fetch('http://localhost:3000/ipns/tombstone', {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ ipnsName }),
});

// 2. Assert publish is rejected with 410
await expect(publishWithCas({ ..., expectedSequenceNumber: '1', ctx: aliceCtx }))
  .rejects.toMatchObject({ response: { status: 410, data: { error: 'IPNS_TOMBSTONED' } } });

// 3. Assert resolve returns 410
await expect(resolveIpnsRecord(ipnsName, aliceCtx))
  .rejects.toMatchObject({ response: { status: 410 } });
```

**Vitest config** (`tests/sdk-e2e/vitest.config.ts`): `sequence: { concurrent: false }`, `fileParallelism: false`, `testTimeout: 120_000`. New file sits alongside the other suites in `tests/sdk-e2e/src/suites/`.

---

## Shared Patterns

### `result.affected` Check Pattern
**Source:** `apps/api/src/auth/auth.service.ts` L244-248; `apps/api/src/republish/republish.service.ts` L257-258
**Apply to:** `IpnsService.atomicCasPublish`, `IpnsService.tombstoneRecord`
```typescript
const result = await this.repository.delete(criteria);
const affected = result.affected ?? 0;
// OR (for update):
if (result.affected === 0) { throw new ... }
```

### TypeORM bigint → string Convention
**Source:** `apps/api/src/ipns/entities/folder-ipns.entity.ts` L49-50
**Apply to:** `IpnsRecord.generation`, `IpnsRecord.sequenceNumber`, `Share.rootGeneration`
```typescript
@Column({ type: 'bigint', name: 'sequence_number', default: 0 })
sequenceNumber!: string; // TypeORM returns bigint as string
```
When comparing: `BigInt(row.generation)`. In raw SQL WHERE clause: `:incoming::bigint`.

### `@ApiResponse` Pattern
**Source:** `apps/api/src/ipns/ipns.controller.ts` L51-73
**Apply to:** all new/modified endpoints in `IpnsController`
```typescript
@ApiResponse({ status: 200, description: '...', type: ResponseDto })
@ApiResponse({ status: 400, description: '...' })
@ApiResponse({ status: 409, description: '...' })
// New for Phase 66:
@ApiResponse({ status: 410, description: '...', schema: { ... } })
```

### JWT Guard + Controller Pattern
**Source:** `apps/api/src/ipns/ipns.controller.ts` L30-38
**Apply to:** new `tombstone` endpoint (same class, inherits class-level `@UseGuards`)
```typescript
@ApiTags('IPNS')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, ThrottlerGuard)
@Controller('ipns')
export class IpnsController {
  constructor(private readonly ipnsService: IpnsService, ...) {}
}
```

### Migration queryRunner.query Style
**Source:** `apps/api/src/migrations/1749300000000-IpnsCacheKeyedByName.ts` L23-49
**Apply to:** new `1750000000000-ApiSchemaCutover.ts`
- All DDL via `await queryRunner.query(\` ... \`)` with SQL template literals
- CREATE TABLE inline constraints (`CONSTRAINT "PK_..." PRIMARY KEY`)
- FKs and indexes added in separate `queryRunner.query` calls after the CREATE TABLE
- Use `IF NOT EXISTS` / `IF EXISTS` for idempotency guards where needed

---

## No Analog Found

All files have close analogs within the existing codebase. No file requires falling back to RESEARCH.md patterns alone.

---

## Metadata

**Analog search scope:** `apps/api/src/`, `tests/sdk-e2e/src/`
**Files scanned:** 14 source files read directly
**Pattern extraction date:** 2026-06-30
