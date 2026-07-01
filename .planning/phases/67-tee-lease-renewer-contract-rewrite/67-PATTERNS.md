# Phase 67: TEE Lease-Renewer Contract Rewrite - Pattern Map

**Mapped:** 2026-07-01
**Files analyzed:** 9 new/modified files
**Analogs found:** 9 / 9

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `apps/tee-worker/src/routes/republish.ts` | controller | request-response | self (rewrite in place) | exact |
| `apps/tee-worker/src/services/ipns-signer.ts` | service | transform | self (extend in place) | exact |
| `apps/tee-worker/src/services/key-manager.ts` | service | transform | self (extend in place) | exact |
| `apps/tee-worker/src/services/tee-keys.ts` | service | transform | self (extend in place) | exact |
| `apps/api/src/republish/republish.service.ts` | service | CRUD | self (rewrite getDueEntries + sync) | exact |
| `apps/api/src/republish/republish-schedule.entity.ts` | model | — | self (drop 4 columns) | exact |
| `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts` | migration | — | `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` | role-match |
| `packages/sdk-core/src/folder/registration.ts` | service | CRUD | self (wire teeKeys fields) | exact |
| `tests/sdk-e2e/src/suites/tee-republish.test.ts` | test | event-driven | `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` | role-match |
| `docker/docker-compose.yml` | config | — | `docker/docker-compose.staging.yml:96-115` | role-match |

---

## Pattern Assignments

### `apps/tee-worker/src/routes/republish.ts` (controller, request-response)

**Analog:** self — full current file is the base; rewrite the interface, step 2, step 3, and step 4.

**Current imports pattern** (lines 16-20):
```typescript
import { Router, type Request, type Response } from 'express';
import { decryptWithFallback, reEncryptForEpoch } from '../services/key-manager.js';
import { signIpnsRecord } from '../services/ipns-signer.js';
import { republishEntries } from '../middleware/metrics.js';
import { logger } from '../services/logger.js';
```
After rewrite, add:
```typescript
import { parseIpnsRecord, verifyIpnsRecordSignature, publicKeyFromIpnsName } from '@cipherbox/crypto';
import { renewIpnsRecord } from '../services/ipns-signer.js';       // replaces signIpnsRecord
import { getInternalCurrentEpoch } from '../services/tee-keys.js';  // new export
```

**RepublishEntry interface to replace** (lines 25-32) — current shape being removed:
```typescript
interface RepublishEntry {
  encryptedIpnsKey: string; // base64-encoded ECIES ciphertext
  ipnsName: string;
  latestCid: string;
  sequenceNumber: string;   // bigint as string
  currentEpoch: number;     // REMOVE — TEE self-derives
  previousEpoch: number | null; // REMOVE
}
```
Target shape after D-01/D-02/D-03:
```typescript
interface RepublishEntry {
  encryptedIpnsKey: string; // base64-encoded ECIES ciphertext
  keyEpoch: number;         // from ipns_records.key_epoch (ECIES epoch hint)
  ipnsName: string;
  signedRecord: string;     // NEW: base64-encoded marshaled IPNS record bytes
  // removed: latestCid, sequenceNumber, currentEpoch, previousEpoch
}
```

**RepublishResult interface** (lines 35-43) — `newSequenceNumber` field stays (same value as input) for relay write-back; add optional `requiresReEnroll`:
```typescript
interface RepublishResult {
  ipnsName: string;
  success: boolean;
  signedRecord?: string;         // base64-encoded renewed record bytes
  newSequenceNumber?: string;    // same as input seq (no +1n)
  upgradedEncryptedKey?: string;
  upgradedKeyEpoch?: number;
  requiresReEnroll?: true;       // NEW: signals stale-key guard triggered (D-03)
  error?: string;
}
```

**Core per-entry processing block to replace** (lines 63-109) — current `step 2 + 3 + 4`:

Current (lines 71-90) — the pattern to replace:
```typescript
// Step 2: Decrypt with epoch fallback
const { ipnsPrivateKey: decryptedKey, usedEpoch } = await decryptWithFallback(
  encryptedIpnsKey,
  entry.currentEpoch,      // REMOVE: relay-supplied epoch
  entry.previousEpoch      // REMOVE: relay-supplied epoch
);

// Step 3: Sign IPNS record with incremented sequence number
const newSequenceNumber = BigInt(entry.sequenceNumber) + 1n;  // REMOVE +1n
const signedRecord = await signIpnsRecord(ipnsPrivateKey, entry.latestCid, newSequenceNumber);

// Step 4: Check if re-encryption needed
if (usedEpoch !== entry.currentEpoch) {                       // REMOVE: used relay epoch
  const reEncrypted = await reEncryptForEpoch(ipnsPrivateKey, entry.currentEpoch);
```

Target pattern (RESEARCH.md Pattern 1, lines 700-742):
```typescript
const signedRecordBytes = Buffer.from(entry.signedRecord, 'base64');

// Step 1: Parse the existing record
const parsed = await parseIpnsRecord(signedRecordBytes);

// Step 2: Verify signature against the name
const isValid = await verifyIpnsRecordSignature(entry.ipnsName, signedRecordBytes);
if (!isValid) throw new Error('IPNS signature verification failed');

// Step 3: Decrypt with internal epoch derivation (D-03)
const { ipnsPrivateKey: decryptedKey, usedEpoch } = await decryptWithFallback(
  encryptedIpnsKey,
  entry.keyEpoch  // hint only; TEE derives currentEpoch internally
);
ipnsPrivateKey = decryptedKey;

// Step 4: Name↔key binding assertion (D-01 §6.7-2)
const derivedPubkey = getPublicKey(decryptedKey);  // @noble/ed25519
const namePubkey = publicKeyFromIpnsName(entry.ipnsName);
if (!derivedPubkey.every((b, i) => b === namePubkey[i])) {
  decryptedKey.fill(0);
  throw new Error('Name-key binding violation');
}

// Step 5: Re-sign same value + same sequence, later EOL (D-01 TEE-02)
const renewedBytes = await renewIpnsRecord(decryptedKey, signedRecordBytes, TEE_RECORD_LIFETIME_MS);
const newSequenceNumber = parsed.sequence.toString(); // SAME — no +1n

// Step 6: Zero key immediately (unchanged pattern — lines 92-94)
ipnsPrivateKey.fill(0);
ipnsPrivateKey = null;

// Step 7: Epoch upgrade targets internal current epoch (D-03)
const internalCurrent = getInternalCurrentEpoch();
if (usedEpoch !== internalCurrent) {
  // reEncryptForEpoch targets internal epoch, not relay-supplied
  const reEncrypted = await reEncryptForEpoch(decryptedKey, internalCurrent);
  // NOTE: decryptedKey already zeroed above — restructure: zero AFTER re-encrypt
}
```

**Error handling pattern** (lines 111-125) — unchanged; catch block zeroes key:
```typescript
} catch (error) {
  if (ipnsPrivateKey) { ipnsPrivateKey.fill(0); ipnsPrivateKey = null; }
  // Check for ReEnrollRequiredError; surface as structured result field, not plain error
  const isReEnroll = error instanceof ReEnrollRequiredError;
  results.push({
    ipnsName: entry.ipnsName,
    success: false,
    ...(isReEnroll ? { requiresReEnroll: true } : {}),
    error: error instanceof Error ? error.message : 'Unknown error',
  });
  republishEntries.inc({ result: 'failure' });
}
```

---

### `apps/tee-worker/src/services/ipns-signer.ts` (service, transform)

**Analog:** self — add `renewIpnsRecord` alongside existing `signIpnsRecord`.

**Current imports + constant** (lines 9-12):
```typescript
import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
const TEE_RECORD_LIFETIME_MS = 48 * 60 * 60 * 1000;
```
Add to imports:
```typescript
import { parseIpnsRecord } from '@cipherbox/crypto';
```

**Existing `signIpnsRecord`** (lines 25-37) — keep unchanged, it is still used by unit tests:
```typescript
export async function signIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  cid: string,
  sequenceNumber: bigint
): Promise<Uint8Array> {
  const record = await createIpnsRecord(ed25519PrivateKey, '/ipfs/' + cid, sequenceNumber, TEE_RECORD_LIFETIME_MS);
  return marshalIpnsRecord(record);
}
```

**New `renewIpnsRecord` to add** (RESEARCH.md Q4 pattern):
```typescript
/**
 * Renew an existing IPNS record lease: re-sign the SAME value (CID) + SAME
 * sequenceNumber with only a later EOL (extends the lease).
 * Cannot change CID or increment sequence — lease-renewer contract (D-01 / TEE-02).
 */
export async function renewIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  marshaledExistingRecord: Uint8Array,
  lifetimeMs: number = TEE_RECORD_LIFETIME_MS
): Promise<Uint8Array> {
  const parsed = await parseIpnsRecord(marshaledExistingRecord);
  // Re-sign with SAME value + SAME sequence, new EOL.
  // createIpnsRecord → ipns package → ValidityType=0 (EOL) automatically.
  const record = await createIpnsRecord(ed25519PrivateKey, parsed.value, parsed.sequence, lifetimeMs);
  return marshalIpnsRecord(record);
}
```

---

### `apps/tee-worker/src/services/key-manager.ts` (service, transform)

**Analog:** self — rewrite `decryptWithFallback` signature; add `ReEnrollRequiredError`; retarget `reEncryptForEpoch`.

**Current `decryptWithFallback` signature** (lines 47-51) — being replaced:
```typescript
export async function decryptWithFallback(
  encryptedIpnsKey: Uint8Array,
  currentEpoch: number,
  previousEpoch: number | null
): Promise<{ ipnsPrivateKey: Uint8Array; usedEpoch: number }>
```

**Target signature** (RESEARCH.md Q7 pattern):
```typescript
export async function decryptWithFallback(
  encryptedIpnsKey: Uint8Array,
  keyEpoch: number  // hint: the epoch the key was encrypted for (from ipns_records.key_epoch)
): Promise<{ ipnsPrivateKey: Uint8Array; usedEpoch: number }>
```

**ReEnrollRequiredError to add** (before `decryptWithFallback`):
```typescript
export class ReEnrollRequiredError extends Error {
  readonly requiresReEnroll = true;
  constructor(readonly keyEpoch: number, readonly currentEpoch: number) {
    super(`IPNS key epoch ${keyEpoch} is older than currentEpoch-1 (${currentEpoch - 1}). Re-enrollment required.`);
  }
}
```

**New `decryptWithFallback` body** (replaces lines 52-71):
```typescript
  const internalCurrentEpoch = getInternalCurrentEpoch();  // from tee-keys.ts new export

  // Guard: key older than currentEpoch - 1 is outside grace period (D-03)
  if (keyEpoch < internalCurrentEpoch - 1) {
    throw new ReEnrollRequiredError(keyEpoch, internalCurrentEpoch);
  }

  // Try keyEpoch (the epoch the key was encrypted for)
  try {
    const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsKey, keyEpoch);
    return { ipnsPrivateKey, usedEpoch: keyEpoch };
  } catch { /* fall through */ }

  // Try internalCurrentEpoch as fallback (grace window: key encrypted for previous epoch)
  if (keyEpoch !== internalCurrentEpoch) {
    try {
      const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsKey, internalCurrentEpoch);
      return { ipnsPrivateKey, usedEpoch: internalCurrentEpoch };
    } catch { /* fall through */ }
  }

  throw new Error('ECIES decryption failed for available epochs');
```

**`reEncryptForEpoch` retarget** (lines 84-90) — callers now pass `internalCurrentEpoch`; the function itself is unchanged. The call site in `republish.ts` changes from `entry.currentEpoch` to `getInternalCurrentEpoch()`.

---

### `apps/tee-worker/src/services/tee-keys.ts` (service, transform)

**Analog:** self — add `getInternalCurrentEpoch()` export. Existing `getKeypair` / `getPublicKey` are unchanged.

**Current constants** (lines 17-19):
```typescript
export const MIN_EPOCH = 1;
export const MAX_EPOCH = 10_000;
```

**New export to add** after the constants (RESEARCH.md Q7 open-question resolution — Option B: use `keyEpoch` as hint, so `getInternalCurrentEpoch` is used only to compute the stale guard and re-encryption target, not to derive the ECIES trial epoch):
```typescript
/**
 * EPOCH_ZERO_TIMESTAMP_MS: anchor for clock-based epoch derivation.
 * Set this to the UTC ms timestamp when epoch 1 began (configure at TEE bootstrap).
 * If not configured, falls back to a safe sentinel that makes internalCurrentEpoch = 1.
 */
const EPOCH_ZERO_TIMESTAMP_MS = parseInt(process.env.EPOCH_ZERO_TIMESTAMP_MS ?? '0', 10);
const EPOCH_DURATION_MS = 4 * 7 * 24 * 60 * 60 * 1000; // 4 weeks

/**
 * Derive the current epoch from the TEE's own clock (D-03 §6.7-1).
 * Never uses relay-supplied epoch scalars.
 */
export function getInternalCurrentEpoch(): number {
  if (EPOCH_ZERO_TIMESTAMP_MS === 0) return 1; // fallback: epoch 1 until configured
  return Math.max(MIN_EPOCH, Math.floor((Date.now() - EPOCH_ZERO_TIMESTAMP_MS) / EPOCH_DURATION_MS) + 1);
}
```

**Simulator mode pattern** (lines 66-71) — reference for how CIPHERBOX_ENVIRONMENT guard works; same guard needed around `getInternalCurrentEpoch` if strict derivation is required in CVM mode later.

---

### `apps/api/src/republish/republish.service.ts` (service, CRUD)

**Analog:** self — four surgical changes: `getDueEntries`, `teeEntries` map, success branch, `syncIpnsRecordSequence` → `renewIpnsRecordEol`.

**Current `getDueEntries`** (lines 43-52) — no JOIN; uses schedule row fields:
```typescript
async getDueEntries(): Promise<IpnsRepublishSchedule[]> {
  return this.scheduleRepository.find({
    where: { status: In(['active', 'retrying']), nextRepublishAt: LessThanOrEqual(new Date()) },
    order: { nextRepublishAt: 'ASC' },
    take: 2000,
  });
}
```
Target (RESEARCH.md Pattern 2) — adds JOIN + tombstone filter + `encrypted_ipns_private_key IS NOT NULL`:
```typescript
async getDueEntries(): Promise<Array<{ schedule: IpnsRepublishSchedule; record: IpnsRecord }>> {
  const rows = await this.scheduleRepository
    .createQueryBuilder('s')
    .innerJoin(
      IpnsRecord, 'r',
      's.ipns_name = r.ipns_name AND r.tombstoned_at IS NULL AND r.encrypted_ipns_private_key IS NOT NULL'
    )
    .addSelect(['r.ipns_name', 'r.signed_record', 'r.encrypted_ipns_private_key', 'r.key_epoch'])
    .where("s.status IN ('active', 'retrying')")
    .andWhere('s.next_republish_at <= :now', { now: new Date() })
    .orderBy('s.next_republish_at', 'ASC')
    .take(2000)
    .getRawAndEntities();
  // parse raw columns to pair { schedule, record }
}
```

**Current `teeEntries` map** (lines 97-105) — reads from schedule row:
```typescript
const teeEntries: RepublishEntry[] = batch.map((entry) => ({
  encryptedIpnsKey: entry.encryptedIpnsKey.toString('base64'),
  keyEpoch: entry.keyEpoch,
  ipnsName: entry.ipnsName,
  latestCid: entry.latestCid,
  sequenceNumber: entry.sequenceNumber,
  currentEpoch,
  previousEpoch,
}));
```
Target — reads from joined `record` (RESEARCH.md Q3):
```typescript
const teeEntries: RepublishEntry[] = batch.map(({ schedule, record }) => ({
  encryptedIpnsKey: record.encryptedIpnsPrivateKey!.toString('base64'),
  keyEpoch: record.keyEpoch!,
  ipnsName: schedule.ipnsName,
  signedRecord: record.signedRecord!.toString('base64'),
}));
```

**Success branch** (lines 133-163) — after D-02, `entry.sequenceNumber` field is gone from schedule; relay still needs the loadedSeq for the CAS write. Carry it through from the batch load (from `record.sequenceNumber` at getDueEntries time). The `result.newSequenceNumber` from TEE equals the loaded seq (no +1n). Epoch upgrade writes to `ipns_records` (`encrypted_ipns_private_key` + `key_epoch`), not the schedule:

Pattern: `entry.encryptedIpnsKey = ...` and `entry.keyEpoch = ...` on lines 148-149 move to an `ipnsRecordRepository.update()` call instead.

**`syncIpnsRecordSequence` to replace** (lines 372-403) — current weak `LessThanOrEqual` write-back:
```typescript
await this.ipnsRecordRepository.update(
  { userId, ipnsName, tombstonedAt: IsNull(), sequenceNumber: LessThanOrEqual(newSequenceNumber) },
  { sequenceNumber: newSequenceNumber, signedRecord: Buffer.from(signedRecordBase64, 'base64') }
);
```
Target `renewIpnsRecordEol` (RESEARCH.md Q5 recommended pattern):
```typescript
private async renewIpnsRecordEol(
  ipnsName: string,
  loadedSequenceNumber: string,
  renewedSignedRecord: Buffer
): Promise<void> {
  const result = await this.ipnsRecordRepository
    .createQueryBuilder()
    .update(IpnsRecord)
    .set({ signedRecord: renewedSignedRecord, updatedAt: new Date() })
    .where(
      'ipns_name = :ipnsName AND sequence_number = :expected AND tombstoned_at IS NULL',
      { ipnsName, expected: loadedSequenceNumber }
    )
    .execute();

  if (result.affected === 0) {
    this.logger.debug(`EOL renewal CAS miss for ${ipnsName} (seq advanced or tombstoned) — discarding`);
  }
}
```

**`enrollFolder` signature change** (lines 211-250) — current 6-param:
```typescript
async enrollFolder(userId, ipnsName, encryptedIpnsKey, keyEpoch, latestCid, sequenceNumber)
```
Target 2-param after D-02 (schedule stores no crypto fields):
```typescript
async enrollFolder(userId: string, ipnsName: string): Promise<void>
```
Callers to update: `ipns.service.ts:421-434` which calls `enrollFolder(existing.userId, ipnsName, Buffer.from(...), keyEpoch!, metadataCid, newSeq)`.

---

### `apps/api/src/republish/republish-schedule.entity.ts` (model)

**Analog:** self — remove 4 `@Column` declarations.

**Columns to remove** (lines 39-60):
```typescript
@Column({ type: 'bytea', name: 'encrypted_ipns_key' })
encryptedIpnsKey!: Buffer;          // line 39-40

@Column({ type: 'int', name: 'key_epoch' })
keyEpoch!: number;                  // line 46-47

@Column({ type: 'varchar', length: 255, name: 'latest_cid' })
latestCid!: string;                 // line 52-53

@Column({ type: 'bigint', name: 'sequence_number', default: 0 })
sequenceNumber!: string;            // line 59-60
```
Retained columns: `id`, `userId`, `user`, `ipnsName`, `nextRepublishAt`, `lastRepublishAt`, `consecutiveFailures`, `status`, `lastError`, `createdAt`, `updatedAt`.

---

### `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts` (migration)

**Analog:** `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts`

**Structural pattern from analog** (lines 1-17):
```typescript
import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * [description]
 * down() deliberately throws — greenfield waiver (D-01/D-02).
 */
export class SomeName1750000000000 implements MigrationInterface {
  name = 'SomeName1750000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`...`);
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    throw new Error('... migration is irreversible — greenfield waiver');
  }
}
```

**Target migration body** (RESEARCH.md Q6):
```typescript
export class ScheduleCollapse1751000000000 implements MigrationInterface {
  name = 'ScheduleCollapse1751000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // TEE-03 / D-02: collapse duplicated signing-input columns from ipns_republish_schedule.
    // All signing inputs now source from ipns_records via JOIN on ipns_name.
    await queryRunner.query(`
      ALTER TABLE "ipns_republish_schedule"
        DROP COLUMN IF EXISTS "encrypted_ipns_key",
        DROP COLUMN IF EXISTS "key_epoch",
        DROP COLUMN IF EXISTS "latest_cid",
        DROP COLUMN IF EXISTS "sequence_number"
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_ipns_republish_schedule_ipns_name"
        ON "ipns_republish_schedule" ("ipns_name")
    `);
  }

  public async down(_queryRunner: QueryRunner): Promise<void> {
    throw new Error('ScheduleCollapse migration is irreversible — greenfield waiver (D-02)');
  }
}
```

---

### `packages/sdk-core/src/folder/registration.ts` (service, CRUD — folded todo 2)

**Analog:** self — add `teeKeys` field forwarding to `createAndPublishIpnsRecord`.

**Current call site** (lines 86-92) — teeKeys not wired:
```typescript
await createAndPublishIpnsRecord({
  ipnsPrivateKey,
  ipnsName,
  metadataCid: cid,
  sequenceNumber: 1n,
  ctx: params.ctx,
  // TEE republishing (phase 65): encryptedIpnsPrivateKey and keyEpoch not wired yet
});
```

Target — pass through teeKeys fields so new subfolders enroll in TEE renewal:
```typescript
await createAndPublishIpnsRecord({
  ipnsPrivateKey,
  ipnsName,
  metadataCid: cid,
  sequenceNumber: 1n,
  ctx: params.ctx,
  encryptedIpnsPrivateKey: params.teeKeys?.encryptedIpnsPrivateKey,
  keyEpoch: params.teeKeys?.keyEpoch,
});
```

**Planner verification:** trace `createAndPublishIpnsRecord` → `publishRecord` API call to confirm these params are forwarded through the SDK helper. RESEARCH.md open question 4 flags this as unverified.

---

### `tests/sdk-e2e/src/suites/tee-republish.test.ts` (test, event-driven — new file)

**Analog:** `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts`

**Test file structure pattern** (analog lines 1-57):
```typescript
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';
import { API_URL, testFetch } from '../fixtures/test-harness';
// ... domain imports

let fixture: MultiAccountFixture;

beforeAll(async () => {
  fixture = await createMultiAccountFixture(['alice']);
});

afterAll(async () => {
  if (fixture) await fixture.cleanupAll();
});

describe('suite name', () => {
  it('test name', async () => { ... }, 120_000);
});
```

**BullMQ trigger pattern** (RESEARCH.md Q1 + Pattern 3):
```typescript
import { Queue } from 'bullmq';

// Make schedule row due
await testDb.query(
  `UPDATE ipns_republish_schedule SET next_republish_at = NOW() - interval '1 second' WHERE ipns_name = $1`,
  [ipnsName]
);

// Enqueue one-shot job (NOT upsertJobScheduler which is for the repeating scheduler)
const queue = new Queue('republish', { connection: { host: 'localhost', port: 6380 } });
await queue.add('republish-batch', {});
await queue.close();
```

**Assertion pattern** (RESEARCH.md Pattern 3):
```typescript
// Poll for signedRecord change (renewed bytes differ due to new EOL, even at same seq)
await waitFor(async () => {
  const row = await testDb.query(`SELECT signed_record FROM ipns_records WHERE ipns_name = $1`, [ipnsName]);
  return !row.rows[0].signed_record.equals(originalSignedRecord);
}, { timeout: 10_000 });

const renewed = await parseIpnsRecord(renewedBytes);
const original = await parseIpnsRecord(originalBytes);
expect(renewed.sequence).toBe(original.sequence); // same seq (TEE-02)
expect(renewed.value).toBe(original.value);        // same CID (TEE-01)
expect(Buffer.from(renewedBytes).equals(Buffer.from(originalBytes))).toBe(false); // later EOL
```

**`bullmq` dependency check:** Verify `tests/sdk-e2e/package.json` has `bullmq`; add as devDependency if absent (RESEARCH.md open question 2).

**Tombstone test pattern** — verify tombstoned name never reaches TEE:
```typescript
it('tombstoned name is never re-signed forward', async () => {
  // ... publish, tombstone via API, make due, enqueue job
  const scheduleRow = await testDb.query(
    `SELECT status FROM ipns_republish_schedule WHERE ipns_name = $1`, [ipnsName]
  );
  // Phase-66 tombstoneRecord → republishService.unenrollIpns → row deleted
  expect(scheduleRow.rows).toHaveLength(0);
});
```

---

### `docker/docker-compose.yml` (config — add tee-worker service)

**Analog:** `docker/docker-compose.staging.yml:96-115`

**Staging reference block**:
```yaml
tee-worker:
  image: ghcr.io/${GITHUB_REPOSITORY_OWNER:-OWNER}/cipherbox-tee-worker:${TAG:-latest}
  restart: unless-stopped
  environment:
    PORT: 3001
    TEE_MODE: simulator
    CIPHERBOX_ENVIRONMENT: staging
    TEE_WORKER_SECRET: ${TEE_WORKER_SECRET}
```

**Local compose target block** (RESEARCH.md Q2, port-conflict-aware):
```yaml
  tee-worker:
    build:
      context: ../apps/tee-worker
      dockerfile: Dockerfile
    container_name: cipherbox-tee-worker
    restart: unless-stopped
    environment:
      PORT: 3001
      TEE_MODE: simulator
      CIPHERBOX_ENVIRONMENT: development
      TEE_WORKER_SECRET: ${TEE_WORKER_SECRET:-dev-secret}
    ports:
      - '127.0.0.1:3002:3001'   # 3001 is taken by mock-ipns-routing
    healthcheck:
      test: ['CMD-SHELL', 'wget -qO- http://localhost:3001/health || exit 1']
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.5'
```

**Required env change in API `.env`:** `TEE_WORKER_URL=http://localhost:3002` (default in `tee.service.ts:59` is `http://localhost:3001` which would hit mock-ipns-routing).

**Dockerfile check:** RESEARCH.md open question 3 — verify `apps/tee-worker/Dockerfile` exists; if absent, planner creates minimal one.

---

## Shared Patterns

### Key Zeroing (apply to all TEE worker service changes)

**Source:** `apps/tee-worker/src/routes/republish.ts:92-94` + `apps/tee-worker/src/services/key-manager.ts:29-31`

Pattern: zero IMMEDIATELY after last use; zero in `finally` for crypto keypair; zero in `catch` for caller-held keys; NEVER zero a caller-provided buffer (callee must not zero a reused buffer per memory note):
```typescript
// In finally block (keypair — callee owns it):
try { return await unwrapKey(encryptedIpnsKey, keypair.privateKey); }
finally { keypair.privateKey.fill(0); }

// In catch + after use (caller-owned, TEE route):
ipnsPrivateKey.fill(0);
ipnsPrivateKey = null;
```

### Equality CAS Shape (apply to `renewIpnsRecordEol`)

**Source:** `apps/api/src/ipns/ipns.service.ts:379-392`

The canonical Phase-66 CAS shape (fused: `sequence_number = :expected AND generation <= ... AND tombstoned_at IS NULL`) uses `createQueryBuilder().update().set().where().execute()`. The renewal CAS is a simplified subset:

```typescript
.where(
  'ipns_name = :ipnsName AND sequence_number = :expected AND tombstoned_at IS NULL',
  { ipnsName, expected: loadedSeq }
)
```

Same TypeORM idiom; check `result.affected === 0` for miss → log and discard (not an error).

### Migration Pattern (greenfield waiver)

**Source:** `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts:1-17`

Every Phase-67 migration follows: `MigrationInterface`, `name = 'ClassName<timestamp>'`, `up()` with raw SQL, `down()` throws with greenfield waiver message.

### sdk-e2e Test Harness (apply to new `tee-republish.test.ts`)

**Source:** `tests/sdk-e2e/src/fixtures/test-harness.ts` + `tests/sdk-e2e/src/fixtures/multi-account.ts`

Account setup: `createMultiAccountFixture(['alice'])` → `fixture.accounts.get('alice')` → `alice.client.getContext()`. DB access for make-due SQL: use the `testDb` pattern (check existing suites for the import; look for `pg` or `typeorm` direct connection in the harness).

### Logger Pattern (API services)

**Source:** `apps/api/src/republish/republish.service.ts:27`

```typescript
private readonly logger = new Logger(RepublishService.name);
```
NEVER log key material; log only `ipnsName`, epoch number, failure count.

---

## No Analog Found

All files in this phase have strong analogs. No files require falling back to RESEARCH.md patterns alone.

---

## Pitfalls Summary for Planner

| # | File | Pitfall | Avoidance |
|---|------|---------|-----------|
| P1 | `republish.ts` | `parsed.pubKey` undefined for Ed25519 identity records | Always use `publicKeyFromIpnsName(ipnsName)` for name↔key binding (never `parsed.pubKey`) |
| P2 | `republish.ts` | `verifyIpnsRecordSignature` rejects expired EOL | E2E test must publish fresh + trigger immediately; production 6h cycle keeps records fresh |
| P3 | `docker-compose.yml` | Port 3001 taken by mock-ipns-routing | Use `127.0.0.1:3002:3001` for tee-worker; set `TEE_WORKER_URL=http://localhost:3002` |
| P4 | `tee-republish.test.ts` | `upsertJobScheduler` does NOT immediately fire a job | Use `queue.add('republish-batch', {})` for one-shot trigger |
| P5 | `republish.service.ts` | `LessThanOrEqual` write-back allows seq regress under race | Replace with equality CAS `sequence_number = :loaded` in `renewIpnsRecordEol` |
| P6 | `republish.service.ts` | `enrollFolder` callers still pass 6 args after collapse | Update `enrollFolder` to 2-param AND update `ipns.service.ts:421-434` call site |
| P7 | `tee-keys.ts` | `EPOCH_ZERO_TIMESTAMP_MS` undefined → cannot clock-derive epoch | Add as env var with fallback to `1` (Option B from RESEARCH.md Q7) |

## Metadata

**Analog search scope:** `apps/tee-worker/src/`, `apps/api/src/republish/`, `apps/api/src/ipns/`, `apps/api/src/migrations/`, `packages/sdk-core/src/folder/`, `tests/sdk-e2e/src/`, `docker/`
**Files scanned:** 15
**Pattern extraction date:** 2026-07-01
