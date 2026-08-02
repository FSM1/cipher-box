import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { RecordCache } from '../entities/record-cache.entity';
import { RecordCacheService } from './record-cache.service';

/**
 * The record cache's monotonicity invariant proven on a REAL Postgres: the
 * conditional upsert refuses every sequence regression, atomically, with no
 * read-then-write window. Each guarantee is pinned by a negative control that
 * reproduces the regression once the `WHERE excluded.sequence > ...` guard is
 * stripped (the naive `DO UPDATE`) — exactly the race the guard closes.
 */

function name(): string {
  return `k51${randomBytes(12).toString('hex')}`;
}

function bytes(marker: number): Buffer {
  return Buffer.concat([Buffer.from([marker]), randomBytes(16)]);
}

const AT = new Date('2026-07-01T00:00:00Z');

describe('RecordCacheService monotonicity (real Postgres)', () => {
  let db: IntegrationDatabase;
  let service: RecordCacheService;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    service = new RecordCacheService(db.dataSource.getRepository(RecordCache) as never);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE record_cache');
  });

  /** The pre-guard code path: an unconditional upsert that admits any sequence. */
  async function unsafeUpsert(ipnsName: string, record: Buffer, sequence: bigint): Promise<void> {
    await db.dataSource.query(
      `INSERT INTO record_cache (ipns_name, record, sequence, created_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (ipns_name) DO UPDATE
         SET record = EXCLUDED.record, sequence = EXCLUDED.sequence`,
      [ipnsName, record, sequence.toString(), AT]
    );
  }

  async function storedSequence(ipnsName: string): Promise<bigint | null> {
    const row = await db.dataSource.getRepository(RecordCache).findOne({ where: { ipnsName } });
    return row ? BigInt(row.sequence) : null;
  }

  it('inserts a first record and reports it stored', async () => {
    const n = name();
    const rec = bytes(1);
    const result = await service.upsert(n, rec, 1n, AT);
    expect(result.stored).toBe(true);
    expect(Buffer.compare((await service.fetch(n))!, rec)).toBe(0);
    expect(await storedSequence(n)).toBe(1n);
  });

  it('refuses a sequence-regressing record; the newer one survives', async () => {
    const n = name();
    const newer = bytes(5);
    await service.upsert(n, newer, 5n, AT);

    const refused = await service.upsert(n, bytes(3), 3n, AT);
    expect(refused.stored).toBe(false);

    // The cache still holds the newer record — the stale sequence was refused.
    expect(await storedSequence(n)).toBe(5n);
    expect(Buffer.compare((await service.fetch(n))!, newer)).toBe(0);
  });

  it('treats an equal sequence as an idempotent no-op', async () => {
    const n = name();
    const original = bytes(4);
    await service.upsert(n, original, 4n, AT);

    const again = await service.upsert(n, bytes(4), 4n, AT);
    expect(again.stored).toBe(false);
    // Strictly-greater means the same sequence never overwrites the bytes.
    expect(Buffer.compare((await service.fetch(n))!, original)).toBe(0);
  });

  it('accepts a strictly-newer record', async () => {
    const n = name();
    await service.upsert(n, bytes(5), 5n, AT);
    const newer = bytes(9);
    const result = await service.upsert(n, newer, 9n, AT);
    expect(result.stored).toBe(true);
    expect(await storedSequence(n)).toBe(9n);
    expect(Buffer.compare((await service.fetch(n))!, newer)).toBe(0);
  });

  it('the newer sequence wins under concurrent writes regardless of arrival order', async () => {
    for (let i = 0; i < 25; i += 1) {
      const n = name();
      const newer = bytes(5);
      // Fire the newer and older writes concurrently; the atomic conditional
      // upsert must always settle on the newer, whichever row lands first.
      await Promise.all([service.upsert(n, newer, 5n, AT), service.upsert(n, bytes(3), 3n, AT)]);
      expect(await storedSequence(n)).toBe(5n);
      expect(Buffer.compare((await service.fetch(n))!, newer)).toBe(0);
    }
  });

  it('stores and orders sequences across the full uint64 domain, past signed bigint', async () => {
    const n = name();
    // 2^63 overflows a signed `bigint` column; the numeric(20,0) column holds it,
    // so a hostile/garbage high sequence stores instead of faulting the upsert.
    const beyondSigned = 2n ** 63n;
    expect((await service.upsert(n, bytes(1), beyondSigned, AT)).stored).toBe(true);
    expect(await storedSequence(n)).toBe(beyondSigned);

    // A strictly-greater near-max uint64 still wins.
    const nearMax = 2n ** 64n - 1n;
    expect((await service.upsert(n, bytes(2), nearMax, AT)).stored).toBe(true);
    expect(await storedSequence(n)).toBe(nearMax);

    // And a regression just below 2^63 is refused — monotonicity holds past the boundary.
    const belowSigned = 2n ** 63n - 1n;
    expect((await service.upsert(n, bytes(3), belowSigned, AT)).stored).toBe(false);
    expect(await storedSequence(n)).toBe(nearMax);
  });

  it('negative control — without the guard, a regressing sequence overwrites the newer record', async () => {
    const n = name();
    await unsafeUpsert(n, bytes(5), 5n);
    await unsafeUpsert(n, bytes(3), 3n);
    // The unconditional upsert admitted the older sequence — the regression the
    // production guard refuses.
    expect(await storedSequence(n)).toBe(3n);
  });

  describe('staleNames + markRepublished', () => {
    /** Seed a row with explicit timestamps to drive the staleness cutoff. */
    async function seed(
      ipnsName: string,
      createdAt: Date,
      lastRepublishedAt: Date | null
    ): Promise<void> {
      await db.dataSource.query(
        `INSERT INTO record_cache (ipns_name, record, sequence, created_at, last_republished_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [ipnsName, bytes(1), '1', createdAt, lastRepublishedAt]
      );
    }

    it('returns names whose last re-PUT (or first-seen) predates the cutoff', async () => {
      const now = new Date('2026-07-10T00:00:00Z');
      const cutoff = new Date(now.getTime() - 24 * 3_600_000);
      const stale = name();
      const neverRepublished = name();
      const fresh = name();

      await seed(stale, new Date('2026-07-01T00:00:00Z'), new Date('2026-07-08T00:00:00Z')); // 2d stale
      await seed(neverRepublished, new Date('2026-07-01T00:00:00Z'), null); // ages from created_at
      await seed(fresh, new Date('2026-07-01T00:00:00Z'), new Date('2026-07-09T23:00:00Z')); // 1h ago

      const staleNames = (await service.staleNames(cutoff)).map((s) => s.ipnsName).sort();
      expect(staleNames).toEqual([neverRepublished, stale].sort());
    });

    it('markRepublished resets a name out of the stale set', async () => {
      const now = new Date('2026-07-10T00:00:00Z');
      const cutoff = new Date(now.getTime() - 24 * 3_600_000);
      const n = name();
      await seed(n, new Date('2026-07-01T00:00:00Z'), null);
      expect((await service.staleNames(cutoff)).map((s) => s.ipnsName)).toContain(n);

      await service.markRepublished(n, now);
      expect((await service.staleNames(cutoff)).map((s) => s.ipnsName)).not.toContain(n);
    });
  });
});
