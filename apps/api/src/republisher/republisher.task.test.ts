import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FakeClock, fakeConfig } from '../testing/fakes';
import { MinimalIpnsSequenceReader } from './record-sequence-reader';
import { RecordTransport } from './record-transport';
import { RepublisherAlerter } from './republisher.alerter';
import { RepublisherTask } from './republisher.task';
import type { CacheUpsertResult } from './services/record-cache.service';

const HOUR = 3_600_000;

/** Build an IPNS-record-shaped byte string carrying only the sequence field (5). */
function record(sequence: bigint): Buffer {
  const tag = (5 << 3) | 0;
  const bytes: number[] = [tag];
  let v = sequence;
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    bytes.push(byte);
  } while (v > 0n);
  return Buffer.from(bytes);
}

/** A well-formed record carrying NO sequence field — the reader returns null. */
function recordWithoutSequence(): Buffer {
  // A length-delimited field 1 (`value`) only; field 5 (`sequence`) is absent.
  const payload = Buffer.from('value-cid-bytes');
  return Buffer.concat([Buffer.from([(1 << 3) | 2, payload.length]), payload]);
}

interface CacheRow {
  record: Buffer;
  sequence: bigint;
  lastRepublishedAt: Date | null;
  createdAt: Date;
}

/** In-memory cache mirroring RecordCacheService's monotonic semantics. */
class FakeRecordCache {
  readonly rows = new Map<string, CacheRow>();
  /** Names whose `upsert` rejects — models a transient per-name DB failure. */
  readonly upsertThrows = new Set<string>();

  seed(name: string, row: CacheRow): void {
    this.rows.set(name, row);
  }

  async upsert(name: string, rec: Buffer, sequence: bigint, now: Date): Promise<CacheUpsertResult> {
    if (this.upsertThrows.has(name)) throw new Error('cache upsert failed');
    const existing = this.rows.get(name);
    if (!existing) {
      this.rows.set(name, { record: rec, sequence, lastRepublishedAt: null, createdAt: now });
      return { stored: true };
    }
    if (sequence > existing.sequence) {
      existing.record = rec;
      existing.sequence = sequence;
      return { stored: true };
    }
    return { stored: false };
  }

  async markRepublished(name: string, now: Date): Promise<void> {
    const row = this.rows.get(name);
    if (row) row.lastRepublishedAt = now;
  }

  async staleNames(cutoff: Date): Promise<{ ipnsName: string; baseline: Date }[]> {
    const out: { ipnsName: string; baseline: Date }[] = [];
    for (const [ipnsName, row] of this.rows) {
      const baseline = row.lastRepublishedAt ?? row.createdAt;
      if (baseline < cutoff) out.push({ ipnsName, baseline });
    }
    return out;
  }

  async fetch(name: string): Promise<Buffer | null> {
    return this.rows.get(name)?.record ?? null;
  }
}

/** Fake transport with per-name resolve answers and re-PUT outcomes. */
class FakeTransport extends RecordTransport {
  resolveAnswers = new Map<string, Buffer | null | 'throw'>();
  republishFailures = new Set<string>();
  republished: string[] = [];
  isConfigured = true;

  override get configured(): boolean {
    return this.isConfigured;
  }

  async resolve(name: string): Promise<Buffer | null> {
    const answer = this.resolveAnswers.get(name);
    if (answer === 'throw') throw new Error('transport down');
    return answer ?? null;
  }

  async republish(name: string, _record: Buffer): Promise<void> {
    if (this.republishFailures.has(name)) throw new Error('re-PUT failed');
    this.republished.push(name);
  }
}

/** Transport that delays each resolve so a sweep's live concurrency is observable. */
class ConcurrencyTransport extends RecordTransport {
  inFlight = 0;
  maxInFlight = 0;
  republished: string[] = [];

  constructor(private readonly delayMs: number) {
    super();
  }

  async resolve(_name: string): Promise<Buffer | null> {
    this.inFlight += 1;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    this.inFlight -= 1;
    return record(1n);
  }

  async republish(name: string, _record: Buffer): Promise<void> {
    this.republished.push(name);
  }
}

/** Recording alerter capturing every alert for assertions. */
class RecordingAlerter extends RepublisherAlerter {
  resolveFailures: string[] = [];
  staleAlerts: { name: string; ageMs: number }[] = [];
  walks: { names: number; republished: number }[] = [];
  walkSkips = 0;

  resolveFailure(name: string): void {
    this.resolveFailures.push(name);
  }
  staleRepublish(name: string, ageMs: number): void {
    this.staleAlerts.push({ name, ageMs });
  }
  walkComplete(names: number, republished: number): void {
    this.walks.push({ names, republished });
  }
  walkSkipped(): void {
    this.walkSkips += 1;
  }
}

/** A name-inventory repo stub exposing only the distinct-name query the task uses. */
function fakeNameRepo(names: string[]): never {
  const distinct = [...new Set(names)];
  return {
    createQueryBuilder: () => ({
      select: () => ({
        getRawMany: async () => distinct.map((ipns_name) => ({ ipns_name })),
      }),
    }),
  } as never;
}

function buildTask(opts: {
  names: string[];
  cache: FakeRecordCache;
  transport: RecordTransport;
  alerter: RecordingAlerter;
  clock: FakeClock;
  staleAlertMs?: number;
  concurrency?: number;
}): RepublisherTask {
  return new RepublisherTask(
    fakeNameRepo(opts.names),
    opts.cache as never,
    opts.transport,
    new MinimalIpnsSequenceReader(),
    opts.alerter,
    opts.clock,
    fakeConfig({
      REPUBLISHER_STALE_ALERT_MS: String(opts.staleAlertMs ?? 24 * HOUR),
      REPUBLISHER_CONCURRENCY: opts.concurrency ? String(opts.concurrency) : undefined,
    }).service
  );
}

describe('RepublisherTask walk', () => {
  it('resolves, caches, and re-PUTs every distinct name', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const alerter = new RecordingAlerter();
    const clock = new FakeClock();
    transport.resolveAnswers.set('name-a', record(1n));
    transport.resolveAnswers.set('name-b', record(1n));

    await buildTask({ names: ['name-a', 'name-b'], cache, transport, alerter, clock }).runOnce();

    expect(transport.republished.sort()).toEqual(['name-a', 'name-b']);
    expect(cache.rows.get('name-a')?.lastRepublishedAt).toEqual(clock.now());
    expect(alerter.resolveFailures).toEqual([]);
    expect(alerter.walks).toEqual([{ names: 2, republished: 2 }]);
    expect(alerter.walkSkips).toBe(0);
  });

  it('alerts a resolve failure for an unresolvable name and never re-PUTs it', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const alerter = new RecordingAlerter();
    transport.resolveAnswers.set('orphan', null); // registered-never-published orphan
    transport.resolveAnswers.set('unreachable', 'throw'); // transport-level failure
    transport.resolveAnswers.set('live', record(1n));

    await buildTask({
      names: ['orphan', 'unreachable', 'live'],
      cache,
      transport,
      alerter,
      clock: new FakeClock(),
    }).runOnce();

    expect(alerter.resolveFailures.sort()).toEqual(['orphan', 'unreachable']);
    expect(transport.republished).toEqual(['live']);
    expect(cache.rows.has('orphan')).toBe(false);
  });

  // Per-name isolation (Greptile P1): a cache op that rejects for one name must
  // not reject the pool and abandon the rest — the remaining inventory is still
  // re-PUT, and the failing name is counted through the resolve-failure path.
  it('isolates a cache failure to one name and still processes the rest', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const alerter = new RecordingAlerter();
    const clock = new FakeClock();
    cache.upsertThrows.add('boom');
    transport.resolveAnswers.set('boom', record(1n));
    transport.resolveAnswers.set('name-a', record(1n));
    transport.resolveAnswers.set('name-b', record(1n));

    await buildTask({
      names: ['boom', 'name-a', 'name-b'],
      cache,
      transport,
      alerter,
      clock,
    }).runOnce();

    // The failing name never re-PUTs and is counted as a failure...
    expect(transport.republished).not.toContain('boom');
    expect(alerter.resolveFailures).toEqual(['boom']);
    // ...while the healthy names are still re-PUT and stamped.
    expect(transport.republished.sort()).toEqual(['name-a', 'name-b']);
    expect(cache.rows.get('name-a')?.lastRepublishedAt).toEqual(clock.now());
    expect(cache.rows.get('name-b')?.lastRepublishedAt).toEqual(clock.now());
    // The sweep completed cleanly and reported the two successes.
    expect(alerter.walks).toEqual([{ names: 3, republished: 2 }]);
  });

  it('refuses a sequence-regressing resolve but keeps re-PUTting for liveness', async () => {
    const cache = new FakeRecordCache();
    const clock = new FakeClock();
    cache.seed('name', {
      record: record(5n),
      sequence: 5n,
      lastRepublishedAt: clock.now(),
      createdAt: clock.now(),
    });
    const transport = new FakeTransport();
    transport.resolveAnswers.set('name', record(3n)); // older than cached seq 5

    await buildTask({
      names: ['name'],
      cache,
      transport,
      alerter: new RecordingAlerter(),
      clock,
    }).runOnce();

    // The cache kept seq 5; the stale network answer did not regress it, but the
    // bytes were still re-PUT (liveness is independent of the cache decision).
    expect(cache.rows.get('name')?.sequence).toBe(5n);
    expect(transport.republished).toEqual(['name']);
  });

  it('stores a strictly-newer resolved record', async () => {
    const cache = new FakeRecordCache();
    const clock = new FakeClock();
    cache.seed('name', {
      record: record(5n),
      sequence: 5n,
      lastRepublishedAt: clock.now(),
      createdAt: clock.now(),
    });
    const transport = new FakeTransport();
    transport.resolveAnswers.set('name', record(7n));

    await buildTask({
      names: ['name'],
      cache,
      transport,
      alerter: new RecordingAlerter(),
      clock,
    }).runOnce();

    expect(cache.rows.get('name')?.sequence).toBe(7n);
  });

  it('alerts a name >24h without a successful re-PUT and resets on success', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const alerter = new RecordingAlerter();
    const clock = new FakeClock();

    // A name last re-PUT 25h ago whose re-PUT keeps failing this sweep.
    const stalePast = new Date(clock.now().getTime() - 25 * HOUR);
    cache.seed('stale', {
      record: record(2n),
      sequence: 2n,
      lastRepublishedAt: stalePast,
      createdAt: stalePast,
    });
    transport.resolveAnswers.set('stale', record(2n));
    transport.republishFailures.add('stale');

    // A healthy name that re-PUTs fine this sweep.
    transport.resolveAnswers.set('fresh', record(1n));

    await buildTask({ names: ['stale', 'fresh'], cache, transport, alerter, clock }).runOnce();

    expect(alerter.staleAlerts).toHaveLength(1);
    expect(alerter.staleAlerts[0].name).toBe('stale');
    expect(alerter.staleAlerts[0].ageMs).toBe(25 * HOUR);

    // The fresh name re-PUT successfully, so it is not stale.
    expect(alerter.staleAlerts.map((a) => a.name)).not.toContain('fresh');
  });

  it('does not alert a name comfortably within the staleness window', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const alerter = new RecordingAlerter();
    const clock = new FakeClock();
    transport.resolveAnswers.set('name', record(1n));

    await buildTask({ names: ['name'], cache, transport, alerter, clock }).runOnce();

    expect(alerter.staleAlerts).toEqual([]);
  });

  // G2: a re-PUT name whose sequence is unreadable must still be cached so
  // recovery can serve it and staleness can cover it — never a silent 0-row
  // markRepublished. It caches at the floor 0; a later real record wins.
  it('caches a re-PUT record even when its sequence is unreadable', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const alerter = new RecordingAlerter();
    const clock = new FakeClock();
    transport.resolveAnswers.set('seqless', recordWithoutSequence());

    await buildTask({ names: ['seqless'], cache, transport, alerter, clock }).runOnce();

    // Cached (recovery can fetch it) and stamped re-PUT (not a 0-row no-op).
    const row = cache.rows.get('seqless');
    expect(row?.sequence).toBe(0n);
    expect(row?.lastRepublishedAt).toEqual(clock.now());
    expect(transport.republished).toEqual(['seqless']);
  });

  it('lets a later real record (seq ≥ 1) overwrite a floored placeholder', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    const clock = new FakeClock();
    transport.resolveAnswers.set('name', recordWithoutSequence());
    await buildTask({
      names: ['name'],
      cache,
      transport,
      alerter: new RecordingAlerter(),
      clock,
    }).runOnce();
    expect(cache.rows.get('name')?.sequence).toBe(0n);

    transport.resolveAnswers.set('name', record(1n));
    await buildTask({
      names: ['name'],
      cache,
      transport,
      alerter: new RecordingAlerter(),
      clock,
    }).runOnce();
    expect(cache.rows.get('name')?.sequence).toBe(1n);
  });

  // G3: no routing endpoint (BYO-only deploy) → the walk is a no-op, never an
  // every-name resolve-failure alert storm.
  it('skips the walk without alerting when the transport is not configured', async () => {
    const cache = new FakeRecordCache();
    const transport = new FakeTransport();
    transport.isConfigured = false;
    const alerter = new RecordingAlerter();
    transport.resolveAnswers.set('name-a', record(1n));

    await buildTask({
      names: ['name-a', 'name-b', 'name-c'],
      cache,
      transport,
      alerter,
      clock: new FakeClock(),
    }).runOnce();

    expect(alerter.walkSkips).toBe(1);
    expect(alerter.resolveFailures).toEqual([]);
    expect(alerter.walks).toEqual([]);
    expect(transport.republished).toEqual([]);
    expect(cache.rows.size).toBe(0);
  });

  // G5: names walk through a bounded pool so one slow name can't serialize the
  // sweep; live concurrency never exceeds the cap and all names still process.
  describe('bounded concurrency', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    it('caps in-flight names at the configured concurrency and processes all', async () => {
      const cache = new FakeRecordCache();
      const transport = new ConcurrencyTransport(10);
      const names = ['a', 'b', 'c', 'd', 'e'];
      const task = buildTask({
        names,
        cache,
        transport,
        alerter: new RecordingAlerter(),
        clock: new FakeClock(),
        concurrency: 2,
      });

      const done = task.runOnce();
      await vi.advanceTimersByTimeAsync(100);
      await done;

      expect(transport.maxInFlight).toBe(2); // never more than the cap
      expect(transport.republished.sort()).toEqual([...names].sort());
    });

    it('runs every name concurrently when the cap exceeds the name count', async () => {
      const cache = new FakeRecordCache();
      const transport = new ConcurrencyTransport(10);
      const names = ['a', 'b', 'c'];
      const task = buildTask({
        names,
        cache,
        transport,
        alerter: new RecordingAlerter(),
        clock: new FakeClock(),
        concurrency: 8,
      });

      const done = task.runOnce();
      await vi.advanceTimersByTimeAsync(100);
      await done;

      expect(transport.maxInFlight).toBe(3); // bounded by name count, not the cap
    });
  });
});
