import { describe, expect, it } from 'vitest';
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

interface CacheRow {
  record: Buffer;
  sequence: bigint;
  lastRepublishedAt: Date | null;
  createdAt: Date;
}

/** In-memory cache mirroring RecordCacheService's monotonic semantics. */
class FakeRecordCache {
  readonly rows = new Map<string, CacheRow>();

  seed(name: string, row: CacheRow): void {
    this.rows.set(name, row);
  }

  async upsert(name: string, rec: Buffer, sequence: bigint, now: Date): Promise<CacheUpsertResult> {
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

/** Recording alerter capturing every alert for assertions. */
class RecordingAlerter extends RepublisherAlerter {
  resolveFailures: string[] = [];
  staleAlerts: { name: string; ageMs: number }[] = [];
  walks: { names: number; republished: number }[] = [];

  resolveFailure(name: string): void {
    this.resolveFailures.push(name);
  }
  staleRepublish(name: string, ageMs: number): void {
    this.staleAlerts.push({ name, ageMs });
  }
  walkComplete(names: number, republished: number): void {
    this.walks.push({ names, republished });
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
  transport: FakeTransport;
  alerter: RecordingAlerter;
  clock: FakeClock;
  staleAlertMs?: number;
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
});
