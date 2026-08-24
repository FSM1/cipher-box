import { describe, expect, it } from 'vitest';
import { FakeClock, fakeConfig } from '../testing/fakes';
import { minimalIpnsRecord } from '../testing/ipns-record';
import { MinimalIpnsSequenceReader } from './record-sequence-reader';
import { RecordTransport } from './record-transport';
import { RepublisherAlerter } from './republisher.alerter';
import { RepublisherTask } from './republisher.task';
import type { CacheUpsertResult } from './services/record-cache.service';

/**
 * The compressed-EOL long-horizon run (blueprint/testing.md scheduled tier). It
 * drives the republisher walk over months of VIRTUAL time at a compressed
 * cadence — no real clock, no network — to prove two liveness properties end to
 * end: a walked name is re-PUT every cadence so it never decays past its EOL,
 * and an abandoned name goes stale (alerts) yet its last record stays fetchable
 * from the non-canonical cache as the post-EOL revival aid.
 *
 * Scheduled-only (excluded from the PR unit + integration configs): it is a
 * long-horizon soak, not a per-PR blocking gate.
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

interface CacheRow {
  record: Buffer;
  sequence: bigint;
  lastRepublishedAt: Date | null;
  createdAt: Date;
}

class FakeRecordCache {
  readonly rows = new Map<string, CacheRow>();
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

class HorizonTransport extends RecordTransport {
  republishedCounts = new Map<string, number>();
  constructor(private readonly canRepublish: (name: string) => boolean) {
    super();
  }
  async resolve(_name: string): Promise<Buffer | null> {
    return minimalIpnsRecord(1n); // the record is EOL-stable; only re-PUT keeps it live
  }
  async republish(name: string, _record: Buffer): Promise<void> {
    if (!this.canRepublish(name)) throw new Error('re-PUT failed');
    this.republishedCounts.set(name, (this.republishedCounts.get(name) ?? 0) + 1);
  }
}

class RecordingAlerter extends RepublisherAlerter {
  staleAlerts: { name: string; ageMs: number }[] = [];
  resolveFailure(): void {}
  staleRepublish(name: string, ageMs: number): void {
    this.staleAlerts.push({ name, ageMs });
  }
  walkComplete(): void {}
  walkSkipped(): void {}
}

function fakeNameRepo(names: string[]): never {
  return {
    createQueryBuilder: () => ({
      select: () => ({ getRawMany: async () => names.map((ipns_name) => ({ ipns_name })) }),
    }),
  } as never;
}

describe('republisher long-horizon liveness (compressed EOL)', () => {
  it('keeps a walked name live across a horizon far past its EOL, and preserves an abandoned name for recovery', async () => {
    const cadenceMs = 12 * HOUR;
    const horizonDays = 60; // well past the 5-day compressed EOL below
    const compressedEolMs = 5 * DAY;
    const abandonAtDay = 10;

    const clock = new FakeClock(new Date('2026-01-01T00:00:00Z'));
    const cache = new FakeRecordCache();
    const alerter = new RecordingAlerter();

    // 'abandoned' stops being re-PUT once the clock passes day 10; 'kept' always
    // succeeds. The predicate reads the live clock each step.
    const abandonAt = new Date('2026-01-01T00:00:00Z').getTime() + abandonAtDay * DAY;
    const liveTransport = new HorizonTransport(
      (name) => name !== 'abandoned' || clock.now().getTime() < abandonAt
    );

    const task = new RepublisherTask(
      fakeNameRepo(['kept', 'abandoned']),
      cache as never,
      liveTransport,
      new MinimalIpnsSequenceReader(),
      alerter,
      clock,
      fakeConfig({ REPUBLISHER_STALE_ALERT_MS: String(DAY) }).service
    );

    const steps = (horizonDays * DAY) / cadenceMs;
    let lastKeptRepublishAt = 0;
    for (let i = 0; i < steps; i += 1) {
      clock.advanceMs(cadenceMs);
      await task.runOnce();
      lastKeptRepublishAt = clock.now().getTime();
    }

    // 'kept' was re-PUT every single cadence — it never decays past its EOL.
    expect(liveTransport.republishedCounts.get('kept')).toBe(steps);
    expect(cache.rows.get('kept')?.lastRepublishedAt?.getTime()).toBe(lastKeptRepublishAt);
    // Its liveness never triggered a staleness alert.
    expect(alerter.staleAlerts.filter((a) => a.name === 'kept')).toHaveLength(0);

    // 'abandoned' stopped being re-PUT at day 10 and went stale within a day.
    expect(alerter.staleAlerts.some((a) => a.name === 'abandoned')).toBe(true);
    const firstStale = alerter.staleAlerts.find((a) => a.name === 'abandoned')!;
    expect(firstStale.ageMs).toBeGreaterThanOrEqual(DAY);

    // Even long past its EOL, its last record is still served from the cache —
    // the revival aid a key-holder uses to mint a fresh record.
    const survived = await cache.fetch('abandoned');
    expect(survived).not.toBeNull();
    expect(Buffer.compare(survived!, minimalIpnsRecord(1n))).toBe(0);
    expect(compressedEolMs).toBeLessThan(horizonDays * DAY); // the horizon truly exceeds EOL
  });
});
