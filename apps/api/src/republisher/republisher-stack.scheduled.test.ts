import { randomBytes } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { fakeConfig } from '../testing/fakes';
import { minimalIpnsRecord } from '../testing/ipns-record';
import { sampleMetric } from '../testing/prometheus';
import { RoutingV1RecordTransport } from './record-transport';
import { MinimalIpnsSequenceReader } from './record-sequence-reader';

/**
 * The stack profile of the scheduled liveness tier (see vitest.scheduled.config.ts
 * for the tier). It talks only HTTP to the API process
 * `.github/workflows/scheduled-liveness.yml` boots, so the wiring, the SQL, and
 * the Prometheus counters an operator pages on are the shipped ones.
 */

const API_URL = process.env.SOAK_API_URL ?? 'http://localhost:3000';

/** The profile the API under soak runs; a wait sized from a different one proves nothing. */
function requiredProfileMs(name: string): number {
  const value = Number(process.env[name]);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(
      `${name} must carry the profile of the API under soak; got "${process.env[name]}"`
    );
  }
  return value;
}

const INTERVAL_MS = requiredProfileMs('REPUBLISHER_INTERVAL_MS');
const STALE_ALERT_MS = requiredProfileMs('REPUBLISHER_STALE_ALERT_MS');
const ROUTING_URL = process.env.ROUTING_V1_URL ?? '';

/** Whole-test bound; every wait below is a fraction of it. */
const TEST_TIMEOUT_MS = 180_000;
/** The gauges move once a sweep, so probing far below the cadence only costs scrapes. */
const METRICS_POLL_MS = Math.max(250, Math.floor(INTERVAL_MS / 4));
/** Recovery is rate-limited per account (30/min); stay well inside that. */
const RECOVERY_POLL_MS = 1_500;

/** A bare token the registry's `^[A-Za-z0-9]{1,128}$` name shape accepts. */
function soakToken(): string {
  return `soak${randomBytes(16).toString('hex')}`;
}

/**
 * The shipped `/routing/v1` byte mover, standing in for the key-holding client
 * that publishes a record — so the soak addresses the store exactly as the API
 * does, rather than through a second hand-rolled fetch.
 */
const store = new RoutingV1RecordTransport(fakeConfig({ ROUTING_V1_URL: ROUTING_URL }).service);

async function scrapeMetrics(): Promise<string> {
  const response = await fetch(`${API_URL}/metrics`);
  if (!response.ok) {
    throw new Error(`GET /metrics answered ${response.status}`);
  }
  return response.text();
}

/** Read one series out of an already-taken scrape, so a probe compares one instant. */
function seriesValue(exposition: string, name: string): number {
  const value = sampleMetric(exposition, name);
  if (value === null) {
    throw new Error(`no ${name} series in the exposition`);
  }
  return value;
}

/** Drop one name from the store, so the walk resolves it to absence from here on. */
async function forgetRecord(ipnsName: string): Promise<void> {
  const response = await fetch(`${ROUTING_URL}/forget/${ipnsName}`, { method: 'POST' });
  if (!response.ok) {
    throw new Error(`routing forget answered ${response.status} for ${ipnsName}`);
  }
}

async function testLogin(): Promise<string> {
  const response = await fetch(`${API_URL}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      handle: `${soakToken()}@cipherbox.invalid`,
      secret: process.env.TEST_LOGIN_SECRET ?? '',
    }),
  });
  if (!response.ok) {
    throw new Error(`POST /auth/test-login answered ${response.status}`);
  }
  const { accessToken } = (await response.json()) as { accessToken: string };
  return accessToken;
}

async function registerNames(token: string, names: string[]): Promise<void> {
  const response = await fetch(`${API_URL}/registry/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(names.map((ipnsName) => ({ ipnsName, contentCids: [] }))),
  });
  if (!response.ok) {
    throw new Error(`POST /registry/register answered ${response.status}`);
  }
}

/** The sequence the recovery endpoint currently serves for a name; null if uncached. */
async function cachedSequence(token: string, ipnsName: string): Promise<bigint | null> {
  const response = await fetch(`${API_URL}/recovery/${ipnsName}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`GET /recovery answered ${response.status} for ${ipnsName}`);
  }
  return new MinimalIpnsSequenceReader().read(Buffer.from(await response.arrayBuffer()));
}

describe('republisher liveness against the CI stack (compressed EOL)', () => {
  it(
    're-PUTs the inventory, renews a lease at seq+1, and alerts on a name starved past its window',
    async () => {
      expect(ROUTING_URL, 'ROUTING_V1_URL must address the store the API walks').not.toBe('');

      const token = await testLogin();
      const kept = soakToken();
      const starved = soakToken();

      // The store answers for both names BEFORE they enter the inventory, so the
      // first sweep to see them can resolve and re-PUT them.
      await store.republish(kept, minimalIpnsRecord(1n));
      await store.republish(starved, minimalIpnsRecord(1n));
      await registerNames(token, [kept, starved]);

      const inventory = await vi.waitFor(
        async () => {
          const exposition = await scrapeMetrics();
          const walked = seriesValue(exposition, 'republisher_last_walk_names');
          expect(walked).toBeGreaterThanOrEqual(2);
          expect(seriesValue(exposition, 'republisher_last_walk_republished')).toBe(walked);
          return walked;
        },
        { timeout: 8 * INTERVAL_MS, interval: METRICS_POLL_MS }
      );

      // Lease renewal: the key-holder republishes at seq+1, and the walk carries
      // the newer record forward rather than pinning the cache to the old one.
      await store.republish(kept, minimalIpnsRecord(2n));
      await vi.waitFor(
        async () => {
          expect(await cachedSequence(token, kept)).toBe(2n);
        },
        { timeout: 8 * INTERVAL_MS, interval: RECOVERY_POLL_MS }
      );

      const staleBefore = seriesValue(await scrapeMetrics(), 'republisher_stale_names_total');
      await forgetRecord(starved);

      await vi.waitFor(
        async () => {
          const exposition = await scrapeMetrics();
          // The alert the operator pages on, on the real counter.
          expect(seriesValue(exposition, 'republisher_stale_names_total')).toBeGreaterThan(
            staleBefore
          );
          // Measured against the inventory the sweep walks, not a fixed count, so
          // another name in the database cannot make this read true or false by
          // accident: exactly the starved one stopped being re-PUT.
          expect(seriesValue(exposition, 'republisher_last_walk_names')).toBe(inventory);
          expect(seriesValue(exposition, 'republisher_last_walk_republished')).toBe(inventory - 1);
        },
        { timeout: STALE_ALERT_MS + 8 * INTERVAL_MS, interval: METRICS_POLL_MS }
      );

      // Losing its liveness never cost the starved name its bytes — the cache is
      // the revival aid a key-holder mints a fresh record from.
      expect(await cachedSequence(token, starved)).toBe(1n);
      expect(await cachedSequence(token, kept)).toBe(2n);
    },
    TEST_TIMEOUT_MS
  );
});
