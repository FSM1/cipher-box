import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import { minimalIpnsRecord } from '../testing/ipns-record';
import { MinimalIpnsSequenceReader } from './record-sequence-reader';

/**
 * The compressed-EOL liveness profile against the CI stack (blueprint/deploy.md
 * scheduled tier): the shipped API process over real Postgres, a real Kubo, and
 * the real `/routing/v1` store. Its sibling `republisher.scheduled.test.ts`
 * drives months of virtual time through the walk in isolation; this one buys
 * what virtual time cannot — that the wiring, the SQL, and the Prometheus
 * counters an operator pages on are real.
 *
 * The stack compresses the cadence and the >24 h staleness window into seconds
 * (see `.github/workflows/scheduled-liveness.yml`), so a starved name reaches
 * the alert in bounded wall clock. The suite talks only HTTP — no in-process
 * seam, no fake clock — so what it asserts is what a deployment does.
 */

const API_URL = process.env.SOAK_API_URL ?? 'http://localhost:3000';
const ROUTING_URL = process.env.SOAK_ROUTING_URL ?? 'http://localhost:3001';
const LOGIN_SECRET = process.env.TEST_LOGIN_SECRET ?? '';
const INTERVAL_MS = Number(process.env.REPUBLISHER_INTERVAL_MS ?? 3000);
const STALE_ALERT_MS = Number(process.env.REPUBLISHER_STALE_ALERT_MS ?? 8000);

/** Whole-test bound; every wait below is a fraction of it. */
const TEST_TIMEOUT_MS = 180_000;
/** `/metrics` skips the throttler, so it can be polled at will. */
const METRICS_POLL_MS = 250;
/** Recovery is rate-limited per account (30/min); stay well inside that. */
const RECOVERY_POLL_MS = 1_500;

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';

/** A bare token the registry's `^[A-Za-z0-9]{1,128}$` name shape accepts. */
function soakName(): string {
  return `soak${randomBytes(16).toString('hex')}`;
}

async function poll<T>(
  what: string,
  budgetMs: number,
  everyMs: number,
  probe: () => Promise<T | null>
): Promise<T> {
  const deadline = Date.now() + budgetMs;
  let attempts = 0;
  for (;;) {
    const hit = await probe();
    if (hit !== null) {
      return hit;
    }
    attempts += 1;
    if (Date.now() >= deadline) {
      throw new Error(`${what}: not observed within ${budgetMs}ms (${attempts} probes)`);
    }
    await sleep(everyMs);
  }
}

/** One unlabelled Prometheus series from the live `/metrics` exposition. */
async function metric(name: string): Promise<number> {
  const response = await fetch(`${API_URL}/metrics`);
  if (!response.ok) {
    throw new Error(`GET /metrics answered ${response.status}`);
  }
  const line = (await response.text()).split('\n').find((l) => l.startsWith(`${name} `));
  return line === undefined ? 0 : Number(line.slice(name.length + 1));
}

async function putRecord(ipnsName: string, sequence: bigint): Promise<void> {
  const response = await fetch(`${ROUTING_URL}/routing/v1/ipns/${ipnsName}`, {
    method: 'PUT',
    headers: { 'Content-Type': IPNS_RECORD_MEDIA_TYPE },
    body: new Uint8Array(minimalIpnsRecord(sequence)),
  });
  if (!response.ok) {
    throw new Error(`routing PUT answered ${response.status} for ${ipnsName}`);
  }
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
      handle: `${soakName()}@cipherbox.invalid`,
      secret: LOGIN_SECRET,
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
      expect(LOGIN_SECRET, 'TEST_LOGIN_SECRET must be set for the soak stack').not.toBe('');

      const token = await testLogin();
      const kept = soakName();
      const starved = soakName();

      // The store answers for both names BEFORE they enter the inventory, so the
      // first sweep to see them can resolve and re-PUT them.
      await putRecord(kept, 1n);
      await putRecord(starved, 1n);
      await registerNames(token, [kept, starved]);

      // The walk found the whole inventory and kept every name alive.
      await poll(
        'the first sweep re-PUTs both names',
        8 * INTERVAL_MS,
        METRICS_POLL_MS,
        async () => {
          const walked = await metric('republisher_last_walk_names');
          const republished = await metric('republisher_last_walk_republished');
          return walked >= 2 && republished >= 2 ? true : null;
        }
      );

      // Lease renewal: the key-holder republishes at seq+1, and the walk carries
      // the newer record forward rather than pinning the cache to the old one.
      await putRecord(kept, 2n);
      await poll(
        'the renewed record at seq+1 reaches the cache',
        8 * INTERVAL_MS,
        RECOVERY_POLL_MS,
        async () => {
          const sequence = await cachedSequence(token, kept);
          return sequence === 2n ? true : null;
        }
      );

      // Starve one name: the store forgets it, so every later sweep resolves it
      // to absence and its last successful re-PUT stops moving.
      const staleBefore = await metric('republisher_stale_names_total');
      const failuresBefore = await metric('republisher_resolve_failures_total');
      await forgetRecord(starved);

      // Past the compressed window it raises the >24h-no-re-PUT alert on the real
      // counter, while the sweep still re-PUTs the name that is still answering.
      await poll(
        'the starved name raises a staleness alert',
        STALE_ALERT_MS + 8 * INTERVAL_MS,
        METRICS_POLL_MS,
        async () => {
          const stale = await metric('republisher_stale_names_total');
          const walked = await metric('republisher_last_walk_names');
          const republished = await metric('republisher_last_walk_republished');
          return stale > staleBefore && walked === 2 && republished === 1 ? true : null;
        }
      );

      expect(await metric('republisher_resolve_failures_total')).toBeGreaterThan(failuresBefore);
      // The starved name never lost its bytes — the cache is the revival aid.
      expect(await cachedSequence(token, starved)).toBe(1n);
      // And the live name never decayed.
      expect(await cachedSequence(token, kept)).toBe(2n);
    },
    TEST_TIMEOUT_MS
  );
});
