/**
 * TEE lease-renewer round-trip suite (TEE-01, TEE-02, TEE-06 tombstone) — Phase 67.
 *
 * Two behavior cases exercised against the live API + migrated schedule-collapse schema:
 *   Test A (equal-seq / equal-CID / later-EOL): Enroll a record with TEE keys; make its
 *     schedule row due via a direct DB write; enqueue ONE 'republish-batch' job on the
 *     real BullMQ 'republish' queue (redis:6380); poll ipns_records.signed_record until it
 *     differs; assert renewed.sequence === original.sequence (no increment), renewed.value ===
 *     original.value (same CID), and the renewed bytes differ (later EOL).
 *   Test B (tombstone never re-signed): Enroll a second record with TEE keys; tombstone the
 *     name via POST /ipns/tombstone; assert ipns_republish_schedule row is absent (unenrolled
 *     by tombstone handler); enqueue ONE job; assert the signed_record is unchanged.
 *
 * These two cases need the live stack because they exercise the real relay→TEE→DB round-trip.
 * The determinism is fully test-owned: no timer/scheduler wait; exactly ONE BullMQ job per test.
 *
 * Prerequisites (live local stack):
 *   docker compose -f docker/docker-compose.yml up -d   (redis 6380, kubo, postgres, tee-worker)
 *   pnpm --filter @cipherbox/api dev                    (API on :3000, TEE_WORKER_URL=http://localhost:3002)
 *   pnpm --filter @cipherbox/api migration:run          (ScheduleCollapse1751000000000 applied)
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Queue } from 'bullmq';
import pg from 'pg';
import { parseIpnsRecord, deriveEd25519PublicKey, deriveIpnsName } from '@cipherbox/crypto';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';
import { API_URL, testFetch } from '../fixtures/test-harness';
import { createSubfolder } from '@cipherbox/sdk-core';

// ---------------------------------------------------------------------------
// DB + queue connection settings (mirrors API data-source.ts defaults)
// ---------------------------------------------------------------------------

const DB_CONFIG: pg.PoolConfig = {
  host: process.env.DB_HOST ?? 'localhost',
  port: parseInt(process.env.DB_PORT ?? '5432', 10),
  user: process.env.DB_USERNAME ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
  database: process.env.DB_DATABASE ?? 'cipherbox',
};

const REDIS_CONFIG = {
  host: process.env.REDIS_HOST ?? 'localhost',
  port: parseInt(process.env.REDIS_PORT ?? '6380', 10),
};

// ---------------------------------------------------------------------------
// Shared fixture + DB pool
// ---------------------------------------------------------------------------

let fixture: MultiAccountFixture;
let pool: pg.Pool;

// This suite drives the real relay→TEE→DB→BullMQ lease-renew round-trip, which needs the
// LOCAL live stack: the TEE worker on :3002, the `cipherbox` DB, and redis. CI's sdk-e2e
// job provisions none of those (it uses `cipherbox_test` and runs no TEE worker), so gate
// the suite — and its module-level beforeAll DB query — to local runs. This is the
// documented local publish gate (see project-tee-republish-e2e-stack-recipe).
const SKIP_TEE_LIVE = !!process.env.CI;

beforeAll(async () => {
  if (SKIP_TEE_LIVE) return;
  fixture = await createMultiAccountFixture(['alice', 'bob']);
  pool = new pg.Pool(DB_CONFIG);

  // Guard (T-67-08-T): assert the schedule-collapse migration is applied — the four
  // signing-input columns MUST be absent. The round-trip below would still pass against
  // an un-migrated DB (the dropped columns would merely sit unused), so without this
  // check the suite could green on a stale schema. Fail loudly instead.
  const { rows } = await pool.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns
     WHERE table_name = 'ipns_republish_schedule'
       AND column_name IN ('encrypted_ipns_key', 'key_epoch', 'latest_cid', 'sequence_number')`
  );
  if (rows.length > 0) {
    throw new Error(
      `ScheduleCollapse migration not applied — ipns_republish_schedule still has signing ` +
        `columns: ${rows.map((r) => r.column_name).join(', ')}. ` +
        `Run: DB_DATABASE=cipherbox pnpm --filter @cipherbox/api migration:run`
    );
  }
});

afterAll(async () => {
  if (fixture) await fixture.cleanupAll();
  if (pool) await pool.end();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Read the TEE public key + current epoch from tee_key_state.
 * Returns an object compatible with the TeeKeys type expected by createSubfolder.
 */
async function readTeeKeys(): Promise<{ currentPublicKey: string; currentEpoch: number }> {
  const result = await pool.query<{ current_public_key: Buffer; current_epoch: number }>(
    'SELECT current_public_key, current_epoch FROM tee_key_state LIMIT 1'
  );
  if (result.rows.length === 0) {
    throw new Error(
      'tee_key_state is empty — ensure the TEE worker is running and has been initialised'
    );
  }
  const row = result.rows[0];
  return {
    // current_public_key is a bytea (65-byte uncompressed secp256k1); createSubfolder
    // passes teeKeys.currentPublicKey through hexToBytes, so hand it back as hex.
    currentPublicKey: row.current_public_key.toString('hex'),
    currentEpoch: row.current_epoch,
  };
}

/**
 * Fetch the current signed_record bytes from ipns_records for the given ipnsName.
 * Returns null if no row exists.
 */
async function fetchSignedRecord(ipnsName: string): Promise<Buffer | null> {
  const result = await pool.query<{ signed_record: Buffer | null }>(
    'SELECT signed_record FROM ipns_records WHERE ipns_name = $1',
    [ipnsName]
  );
  return result.rows[0]?.signed_record ?? null;
}

/**
 * Make the schedule row for the given ipnsName due immediately.
 * Noop if no schedule row exists (tombstoned names have already been unenrolled).
 */
async function makeScheduleDue(ipnsName: string): Promise<void> {
  await pool.query(
    `UPDATE ipns_republish_schedule SET next_republish_at = NOW() - interval '1 second' WHERE ipns_name = $1`,
    [ipnsName]
  );
}

/**
 * Enqueue exactly ONE 'republish-batch' job on the real BullMQ 'republish' queue.
 * Creates a fresh Queue connection, adds the job, then closes the connection.
 * The processor (RepublishProcessor) picks it up regardless of whether it came
 * from the scheduler or from this one-shot add.
 */
async function enqueueRepublishBatch(): Promise<void> {
  const queue = new Queue('republish', { connection: REDIS_CONFIG });
  try {
    await queue.add('republish-batch', {});
  } finally {
    await queue.close();
  }
}

/**
 * Poll predicate until it returns true or the timeout is reached.
 * Throws if the timeout expires.
 */
async function waitFor(
  predicate: () => Promise<boolean>,
  options: { timeout: number; interval?: number; label?: string } = { timeout: 15_000 }
): Promise<void> {
  const interval = options.interval ?? 500;
  const deadline = Date.now() + options.timeout;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  throw new Error(
    `waitFor timed out after ${options.timeout}ms${options.label ? ` (${options.label})` : ''}`
  );
}

/**
 * Check whether an ipns_republish_schedule row exists for the given ipnsName.
 */
async function scheduleRowExists(ipnsName: string): Promise<boolean> {
  const result = await pool.query<{ count: string }>(
    'SELECT COUNT(*)::text AS count FROM ipns_republish_schedule WHERE ipns_name = $1',
    [ipnsName]
  );
  return parseInt(result.rows[0]?.count ?? '0', 10) > 0;
}

/**
 * Tombstone a name via the API (POST /ipns/tombstone).
 * Phase-66 tombstone endpoint — unenrolls the name from TEE republishing.
 */
async function tombstoneName(accessToken: string, ipnsName: string): Promise<void> {
  const resp = await testFetch(`${API_URL}/ipns/tombstone`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ ipnsName }),
  });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`tombstone failed (${resp.status}): ${body}`);
  }
}

// ---------------------------------------------------------------------------
// Describe
// ---------------------------------------------------------------------------

describe.skipIf(SKIP_TEE_LIVE)(
  'TEE lease-renewer round-trip suite (TEE-01, TEE-02, tombstone gate)',
  () => {
    // -------------------------------------------------------------------------
    // Test A — equal-seq / equal-CID / later-EOL
    // -------------------------------------------------------------------------
    it('Test A: republish re-signs same CID + same seq with later EOL (TEE-01, TEE-02)', async () => {
      const alice = fixture.accounts.get('alice')!;
      const aliceCtx = alice.client.getContext();

      // 1. Read TEE keys from the live DB
      const teeKeys = await readTeeKeys();

      // 2. Create a subfolder enrolled for TEE republishing
      const { ipnsPrivateKey: subfolderKey } = await createSubfolder({
        name: 'tee-republish-test-a',
        ctx: aliceCtx,
        teeKeys,
      });
      const ipnsName = await deriveIpnsName(deriveEd25519PublicKey(subfolderKey));

      // 3. Capture the original signed_record bytes + sequence
      const originalBytes = await fetchSignedRecord(ipnsName);
      expect(originalBytes).not.toBeNull();
      const originalRecord = await parseIpnsRecord(new Uint8Array(originalBytes!));

      // 4. Make the schedule row due immediately
      await makeScheduleDue(ipnsName);

      // 5. Enqueue ONE republish-batch job (deterministic trigger, no scheduler wait)
      await enqueueRepublishBatch();

      // 6. Poll until ipns_records.signed_record changes
      await waitFor(
        async () => {
          const current = await fetchSignedRecord(ipnsName);
          if (!current) return false;
          return !current.equals(originalBytes!);
        },
        { timeout: 15_000, label: 'wait for signed_record to be renewed' }
      );

      // 7. Fetch renewed record and parse it
      const renewedBytes = await fetchSignedRecord(ipnsName);
      expect(renewedBytes).not.toBeNull();
      const renewedRecord = await parseIpnsRecord(new Uint8Array(renewedBytes!));

      // 8. Assert TEE-01 + TEE-02 invariants:
      //    - same sequence (no increment — TEE-02)
      //    - same CID (no repoint — TEE-01)
      //    - bytes differ (later EOL was written — TEE-01)
      expect(renewedRecord.sequence).toBe(originalRecord.sequence);
      expect(renewedRecord.value).toBe(originalRecord.value);
      expect(renewedBytes!.equals(originalBytes!)).toBe(false);
    }, 120_000);

    // -------------------------------------------------------------------------
    // Test B — tombstone never re-signed
    // -------------------------------------------------------------------------
    it('Test B: tombstoned name is never re-signed forward', async () => {
      const bob = fixture.accounts.get('bob')!;
      const bobCtx = bob.client.getContext();

      // 1. Read TEE keys from the live DB
      const teeKeys = await readTeeKeys();

      // 2. Create a subfolder enrolled for TEE republishing
      const { ipnsPrivateKey: subfolderKey } = await createSubfolder({
        name: 'tee-republish-test-b',
        ctx: bobCtx,
        teeKeys,
      });
      const ipnsName = await deriveIpnsName(deriveEd25519PublicKey(subfolderKey));

      // 3. Capture the original signed_record bytes before tombstoning
      const originalBytes = await fetchSignedRecord(ipnsName);
      expect(originalBytes).not.toBeNull();

      // 4. Tombstone the name via the API (unenrolls from republish schedule)
      await tombstoneName(bob.accessToken, ipnsName);

      // 5. Assert the schedule row is gone (tombstone handler calls unenrollIpns)
      const rowExists = await scheduleRowExists(ipnsName);
      expect(rowExists).toBe(false);

      // 6. Attempt to make the (now-absent) schedule row due — noop
      await makeScheduleDue(ipnsName);

      // 7. Enqueue ONE republish-batch job
      await enqueueRepublishBatch();

      // 8. Wait a moment for the batch to process
      //    The tombstoned name should be absent from getDueEntries (tombstoned_at IS NULL filter)
      //    so the signed_record should remain unchanged even after a full batch cycle.
      await new Promise((resolve) => setTimeout(resolve, 3_000));

      // 9. Assert the signed_record is unchanged (tombstoned name was not re-signed)
      const currentBytes = await fetchSignedRecord(ipnsName);
      expect(currentBytes).not.toBeNull();
      expect(currentBytes!.equals(originalBytes!)).toBe(true);
    }, 120_000);
  }
);
