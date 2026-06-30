/**
 * IPNS publish-gate suite (TEE-04/05/07, WRITE-04 phase gate) — Phase 66.
 *
 * Five behavior cases exercised against the live API + migrated node/v3 schema:
 *   Test 16 (TEE-04): Two concurrent forward publishes from the same expected
 *     sequenceNumber='1' → exactly one 200 + one 409; follow-up resolve shows
 *     sequenceNumber=2n (one increment, zero lost updates).
 *   Test 17 (TEE-04): Forward publish advances 1→2; simulated renewal re-publishing
 *     at expected='1' → 409 (NOT 410); latestCid stays the forward-publish CID.
 *   TEE-07: Publish with generation='5'; subsequent publish with generation='3' at the
 *     correct expected sequence → 409; served CID never regresses to the lower-gen value.
 *   Test 20 (WRITE-04 tombstone): POST /ipns/tombstone; subsequent publish returns
 *     HTTP 410 {error:'IPNS_TOMBSTONED'}; resolve of the tombstoned name → 410.
 *   Test 15 (TEE-05 seqFloor): Row with null signedRecord + stored sequenceNumber
 *     (expected-null shared-folder scenario, seeded via psql) — network record
 *     at/above the seq floor serves; below-floor fails closed (null → 404);
 *     an unparseable signedRecord also fails closed when there is no network fallback.
 *
 * Test 15 uses psql (via execFileSync) to seed preconditions that cannot be reached
 * through the public API, which is normal practice for live-stack e2e tests.
 *
 * Prerequisites (live local stack):
 *   docker compose -f docker/docker-compose.yml up -d   (redis 6380, kubo, postgres)
 *   pnpm --filter @cipherbox/api dev                    (API on :3000)
 *   pnpm --filter @cipherbox/api migration:run          (ApiSchemaCutover1750000000000 applied)
 */

import { execFileSync } from 'child_process';
import { writeFileSync, unlinkSync, mkdtempSync, rmdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addToIpfs,
  createAndPublishIpnsRecord,
  resolveIpnsRecord,
  type SdkContext,
} from '@cipherbox/sdk-core';
import {
  bytesToHex,
  deriveEd25519PublicKey,
  deriveIpnsName,
  generateEd25519Keypair,
  generateRandomBytes,
} from '@cipherbox/crypto';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';
import { API_URL, testFetch } from '../fixtures/test-harness';

// ---------------------------------------------------------------------------
// Shared fixture
// ---------------------------------------------------------------------------

let fixture: MultiAccountFixture;

beforeAll(async () => {
  fixture = await createMultiAccountFixture(['alice']);
});

afterAll(async () => {
  if (fixture) await fixture.cleanupAll();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract the HTTP status code from an axios/fetch error.
 * Handles both the `{ status }` and `{ response: { status } }` shapes.
 */
function statusOf(err: unknown): number | undefined {
  const e = err as { response?: { status?: number }; status?: number } | null;
  return e?.response?.status ?? e?.status;
}

/**
 * Extract the response body `data` from an axios error.
 */
function dataOf(err: unknown): unknown {
  return (err as { response?: { data?: unknown } } | null)?.response?.data;
}

/**
 * Run a SQL statement against the local test database via psql.
 * Writes SQL to a temp file to avoid shell-quoting hazards.
 * Only used for seeding preconditions in Test 15.
 */
// The API (apps/api/.env) uses DB_DATABASE=cipherbox_test, so Test 15's psql
// seeding MUST target the same database or the API never sees the seeded rows.
const PSQL_DB = process.env.SDK_E2E_DB ?? 'cipherbox_test';

function psqlExec(sql: string): void {
  const dir = mkdtempSync(join(tmpdir(), 'ipns-gate-'));
  const file = join(dir, 'q.sql');
  writeFileSync(file, sql + '\n');
  try {
    execFileSync('psql', ['-h', 'localhost', '-U', 'postgres', '-d', PSQL_DB, '-f', file], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 15_000, // fail fast instead of hanging the Vitest worker on a stalled psql
      // Pass psql args as an array and PGPASSWORD via env so PSQL_DB is never
      // shell-interpolated into a command string (no injection via SDK_E2E_DB).
      env: { ...process.env, PGPASSWORD: 'postgres' },
    });
  } finally {
    try {
      unlinkSync(file);
    } catch {
      /* ignore */
    }
    try {
      rmdirSync(dir);
    } catch {
      /* ignore */
    }
  }
}

/**
 * Query a single text value from the test database.
 */
function psqlQueryOne(sql: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'ipns-gate-'));
  const file = join(dir, 'q.sql');
  writeFileSync(file, sql + '\n');
  try {
    return execFileSync(
      'psql',
      ['-h', 'localhost', '-U', 'postgres', '-d', PSQL_DB, '-t', '-A', '-f', file],
      {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 15_000,
        env: { ...process.env, PGPASSWORD: 'postgres' },
      }
    ).trim();
  } finally {
    try {
      unlinkSync(file);
    } catch {
      /* ignore */
    }
    try {
      rmdirSync(dir);
    } catch {
      /* ignore */
    }
  }
}

/** Upload a small unique blob to IPFS and return its CID. */
async function uploadBlob(label: string, ctx: SdkContext): Promise<string> {
  const data = new TextEncoder().encode(
    `ipns-publish-gate/${label}/${Date.now()}/${bytesToHex(generateRandomBytes(8))}`
  );
  const result = await addToIpfs(ctx, data);
  return result.cid;
}

// ---------------------------------------------------------------------------
// Describe
// ---------------------------------------------------------------------------

describe('IPNS publish-gate suite (TEE-04/05/07, WRITE-04 phase gate)', () => {
  // -------------------------------------------------------------------------
  // Test 16 — TEE-04: concurrent forward publishes → exactly one 200 + one 409
  // -------------------------------------------------------------------------
  it('Test 16 (TEE-04): concurrent forward publishes → one 200 + one 409, final seq=2', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    // Fresh Ed25519 keypair for this test's IPNS name
    const kp = generateEd25519Keypair();
    const pubKey = deriveEd25519PublicKey(kp.privateKey);
    const ipnsName = await deriveIpnsName(pubKey);
    const cid = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

    // Baseline: publish at seq=1 (first publish — no expectedSequenceNumber)
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cid,
      sequenceNumber: 1n,
      ctx: aliceCtx,
    });

    // Fire two concurrent forward publishes both asserting expected='1'.
    // The API serialises UPDATE ... WHERE sequence_number = 1, so exactly one
    // concurrent UPDATE touches the row; the other sees 0 rows → 409.
    const [resultA, resultB] = await Promise.allSettled([
      createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cid,
        sequenceNumber: 2n,
        expectedSequenceNumber: '1',
        ctx: aliceCtx,
      }),
      createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cid,
        sequenceNumber: 2n,
        expectedSequenceNumber: '1',
        ctx: aliceCtx,
      }),
    ]);

    const fulfilled = [resultA, resultB].filter((r) => r.status === 'fulfilled');
    const rejected = [resultA, resultB].filter((r) => r.status === 'rejected');

    // Exactly one winner, exactly one loser
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);

    // The losing call must report 409 ConflictException
    const rejectedResult = rejected[0] as PromiseRejectedResult;
    expect(statusOf(rejectedResult.reason)).toBe(409);

    // Follow-up resolve: exactly one sequence increment (zero lost updates)
    const resolved = await resolveIpnsRecord(ipnsName, aliceCtx);
    expect(resolved).not.toBeNull();
    expect(resolved!.sequenceNumber).toBe(2n);
  }, 120_000);

  // -------------------------------------------------------------------------
  // Test 17 — TEE-04: renewal racing a forward publish → renewal gets 409
  // -------------------------------------------------------------------------
  it('Test 17 (TEE-04): renewal at stale expected → 409 (not 410), latestCid stays forward CID', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    const kp = generateEd25519Keypair();
    const pubKey = deriveEd25519PublicKey(kp.privateKey);
    const ipnsName = await deriveIpnsName(pubKey);

    // Upload two distinct blobs so we can verify which CID is served after the race
    const cidBaseline = await uploadBlob('t17-baseline', aliceCtx);
    const cidForward = await uploadBlob('t17-forward', aliceCtx);
    const cidRenewal = await uploadBlob('t17-renewal', aliceCtx);

    // Baseline publish at seq=1
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cidBaseline,
      sequenceNumber: 1n,
      ctx: aliceCtx,
    });

    // Forward publish: 1→2, expected='1'
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cidForward,
      sequenceNumber: 2n,
      expectedSequenceNumber: '1',
      ctx: aliceCtx,
    });

    // Simulated renewal: a lease renewer that read expected='1' before the forward
    // publish completed now re-submits its OLD signed bytes (embedded seq=1). The DB
    // is already at sequence_number=2, so the embedded sequence (1) is below the
    // stored sequence and the anti-rollback gate fails it closed with 409 (not 410).
    let renewalError: unknown;
    try {
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cidRenewal,
        sequenceNumber: 1n, // renewal replays the stale signed seq=1 bytes
        expectedSequenceNumber: '1', // stale expected — DB is already at 2
        ctx: aliceCtx,
      });
    } catch (err) {
      renewalError = err;
    }

    // Must reject with 409 (conflict), NOT 410 (tombstone)
    expect(renewalError).toBeDefined();
    expect(statusOf(renewalError)).toBe(409);

    // Resolve: latestCid is the forward CID, never the stale renewal CID
    const resolved = await resolveIpnsRecord(ipnsName, aliceCtx);
    expect(resolved).not.toBeNull();
    expect(resolved!.cid).toBe(cidForward);
    // Sequence stayed at 2 (renewal did not advance it)
    expect(resolved!.sequenceNumber).toBe(2n);
  }, 120_000);

  // -------------------------------------------------------------------------
  // TEE-07 — generation regression rejected at publish
  // -------------------------------------------------------------------------
  it('TEE-07: lower-generation publish rejected → served generation never regresses', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    const kp = generateEd25519Keypair();
    const pubKey = deriveEd25519PublicKey(kp.privateKey);
    const ipnsName = await deriveIpnsName(pubKey);

    const cidBase = await uploadBlob('tee07-base', aliceCtx);
    const cidHighGen = await uploadBlob('tee07-highgen', aliceCtx);
    const cidLowGen = await uploadBlob('tee07-lowgen', aliceCtx);

    // Baseline publish at seq=1 (no generation = default 0)
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cidBase,
      sequenceNumber: 1n,
      ctx: aliceCtx,
    });

    // Forward publish with generation='5': seq 1→2, generation 0→5
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cidHighGen,
      sequenceNumber: 2n,
      expectedSequenceNumber: '1',
      generation: '5',
      ctx: aliceCtx,
    });

    // Capture the CID after the high-generation publish
    const resolvedHighGen = await resolveIpnsRecord(ipnsName, aliceCtx);
    expect(resolvedHighGen).not.toBeNull();
    expect(resolvedHighGen!.cid).toBe(cidHighGen);

    // Attempt a publish with a LOWER generation ('3' < '5') at the correct expected seq.
    // The API's WHERE clause includes `generation <= :incoming`, so '5 <= 3' is false
    // → 0 affected rows → 409 (CAS failed due to generation regression).
    let regressionError: unknown;
    try {
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cidLowGen,
        sequenceNumber: 3n,
        expectedSequenceNumber: '2',
        generation: '3',
        ctx: aliceCtx,
      });
    } catch (err) {
      regressionError = err;
    }

    // Must be rejected with 409 (generation regression ≠ tombstone 410)
    expect(regressionError).toBeDefined();
    expect(statusOf(regressionError)).toBe(409);

    // Resolve still returns the high-gen CID — generation never regressed
    const resolvedAfter = await resolveIpnsRecord(ipnsName, aliceCtx);
    expect(resolvedAfter).not.toBeNull();
    expect(resolvedAfter!.cid).toBe(cidHighGen);
  }, 120_000);

  // -------------------------------------------------------------------------
  // Test 20 — WRITE-04: tombstoned name rejected at publish AND resolve
  // -------------------------------------------------------------------------
  it('Test 20 (WRITE-04): tombstone → publish returns 410 IPNS_TOMBSTONED; resolve returns 410', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    const kp = generateEd25519Keypair();
    const pubKey = deriveEd25519PublicKey(kp.privateKey);
    const ipnsName = await deriveIpnsName(pubKey);
    const cid = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

    // Publish at seq=1 to establish the record
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cid,
      sequenceNumber: 1n,
      ctx: aliceCtx,
    });

    // Tombstone the record via POST /ipns/tombstone (the owner's write-rotation callback)
    const tombstoneResp = await testFetch(`${API_URL}/ipns/tombstone`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${alice.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ipnsName }),
    });
    expect(tombstoneResp.ok).toBe(true);

    // Subsequent publish must be rejected with HTTP 410 IPNS_TOMBSTONED
    let publishError: unknown;
    try {
      await createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cid,
        sequenceNumber: 2n,
        expectedSequenceNumber: '1',
        ctx: aliceCtx,
      });
    } catch (err) {
      publishError = err;
    }
    expect(publishError).toBeDefined();
    expect(statusOf(publishError)).toBe(410);
    expect((dataOf(publishError) as Record<string, unknown>)?.error).toBe('IPNS_TOMBSTONED');

    // Resolve of the tombstoned name must also return HTTP 410
    let resolveError: unknown;
    try {
      await resolveIpnsRecord(ipnsName, aliceCtx);
    } catch (err) {
      resolveError = err;
    }
    expect(resolveError).toBeDefined();
    expect(statusOf(resolveError)).toBe(410);
    expect((dataOf(resolveError) as Record<string, unknown>)?.error).toBe('IPNS_TOMBSTONED');
  }, 120_000);

  // -------------------------------------------------------------------------
  // Test 15 — TEE-05: null-signedRecord seq-floor split
  // -------------------------------------------------------------------------
  it('Test 15 (TEE-05): seqFloor — at/above floor serves; below-floor fails closed; malformed signedRecord fails closed', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    // -----------------------------------------------------------------------
    // Part A: null signedRecord + seq floor gating
    // -----------------------------------------------------------------------

    // Get Alice's DB user_id (needed for the psql INSERT / UPDATE below)
    const alicePublicKeyHex = bytesToHex(alice.publicKey);
    const aliceUserId = psqlQueryOne(
      `SELECT id FROM users WHERE "publicKey" = '${alicePublicKeyHex}'`
    );
    expect(aliceUserId).toMatch(/^[0-9a-f-]{36}$/);

    // Generate a fresh keypair and publish at seq=1 (establishes the row AND network record)
    const kp = generateEd25519Keypair();
    const pubKey = deriveEd25519PublicKey(kp.privateKey);
    const ipnsName = await deriveIpnsName(pubKey);
    const cid = await uploadBlob('t15-floor', aliceCtx);

    await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cid,
      sequenceNumber: 1n,
      ctx: aliceCtx,
    });

    // Seed: null out signedRecord and bump seq_floor to 100 (above network seq=1)
    // This simulates a shared-folder row where signedRecord was never written.
    psqlExec(
      `UPDATE ipns_records SET signed_record = NULL, sequence_number = 100 WHERE ipns_name = '${ipnsName}'`
    );

    // Below-floor: network has seq=1, floor=100 → 1 < 100 → fail closed → null
    const belowFloor = await resolveIpnsRecord(ipnsName, aliceCtx);
    expect(belowFloor).toBeNull();

    // Reset floor to 1 (= network seq) → at-floor → serves
    psqlExec(`UPDATE ipns_records SET sequence_number = 1 WHERE ipns_name = '${ipnsName}'`);

    // The network record is published to delegated routing fire-and-forget, so the
    // DB write can return before the record is resolvable from the routing layer.
    // Under slower CI this lands after the first resolve — poll until it propagates
    // (the at-floor case is expected to serve, so a transient null is just latency,
    // not the fail-closed behavior asserted below).
    let atFloor = await resolveIpnsRecord(ipnsName, aliceCtx);
    for (let attempt = 0; attempt < 20 && atFloor === null; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 300));
      atFloor = await resolveIpnsRecord(ipnsName, aliceCtx);
    }
    expect(atFloor).not.toBeNull();
    expect(atFloor!.cid).toBe(cid);

    // -----------------------------------------------------------------------
    // Part B: unparseable signedRecord → fail closed when no network fallback
    // -----------------------------------------------------------------------

    // Generate a fresh keypair that has never been published to the network.
    // Seed a DB row with garbage signedRecord bytes and a latestCid — parseCachedRecord
    // will throw during parseIpnsRecord → return null → resolver returns null → 404.
    const kp2 = generateEd25519Keypair();
    const pubKey2 = deriveEd25519PublicKey(kp2.privateKey);
    const ipnsName2 = await deriveIpnsName(pubKey2);

    psqlExec(`
      INSERT INTO ipns_records
        (user_id, ipns_name, latest_cid, sequence_number, signed_record, is_root, created_at, updated_at)
      VALUES
        ('${aliceUserId}', '${ipnsName2}', 'bafyteststub000', 1, E'\\\\x01020304', false, NOW(), NOW())
    `);

    // Network: no record (never published). Cached: parse fails → null.
    // resolveIpnsRecord returns null (fail closed, no ungated fallthrough).
    const mismatchResult = await resolveIpnsRecord(ipnsName2, aliceCtx);
    expect(mismatchResult).toBeNull();
  }, 120_000);
});
