/**
 * IPNS publish-gate suite (TEE-04/07, WRITE-04 phase gate) — Phase 66; Test 21 added Phase 71.
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
 *   Test 21 (D-06): Two concurrent FIRST publishes of the same brand-new ipnsName
 *     (no baseline row) → exactly one 200 + one 409 via the Postgres unique
 *     constraint on ipns_records(ipnsName) (23505→409 translation), never a 500.
 *
 * These five cases need the live stack because they exercise real concurrency and the
 * publish CAS / tombstone round-trip. The TEE-05 seqFloor gate (null-signedRecord
 * shared-folder rows: at/above floor serves, below-floor and unparseable cached records
 * fail closed) is pure resolve-decision logic and is covered by unit tests in
 * apps/api/src/ipns/ipns.service.spec.ts ("seqFloor gate" / "unparseable" cases) — no
 * direct DB seeding required.
 *
 * Prerequisites (live local stack):
 *   docker compose -f docker/docker-compose.yml up -d   (redis 6380, kubo, postgres)
 *   pnpm --filter @cipherbox/api dev                    (API on :3000)
 *   pnpm --filter @cipherbox/api migration:run          (ApiSchemaCutover1750000000000 applied)
 */

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

describe('IPNS publish-gate suite (TEE-04/07, WRITE-04 phase gate)', () => {
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
  it('Test 20 (WRITE-04): tombstone → publish surfaces {tombstoned:true}; resolve returns 410', async () => {
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

    // Subsequent publish against the tombstoned name: the API rejects with HTTP
    // 410 IPNS_TOMBSTONED, and `createAndPublishIpnsRecord` maps that to a
    // catchable `{ success: false, tombstoned: true }` signal (SC4/73-02)
    // instead of letting a raw AxiosError propagate -- so it must NOT throw.
    // This is the write-side of the co-writer stale-write UX (publishNodeFn ->
    // CannotWriteUntilRefetch); a raw throw here would bypass that classifier.
    const publishResult = await createAndPublishIpnsRecord({
      ipnsPrivateKey: kp.privateKey,
      ipnsPublicKey: pubKey,
      ipnsName,
      metadataCid: cid,
      sequenceNumber: 2n,
      expectedSequenceNumber: '1',
      ctx: aliceCtx,
    });
    expect(publishResult.tombstoned).toBe(true);
    expect(publishResult.success).toBe(false);

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
  // Test 21 — D-06: concurrent FIRST publish of the same new ipnsName with the
  // SAME CID at sequence=1. Idempotent by design (D-05/D-06), so it settles as
  // EITHER one 200 + one 409 (insert-race on the live Postgres unique constraint)
  // OR two 200s (the loser serialized after the winner committed and re-read the
  // identical CID). Any loser must be a clean 409, never a 5xx.
  // -------------------------------------------------------------------------
  it('Test 21 (D-06): concurrent first-publish of the same new ipnsName → one 200 + one 409 or idempotent two 200s', async () => {
    const alice = fixture.accounts.get('alice')!;
    const aliceCtx = alice.client.getContext();

    // Brand-new Ed25519 keypair / ipnsName — NO baseline publish. Both concurrent
    // calls race the very first INSERT for this ipnsName, exercising the
    // Postgres unique constraint on ipns_records(ipnsName) directly (not the
    // UPDATE...WHERE CAS path Tests 16/17/TEE-07 exercise).
    const kp = generateEd25519Keypair();
    const pubKey = deriveEd25519PublicKey(kp.privateKey);
    const ipnsName = await deriveIpnsName(pubKey);
    const cid = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';

    // Fire two concurrent first-publish requests for the same brand-new ipnsName.
    // Both sign a first-publish record embedding sequence=1 (no expectedSequenceNumber
    // — this is the first-publish path, not a CAS forward publish). Because both
    // carry the SAME CID, the outcome is timing-dependent: if the loser's INSERT
    // races the winner's it hits the ipns_records(ipnsName) unique constraint and
    // its 23505 unique-violation must translate to a clean 409 ConflictException
    // (never a 500); if it serializes after the winner commits it re-reads the
    // identical CID at sequence=1 and returns an idempotent 200.
    const [resultA, resultB] = await Promise.allSettled([
      createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cid,
        sequenceNumber: 1n,
        ctx: aliceCtx,
      }),
      createAndPublishIpnsRecord({
        ipnsPrivateKey: kp.privateKey,
        ipnsPublicKey: pubKey,
        ipnsName,
        metadataCid: cid,
        sequenceNumber: 1n,
        ctx: aliceCtx,
      }),
    ]);

    const fulfilled = [resultA, resultB].filter((r) => r.status === 'fulfilled');
    const rejected = [resultA, resultB].filter((r) => r.status === 'rejected');

    // At least one winner always commits; the loser is EITHER a 409 (insert-race)
    // or an idempotent 200 (same CID + sequence=1). Both shapes are correct, so
    // accept 1 or 2 successes. The only hard invariants: never zero winners, and
    // any loser is a clean 409 ConflictException — never a 500 / unhandled error.
    expect(fulfilled.length).toBeGreaterThanOrEqual(1);
    expect(rejected.length).toBeLessThanOrEqual(1);
    for (const r of rejected) {
      expect(statusOf((r as PromiseRejectedResult).reason)).toBe(409);
    }

    // Follow-up resolve: exactly one row exists, at sequence=1
    const resolved = await resolveIpnsRecord(ipnsName, aliceCtx);
    expect(resolved).not.toBeNull();
    expect(resolved!.sequenceNumber).toBe(1n);
  }, 120_000);
});
