/**
 * Republish Route Tests
 *
 * Tests the POST /republish batch processing endpoint — verify-in-enclave
 * lease-renewer contract (TEE-01 / TEE-02 / TEE-06 / §7.3 tests 12, 18, 19).
 *
 * Security invariants under test:
 *   1. newSequenceNumber == String(parsedSeq) — never incremented (TEE-02 / test 12)
 *   2. verifyIpnsRecordSignature runs BEFORE decryptWithFallback (test 18)
 *   3. Name↔key binding mismatch rejects without emitting signedRecord (test 18)
 *   4. ReEnrollRequiredError surfaces as requiresReEnroll: true (no key material) (test 19)
 *   5. Old relay scalars (latestCid/sequenceNumber/currentEpoch/previousEpoch) are absent
 *
 * Uses real ECIES and real IPNS record creation so that verifyIpnsRecordSignature
 * has genuine bytes to validate. Mocks renewIpnsRecord (tested in @cipherbox/core)
 * and wraps key-manager exports with vi.fn() so call-count assertions work.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import { createIpnsRecord, marshalIpnsRecord } from '@cipherbox/core';
import {
  wrapKey,
  deriveEd25519PublicKey,
  deriveIpnsName,
  generateEd25519Keypair,
} from '@cipherbox/crypto';
import { getKeypair } from '../services/tee-keys.js';
import { ReEnrollRequiredError } from '../services/key-manager.js';

// Mock renewIpnsRecord — the re-signing logic is covered by ipns-signer unit tests.
// The route is tested for WHAT it calls, not for the re-signed bytes themselves.
vi.mock('../services/ipns-signer.js', () => ({
  renewIpnsRecord: vi.fn().mockResolvedValue(new Uint8Array([5, 6, 7, 8])),
}));

// Wrap key-manager exports with vi.fn() passthroughs so we can inspect call counts
// without breaking the real decrypt/re-encrypt behavior.
vi.mock('../services/key-manager.js', async () => {
  const actual = (await vi.importActual(
    '../services/key-manager.js'
  )) as typeof import('../services/key-manager.js');
  return {
    ReEnrollRequiredError: actual.ReEnrollRequiredError,
    decryptIpnsKey: vi.fn((...args: Parameters<typeof actual.decryptIpnsKey>) =>
      actual.decryptIpnsKey(...args)
    ),
    decryptWithFallback: vi.fn((...args: Parameters<typeof actual.decryptWithFallback>) =>
      actual.decryptWithFallback(...args)
    ),
    reEncryptForEpoch: vi.fn((...args: Parameters<typeof actual.reEncryptForEpoch>) =>
      actual.reEncryptForEpoch(...args)
    ),
  };
});

/** Helper: make a POST request to a route using raw http */
async function postJson(
  app: Express,
  path: string,
  body: unknown
): Promise<{
  status: number;
  body: Record<string, unknown>;
}> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('Could not get server address'));
        return;
      }

      const payload = JSON.stringify(body);
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const http = require('node:http');
      const req = http.request(
        {
          hostname: '127.0.0.1',
          port: address.port,
          path,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
        },
        (res: import('node:http').IncomingMessage) => {
          let data = '';
          res.on('data', (chunk: string) => (data += chunk));
          res.on('end', () => {
            server.close();
            resolve({
              status: res.statusCode ?? 500,
              body: JSON.parse(data),
            });
          });
        }
      );
      req.on('error', (err: Error) => {
        server.close();
        reject(err);
      });
      req.write(payload);
      req.end();
    });
  });
}

/** Create a minimal Express app with the republish router */
async function createTestApp(): Promise<Express> {
  const app = express();
  app.use(express.json());
  const republishRouter = (await import('../routes/republish.js')).default;
  app.use(republishRouter);
  return app;
}

/**
 * Build a complete, cryptographically valid RepublishEntry for testing.
 *
 * @param opts.privateKey - Ed25519 private key to sign the record (generated if omitted)
 * @param opts.ipnsNameOverride - Use this ipnsName instead of the one derived from privateKey
 *   (set to a name from a different key to provoke verify-fail or binding-mismatch)
 * @param opts.encryptKeyOverride - Encrypt this key instead of opts.privateKey
 *   (set to a different key to provoke name↔key binding mismatch after successful verify)
 * @param opts.sequenceNumber - Sequence number in the IPNS record (default 5n)
 * @param opts.keyEpoch - Epoch to encrypt with (default 1)
 */
async function makeEntry(opts: {
  privateKey?: Uint8Array;
  ipnsNameOverride?: string;
  encryptKeyOverride?: Uint8Array;
  sequenceNumber?: bigint;
  keyEpoch?: number;
}): Promise<{
  encryptedIpnsPrivateKey: string;
  keyEpoch: number;
  ipnsName: string;
  signedRecord: string;
  expectedSequence: bigint;
}> {
  const epoch = opts.keyEpoch ?? 1;
  const seq = opts.sequenceNumber ?? 5n;

  // Generate the signing key if not provided
  const privateKey = opts.privateKey ?? generateEd25519Keypair().privateKey;

  // Derive the IPNS name from the signing key's public key
  const pubkey = deriveEd25519PublicKey(privateKey);
  const derivedName = await deriveIpnsName(pubkey);
  const ipnsName = opts.ipnsNameOverride ?? derivedName;

  // Create a real IPNS record signed by privateKey (48-hour lifetime — well within EOL)
  const ipnsRecord = await createIpnsRecord(
    privateKey,
    '/ipfs/bafybeiabc123test',
    seq,
    48 * 60 * 60 * 1000
  );
  const recordBytes = marshalIpnsRecord(ipnsRecord);
  const signedRecord = Buffer.from(recordBytes).toString('base64');

  // Encrypt the key (or override) with the TEE epoch public key
  const keyToEncrypt = opts.encryptKeyOverride ?? privateKey;
  const kp = await getKeypair(epoch);
  const encrypted = await wrapKey(keyToEncrypt, kp.publicKey);
  const encryptedIpnsPrivateKey = Buffer.from(encrypted).toString('base64');

  return {
    encryptedIpnsPrivateKey,
    keyEpoch: epoch,
    ipnsName,
    signedRecord,
    expectedSequence: seq,
  };
}

describe('republish route', () => {
  beforeEach(async () => {
    vi.clearAllMocks(); // Reset call counts; implementations remain
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;

    // Reset renewIpnsRecord mock to its default resolved value
    const { renewIpnsRecord } = await import('../services/ipns-signer.js');
    vi.mocked(renewIpnsRecord).mockResolvedValue(new Uint8Array([5, 6, 7, 8]));
  });

  // ─────────────────────────────────────────────────────────────────────────
  // §7.3 test 12: no-increment invariant
  // ─────────────────────────────────────────────────────────────────────────

  it('newSequenceNumber equals the parsed input sequence — never incremented (§7.3 test 12)', async () => {
    const { encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord, expectedSequence } =
      await makeEntry({
        sequenceNumber: 5n,
      });

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].ipnsName).toBe(ipnsName);
    // Must equal the parsed sequence (5), NOT 5+1=6
    expect(results[0].newSequenceNumber).toBe(expectedSequence.toString());
    expect(results[0].newSequenceNumber).toBe('5');
    expect(results[0].signedRecord).toBeDefined();
    // No epoch upgrade when usedEpoch === internalCurrentEpoch
    expect(results[0].upgradedEncryptedKey).toBeUndefined();
  });

  it('processes a single entry successfully and returns valid base64 signedRecord', async () => {
    const { encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord } = await makeEntry({});

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(true);
    // signedRecord is the base64 of the mock's [5, 6, 7, 8]
    const decoded = Buffer.from(results[0].signedRecord as string, 'base64');
    expect(decoded.length).toBeGreaterThan(0);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // §7.3 test 18a: verify-fail rejects BEFORE decryption (decrypt spy uncalled)
  // ─────────────────────────────────────────────────────────────────────────

  it('verify-fail: rejects before decryption, decrypt spy uncalled, no signedRecord (§7.3 test 18)', async () => {
    // Create a valid IPNS record for keyA, but supply a WRONG ipnsName in the entry.
    // verifyIpnsRecordSignature(wrongName, recordFromKeyA) → false → reject before decrypt.
    const { encryptedIpnsPrivateKey, keyEpoch, signedRecord } = await makeEntry({});
    const wrongIpnsName = 'k51qzi5uqu5wrongnamexyzabc123'; // valid-looking but wrong name

    const { decryptWithFallback } = await import('../services/key-manager.js');

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName: wrongIpnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(false);
    expect(results[0].signedRecord).toBeUndefined();
    // The decrypt spy MUST be uncalled — verify happened first and rejected
    expect(vi.mocked(decryptWithFallback)).not.toHaveBeenCalled();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // §7.3 test 18b: name↔key binding mismatch rejects without signedRecord
  // ─────────────────────────────────────────────────────────────────────────

  it('binding-mismatch: rejects when decrypted key does not derive to ipnsName (§7.3 test 18)', async () => {
    // keyA: signs the IPNS record and provides the ipnsNameA
    // keyB: the key inside encryptedIpnsPrivateKey (different from keyA)
    // After decrypt: deriveEd25519PublicKey(keyB) ≠ publicKeyFromIpnsName(ipnsNameA) → reject
    const keyA = generateEd25519Keypair().privateKey;
    const keyB = generateEd25519Keypair().privateKey;

    // Record signed by keyA → verifyIpnsRecordSignature(ipnsNameA, bytes) passes
    // encryptedIpnsPrivateKey contains keyB → binding check fails
    const { encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord } = await makeEntry({
      privateKey: keyA,
      encryptKeyOverride: keyB, // encrypt keyB instead of keyA
    });

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(false);
    expect(results[0].signedRecord).toBeUndefined();
    expect(results[0].ipnsName).toBe(ipnsName);
    // Exact safe error message — no raw key bytes encoded in the string
    expect(results[0].error).toBe('Name-key binding violation');
  });

  // ─────────────────────────────────────────────────────────────────────────
  // §7.3 test 19: ReEnrollRequiredError surfaces as structured requiresReEnroll flag
  // ─────────────────────────────────────────────────────────────────────────

  it('ReEnrollRequiredError surfaces as requiresReEnroll: true with no key material (§7.3 test 19)', async () => {
    const { encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord } = await makeEntry({});

    // Override the passthrough to throw ReEnrollRequiredError for this test
    const { decryptWithFallback } = await import('../services/key-manager.js');
    vi.mocked(decryptWithFallback).mockRejectedValueOnce(new ReEnrollRequiredError(1, 3));

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(false);
    expect(results[0].requiresReEnroll).toBe(true);
    // error must not contain key material — it should be a safe string
    expect(results[0].error).toBe('RE_ENROLL_REQUIRED');
    expect(results[0].signedRecord).toBeUndefined();
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Epoch upgrade: re-encryption when usedEpoch !== getInternalCurrentEpoch()
  // ─────────────────────────────────────────────────────────────────────────

  it('returns epoch upgrade fields when usedEpoch differs from internalCurrentEpoch', async () => {
    // Set the epoch anchor so getInternalCurrentEpoch() returns 2.
    // EPOCH_DURATION_MS = 4 weeks. anchor = now - 1 epoch - 1 second → epoch 2.
    const EPOCH_DURATION_MS = 4 * 7 * 24 * 60 * 60 * 1000;
    vi.stubEnv('EPOCH_ZERO_TIMESTAMP_MS', String(Date.now() - EPOCH_DURATION_MS - 1000));

    // Encrypt the key with epoch 1 (previous epoch); internalCurrentEpoch = 2
    // decryptWithFallback(encrypted, keyEpoch=1) → tries epoch 1 → succeeds → usedEpoch=1
    // usedEpoch (1) !== getInternalCurrentEpoch() (2) → upgrade fires
    const { encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord } = await makeEntry({
      keyEpoch: 1,
    });

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(true);
    expect(results[0].upgradedEncryptedKey).toBeDefined();
    expect(results[0].upgradedKeyEpoch).toBe(2);

    const decoded = Buffer.from(results[0].upgradedEncryptedKey as string, 'base64');
    expect(decoded.length).toBeGreaterThan(0);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Per-entry isolation: one failure does not abort the batch
  // ─────────────────────────────────────────────────────────────────────────

  it('processes batch entries independently — one failure does not block others', async () => {
    const valid1 = await makeEntry({ sequenceNumber: 1n });
    const valid2 = await makeEntry({ sequenceNumber: 10n });

    // An entry whose signedRecord cannot be parsed as a valid IPNS record
    const invalidEntry = {
      encryptedIpnsPrivateKey: valid1.encryptedIpnsPrivateKey,
      keyEpoch: 1,
      ipnsName: valid1.ipnsName,
      signedRecord: Buffer.from('not-valid-ipns-protobuf-bytes').toString('base64'),
    };

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [
        {
          encryptedIpnsPrivateKey: valid1.encryptedIpnsPrivateKey,
          keyEpoch: valid1.keyEpoch,
          ipnsName: valid1.ipnsName,
          signedRecord: valid1.signedRecord,
        },
        invalidEntry,
        {
          encryptedIpnsPrivateKey: valid2.encryptedIpnsPrivateKey,
          keyEpoch: valid2.keyEpoch,
          ipnsName: valid2.ipnsName,
          signedRecord: valid2.signedRecord,
        },
      ],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(3);
    expect(results[0].success).toBe(true);
    expect(results[0].ipnsName).toBe(valid1.ipnsName);
    expect(results[1].success).toBe(false);
    expect(results[1].error).toBeDefined();
    expect(results[2].success).toBe(true);
    expect(results[2].ipnsName).toBe(valid2.ipnsName);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Input validation
  // ─────────────────────────────────────────────────────────────────────────

  it('returns 400 for missing entries array', async () => {
    const app = await createTestApp();
    const res = await postJson(app, '/republish', {});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Missing or invalid entries array');
  });

  it('returns 400 for non-array entries', async () => {
    const app = await createTestApp();
    const res = await postJson(app, '/republish', { entries: 'not-an-array' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Missing or invalid entries array');
  });

  it('returns 400 for oversized batch', async () => {
    const app = await createTestApp();
    // Build 101 minimal entries (we do not need valid crypto here — 400 fires before processing)
    const entries = Array.from({ length: 101 }, (_, i) => ({
      encryptedIpnsPrivateKey: 'dGVzdA==',
      keyEpoch: 1,
      ipnsName: `k51fake${i}`,
      signedRecord: 'dGVzdA==',
    }));
    const res = await postJson(app, '/republish', { entries });

    expect(res.status).toBe(400);
    expect((res.body.error as string).startsWith('Batch too large')).toBe(true);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Absence of relay-supplied scalars: old fields must not appear in contract
  // ─────────────────────────────────────────────────────────────────────────

  it('succeeds with new-contract entry shape (no latestCid/sequenceNumber/currentEpoch/previousEpoch)', async () => {
    const { encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord } = await makeEntry({});

    const app = await createTestApp();
    // Deliberately omit all old relay scalars — the route must not read them
    const res = await postJson(app, '/republish', {
      entries: [{ encryptedIpnsPrivateKey, keyEpoch, ipnsName, signedRecord }],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(true);
  });
});
