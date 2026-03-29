/**
 * Republish Route Tests
 *
 * Tests the POST /republish batch processing endpoint.
 * Uses real ECIES crypto via @cipherbox/crypto for encrypted IPNS keys.
 * Mocks ipns-signer (IPNS record creation is tested in @cipherbox/core).
 *
 * Focuses on TEE-specific concerns:
 * - Batch processing with independent per-entry results
 * - Epoch upgrade detection and re-encryption
 * - Input validation
 * - Base64 encoding of response fields
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import { wrapKey } from '@cipherbox/crypto';
import { getKeypair } from '../services/tee-keys.js';

// Mock ipns-signer -- IPNS record creation is tested in @cipherbox/core
vi.mock('../services/ipns-signer.js', () => ({
  signIpnsRecord: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3, 4])),
}));

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
    // Use node:http to make request to the Express app
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
  // Import the router dynamically after mock is set up
  const republishRouter = (await import('../routes/republish.js')).default;
  app.use(republishRouter);
  return app;
}

describe('republish route', () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
    process.env.TEE_MODE = 'simulator';
    delete process.env.CIPHERBOX_ENVIRONMENT;
    delete process.env.NODE_ENV;
  });

  it('processes a single entry successfully', async () => {
    const epoch = 1;
    const testKey = new Uint8Array(32);
    crypto.getRandomValues(testKey);
    const kp = await getKeypair(epoch);
    const encrypted = await wrapKey(testKey, kp.publicKey);

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [
        {
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: epoch,
          ipnsName: 'k51test123',
          latestCid: 'bafybeiabc',
          sequenceNumber: '5',
          currentEpoch: epoch,
          previousEpoch: null,
        },
      ],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(1);
    expect(results[0].success).toBe(true);
    expect(results[0].ipnsName).toBe('k51test123');
    expect(results[0].newSequenceNumber).toBe('6'); // 5 + 1
    expect(results[0].signedRecord).toBeDefined();
    // No epoch upgrade when currentEpoch matches
    expect(results[0].upgradedEncryptedKey).toBeUndefined();
  });

  it('returns valid base64 in signedRecord', async () => {
    const epoch = 1;
    const testKey = new Uint8Array(32);
    crypto.getRandomValues(testKey);
    const kp = await getKeypair(epoch);
    const encrypted = await wrapKey(testKey, kp.publicKey);

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [
        {
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: epoch,
          ipnsName: 'k51test',
          latestCid: 'bafybeiabc',
          sequenceNumber: '1',
          currentEpoch: epoch,
          previousEpoch: null,
        },
      ],
    });

    expect(res.status).toBe(200);
    const signedRecord = (res.body.results as Array<Record<string, unknown>>)[0]
      .signedRecord as string;
    // Should be valid base64 (no error when decoding)
    const decoded = Buffer.from(signedRecord, 'base64');
    expect(decoded.length).toBeGreaterThan(0);
  });

  it('processes batch entries independently (one failure does not block others)', async () => {
    const epoch = 1;
    const testKey = new Uint8Array(32);
    crypto.getRandomValues(testKey);
    const kp = await getKeypair(epoch);
    const encrypted = await wrapKey(testKey, kp.publicKey);

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [
        {
          // Valid entry
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: epoch,
          ipnsName: 'k51valid',
          latestCid: 'bafybeiabc',
          sequenceNumber: '1',
          currentEpoch: epoch,
          previousEpoch: null,
        },
        {
          // Invalid entry - wrong epoch key will fail ECIES decryption
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: epoch,
          ipnsName: 'k51invalid',
          latestCid: 'bafybeiabc',
          sequenceNumber: '1',
          currentEpoch: 999, // Wrong epoch -- will fail decryption
          previousEpoch: null,
        },
        {
          // Another valid entry
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: epoch,
          ipnsName: 'k51valid2',
          latestCid: 'bafybeidef',
          sequenceNumber: '10',
          currentEpoch: epoch,
          previousEpoch: null,
        },
      ],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results).toHaveLength(3);
    expect(results[0].success).toBe(true);
    expect(results[0].ipnsName).toBe('k51valid');
    expect(results[1].success).toBe(false);
    expect(results[1].ipnsName).toBe('k51invalid');
    expect(results[1].error).toBeDefined();
    expect(results[2].success).toBe(true);
    expect(results[2].ipnsName).toBe('k51valid2');
  });

  it('returns epoch upgrade fields when key decrypted with previous epoch', async () => {
    const previousEpoch = 1;
    const currentEpoch = 2;
    const testKey = new Uint8Array(32);
    crypto.getRandomValues(testKey);

    // Encrypt with the PREVIOUS epoch's key
    const kpPrev = await getKeypair(previousEpoch);
    const encrypted = await wrapKey(testKey, kpPrev.publicKey);

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [
        {
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: previousEpoch,
          ipnsName: 'k51upgrade',
          latestCid: 'bafybeiabc',
          sequenceNumber: '3',
          currentEpoch,
          previousEpoch,
        },
      ],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].success).toBe(true);
    expect(results[0].upgradedEncryptedKey).toBeDefined();
    expect(results[0].upgradedKeyEpoch).toBe(currentEpoch);

    // upgradedEncryptedKey should be valid base64
    const decoded = Buffer.from(results[0].upgradedEncryptedKey as string, 'base64');
    expect(decoded.length).toBeGreaterThan(0);
  });

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

  it('increments sequence number correctly', async () => {
    const epoch = 1;
    const testKey = new Uint8Array(32);
    crypto.getRandomValues(testKey);
    const kp = await getKeypair(epoch);
    const encrypted = await wrapKey(testKey, kp.publicKey);

    const app = await createTestApp();
    const res = await postJson(app, '/republish', {
      entries: [
        {
          encryptedIpnsKey: Buffer.from(encrypted).toString('base64'),
          keyEpoch: epoch,
          ipnsName: 'k51seq',
          latestCid: 'bafybeiabc',
          sequenceNumber: '999',
          currentEpoch: epoch,
          previousEpoch: null,
        },
      ],
    });

    expect(res.status).toBe(200);
    const results = res.body.results as Array<Record<string, unknown>>;
    expect(results[0].newSequenceNumber).toBe('1000');
  });
});
