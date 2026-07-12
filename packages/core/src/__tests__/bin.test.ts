/**
 * @cipherbox/core - Recycle Bin Tests
 *
 * Tests for bin crypto operations: IPNS derivation, ECIES encryption/decryption,
 * and schema validation.
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { deriveBinIpnsKeypair } from '../bin/derive-ipns';
import { encryptBinMetadata, decryptBinMetadata } from '../bin/encrypt';
import { validateBinMetadata } from '../bin/schema';
import type { RecycleBinMetadata } from '../bin/types';

/**
 * Generate a secp256k1 keypair for testing.
 */
function generateTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed, 65 bytes
  return { publicKey, privateKey };
}

/**
 * Create a minimal valid RecycleBinMetadata for testing.
 */
function createTestBinMetadata(entryCount = 1): RecycleBinMetadata {
  const now = Date.now();
  const entries = Array.from({ length: entryCount }, (_, i) => ({
    id: `entry-${i}-${crypto.randomUUID()}`,
    itemType: i % 2 === 0 ? ('file' as const) : ('folder' as const),
    name: `test-item-${i}.txt`,
    originalParentIpnsName: `k51${'a'.repeat(59)}`,
    originalPath: `My Vault / Documents / test-item-${i}.txt`,
    deletedAt: now - i * 60_000,
    size: i * 1024,
    mimeType: i % 2 === 0 ? 'text/plain' : '',
    ...(i % 2 === 0
      ? {
          contentCid: `bafybeicontent${i}${'a'.repeat(40)}`,
          contentSize: (i + 1) * 512,
          nodeRef: {
            schema: 'node/v3' as const,
            kind: 'file' as const,
            id: crypto.randomUUID(),
            generation: 0,
            createdAt: now - i * 60_000,
            modifiedAt: now - i * 60_000,
            content: {
              cid: `bafybeicontent${i}${'a'.repeat(40)}`,
              fileIv: 'AAAAAAAAAAAAAAAA',
              size: (i + 1) * 512,
              mimeType: 'text/plain',
              encryptionMode: 'GCM' as const,
              fileKey: new Uint8Array(32),
              versions: [],
            },
          },
        }
      : {}),
  }));

  return {
    version: 'v1',
    sequenceNumber: entryCount,
    entries,
  };
}

// ─── IPNS Derivation ─────────────────────────────────────────────────────

describe('deriveBinIpnsKeypair', () => {
  it('derives an IPNS name starting with k51 from a 32-byte key', async () => {
    const keypair = generateTestKeypair();
    const result = await deriveBinIpnsKeypair(keypair.privateKey);

    expect(result.ipnsName).toMatch(/^k51/);
    expect(result.privateKey).toBeInstanceOf(Uint8Array);
    expect(result.privateKey.length).toBe(32);
    expect(result.publicKey).toBeInstanceOf(Uint8Array);
    expect(result.publicKey.length).toBe(32);
  });

  it('produces the same IPNS name for the same privateKey (determinism)', async () => {
    const keypair = generateTestKeypair();

    const result1 = await deriveBinIpnsKeypair(keypair.privateKey);
    const result2 = await deriveBinIpnsKeypair(keypair.privateKey);

    expect(result1.ipnsName).toBe(result2.ipnsName);
    expect(result1.privateKey).toEqual(result2.privateKey);
    expect(result1.publicKey).toEqual(result2.publicKey);
  });

  it('produces different IPNS names for different privateKeys', async () => {
    const keypair1 = generateTestKeypair();
    const keypair2 = generateTestKeypair();

    const result1 = await deriveBinIpnsKeypair(keypair1.privateKey);
    const result2 = await deriveBinIpnsKeypair(keypair2.privateKey);

    expect(result1.ipnsName).not.toBe(result2.ipnsName);
  });

  it('throws on invalid key length', async () => {
    const shortKey = new Uint8Array(16);
    await expect(deriveBinIpnsKeypair(shortKey)).rejects.toThrow('Invalid private key size');
  });
});

// ─── Encrypt / Decrypt Round-Trip ────────────────────────────────────────

describe('encryptBinMetadata / decryptBinMetadata', () => {
  it('rejects Ed25519 IPNS public keys for ECIES encryption', async () => {
    const rootKeypair = generateTestKeypair();
    const ipnsKeypair = await deriveBinIpnsKeypair(rootKeypair.privateKey);
    const metadata = createTestBinMetadata(1);

    await expect(encryptBinMetadata(metadata, ipnsKeypair.publicKey)).rejects.toThrow();
  });

  it('round-trips empty bin metadata', async () => {
    const keypair = generateTestKeypair();
    const metadata: RecycleBinMetadata = {
      version: 'v1',
      sequenceNumber: 0,
      entries: [],
    };

    const encrypted = await encryptBinMetadata(metadata, keypair.publicKey);
    expect(encrypted).toBeInstanceOf(Uint8Array);
    expect(encrypted.length).toBeGreaterThan(0);

    const decrypted = await decryptBinMetadata(encrypted, keypair.privateKey);
    expect(decrypted).toEqual(metadata);
  });

  it('round-trips bin metadata with file entries', async () => {
    const keypair = generateTestKeypair();
    const metadata = createTestBinMetadata(3);

    const encrypted = await encryptBinMetadata(metadata, keypair.publicKey);
    const decrypted = await decryptBinMetadata(encrypted, keypair.privateKey);

    expect(decrypted.version).toBe('v1');
    expect(decrypted.sequenceNumber).toBe(3);
    expect(decrypted.entries).toHaveLength(3);
    expect(decrypted.entries[0].itemType).toBe('file');
    expect(decrypted.entries[1].itemType).toBe('folder');
  });

  it('preserves all entry fields through round-trip', async () => {
    const keypair = generateTestKeypair();
    const metadata = createTestBinMetadata(1);

    const encrypted = await encryptBinMetadata(metadata, keypair.publicKey);
    const decrypted = await decryptBinMetadata(encrypted, keypair.privateKey);

    const original = metadata.entries[0];
    const restored = decrypted.entries[0];
    expect(restored.id).toBe(original.id);
    expect(restored.name).toBe(original.name);
    expect(restored.originalParentIpnsName).toBe(original.originalParentIpnsName);
    expect(restored.originalPath).toBe(original.originalPath);
    expect(restored.deletedAt).toBe(original.deletedAt);
    expect(restored.size).toBe(original.size);
    expect(restored.mimeType).toBe(original.mimeType);
    expect(restored.contentCid).toBe(original.contentCid);
    expect(restored.contentSize).toBe(original.contentSize);
    // nodeRef round-trip: identity/content fields survive JSON wire round-trip.
    // content.fileKey is NOT asserted here — the bin wire form only hex-encodes
    // BinEntry.nodeReadKey (see encrypt.ts toBinWireForm); a raw Uint8Array nested
    // inside nodeRef.content.fileKey is not restored as a Uint8Array by this path.
    expect(restored.nodeRef).toBeDefined();
    expect(restored.nodeRef?.schema).toBe(original.nodeRef?.schema);
    expect(restored.nodeRef?.kind).toBe(original.nodeRef?.kind);
    expect(restored.nodeRef?.id).toBe(original.nodeRef?.id);
    expect(restored.nodeRef?.generation).toBe(original.nodeRef?.generation);
    expect(restored.nodeRef?.createdAt).toBe(original.nodeRef?.createdAt);
    expect(restored.nodeRef?.modifiedAt).toBe(original.nodeRef?.modifiedAt);
    expect(restored.nodeRef?.content?.cid).toBe(original.nodeRef?.content?.cid);
    expect(restored.nodeRef?.content?.size).toBe(original.nodeRef?.content?.size);
    expect(restored.nodeRef?.content?.mimeType).toBe(original.nodeRef?.content?.mimeType);
  });

  it('round-trips a nodeReadKey Uint8Array as a 32-byte Uint8Array (hex wire encoding)', async () => {
    // Regression for the bin re-link path (Phase 65): nodeReadKey is a Uint8Array
    // in memory but MUST survive the JSON wire round-trip as a Uint8Array — a raw
    // JSON.stringify turns it into {"0":..,"1":..}, which restoreFromBin then hands
    // to sealChildReadKey and crashes at runtime. This test uses the REAL
    // encrypt/decrypt (no mocks) so the serialisation contract is actually exercised.
    const keypair = generateTestKeypair();
    const nodeReadKey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) nodeReadKey[i] = (i * 7 + 3) & 0xff;

    const metadata: RecycleBinMetadata = {
      version: 'v1',
      sequenceNumber: 4,
      entries: [
        {
          id: `entry-${crypto.randomUUID()}`,
          itemType: 'folder',
          name: 'Restored Folder',
          originalParentIpnsName: 'k51parent',
          originalPath: 'My Vault / Restored Folder',
          deletedAt: Date.now(),
          size: 0,
          mimeType: '',
          nodeReadKey,
          nodeIpnsName: 'k51child',
          nodeRef: {
            schema: 'node/v3',
            kind: 'folder',
            id: '00000000-0000-0000-0000-000000000001',
            generation: 0,
            createdAt: 0,
            modifiedAt: 0,
          },
        },
      ],
    };

    const encrypted = await encryptBinMetadata(metadata, keypair.publicKey);
    const decrypted = await decryptBinMetadata(encrypted, keypair.privateKey);

    const got = decrypted.entries[0].nodeReadKey;
    expect(got).toBeInstanceOf(Uint8Array);
    expect(got).toEqual(nodeReadKey);
    expect(got?.length).toBe(32);
    expect(decrypted.entries[0].nodeIpnsName).toBe('k51child');
  });

  it('fails to decrypt with wrong key', async () => {
    const keypair1 = generateTestKeypair();
    const keypair2 = generateTestKeypair();
    const metadata = createTestBinMetadata(1);

    const encrypted = await encryptBinMetadata(metadata, keypair1.publicKey);
    await expect(decryptBinMetadata(encrypted, keypair2.privateKey)).rejects.toThrow();
  });

  it('fails to decrypt corrupted data', async () => {
    const keypair = generateTestKeypair();
    const metadata = createTestBinMetadata(1);

    const encrypted = await encryptBinMetadata(metadata, keypair.publicKey);
    // Flip a byte in the middle of the ciphertext
    encrypted[Math.floor(encrypted.length / 2)] ^= 0xff;

    await expect(decryptBinMetadata(encrypted, keypair.privateKey)).rejects.toThrow();
  });
});

// ─── Schema Validation ───────────────────────────────────────────────────

describe('validateBinMetadata', () => {
  it('accepts valid metadata with entries', () => {
    const metadata = createTestBinMetadata(2);
    expect(() => validateBinMetadata(metadata)).not.toThrow();
    expect(validateBinMetadata(metadata)).toEqual(metadata);
  });

  it('accepts valid metadata with zero entries', () => {
    const metadata: RecycleBinMetadata = {
      version: 'v1',
      sequenceNumber: 0,
      entries: [],
    };
    expect(validateBinMetadata(metadata)).toEqual(metadata);
  });

  it('rejects null', () => {
    expect(() => validateBinMetadata(null)).toThrow('Invalid bin metadata format');
  });

  it('rejects non-object', () => {
    expect(() => validateBinMetadata('not an object')).toThrow('Invalid bin metadata format');
  });

  it('rejects wrong version', () => {
    expect(() => validateBinMetadata({ version: 'v2', sequenceNumber: 0, entries: [] })).toThrow(
      'Invalid bin metadata format'
    );
  });

  it('rejects missing version', () => {
    expect(() => validateBinMetadata({ sequenceNumber: 0, entries: [] })).toThrow(
      'Invalid bin metadata format'
    );
  });

  it('rejects non-integer sequenceNumber', () => {
    expect(() => validateBinMetadata({ version: 'v1', sequenceNumber: 1.5, entries: [] })).toThrow(
      'Invalid bin metadata format'
    );
  });

  it('rejects negative sequenceNumber', () => {
    expect(() => validateBinMetadata({ version: 'v1', sequenceNumber: -1, entries: [] })).toThrow(
      'Invalid bin metadata format'
    );
  });

  it('rejects non-array entries', () => {
    expect(() =>
      validateBinMetadata({ version: 'v1', sequenceNumber: 0, entries: 'not-array' })
    ).toThrow('Invalid bin metadata format');
  });

  // Entry-level validation
  it('rejects entry with missing id', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with empty id', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: '',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with invalid itemType', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'symlink',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-string name', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 123,
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-string originalParentIpnsName', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 42,
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-string originalPath', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: null,
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-number deletedAt', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: '2026-01-01',
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with negative size', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: -1,
            mimeType: 'text/plain',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-string mimeType', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: null,
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-object nodeRef', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            nodeRef: 'not-an-object',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with null nodeRef', () => {
    // null nodeRef should fail since it's not undefined and not a non-null object
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            nodeRef: null,
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('accepts entry with valid nodeRef object', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            nodeRef: {
              schema: 'node/v3',
              kind: 'file',
              id: 'abc',
              generation: 0,
              createdAt: 0,
              modifiedAt: 0,
            },
          },
        ],
      })
    ).not.toThrow();
  });

  it('rejects entry that is not an object', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: ['not-an-entry'],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry that is null', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [null],
      })
    ).toThrow('Invalid bin metadata format');
  });

  // contentCid validation
  it('accepts entry with valid contentCid', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentCid: 'bafybeicontent123',
          },
        ],
      })
    ).not.toThrow();
  });

  it('accepts entry without contentCid (undefined)', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
          },
        ],
      })
    ).not.toThrow();
  });

  it('rejects entry with empty contentCid', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentCid: '',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-string contentCid', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentCid: 12345,
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  // contentSize validation
  it('accepts entry with valid contentSize', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentSize: 2048,
          },
        ],
      })
    ).not.toThrow();
  });

  it('accepts entry with contentSize of zero', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentSize: 0,
          },
        ],
      })
    ).not.toThrow();
  });

  it('rejects entry with negative contentSize', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentSize: -1,
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-number contentSize', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentSize: '2048',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-finite contentSize', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentSize: Infinity,
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('accepts entry with both contentCid and contentSize', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'file',
            name: 'test.txt',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/test.txt',
            deletedAt: Date.now(),
            size: 100,
            mimeType: 'text/plain',
            contentCid: 'bafybeicontent123',
            contentSize: 2048,
          },
        ],
      })
    ).not.toThrow();
  });
});
