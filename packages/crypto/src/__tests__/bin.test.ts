/**
 * @cipherbox/crypto - Recycle Bin Tests
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
          filePointer: {
            type: 'file' as const,
            id: crypto.randomUUID(),
            name: `test-item-${i}.txt`,
            fileMetaIpnsName: `k51${'c'.repeat(59)}`,
            createdAt: now - i * 120_000,
            modifiedAt: now - i * 60_000,
          },
        }
      : {
          folderEntry: {
            type: 'folder' as const,
            id: crypto.randomUUID(),
            name: `test-item-${i}.txt`,
            ipnsName: `k51${'b'.repeat(59)}`,
            ipnsPrivateKeyEncrypted: `${'dd'.repeat(48)}`,
            folderKeyEncrypted: `${'ee'.repeat(48)}`,
            createdAt: now - i * 120_000,
            modifiedAt: now - i * 60_000,
          },
        }),
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
    expect(restored.filePointer).toEqual(original.filePointer);
    expect(restored.contentCid).toBe(original.contentCid);
    expect(restored.contentSize).toBe(original.contentSize);
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

  it('rejects entry with non-object filePointer', () => {
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
            filePointer: 'not-an-object',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with non-object folderEntry', () => {
    expect(() =>
      validateBinMetadata({
        version: 'v1',
        sequenceNumber: 1,
        entries: [
          {
            id: 'abc',
            itemType: 'folder',
            name: 'docs',
            originalParentIpnsName: 'k51xxx',
            originalPath: '/docs',
            deletedAt: Date.now(),
            size: 0,
            mimeType: '',
            folderEntry: 'not-an-object',
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
  });

  it('rejects entry with null filePointer', () => {
    // null filePointer should fail since it's not undefined and not a non-null object
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
            filePointer: null,
          },
        ],
      })
    ).toThrow('Invalid bin metadata format');
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
