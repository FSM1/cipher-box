/**
 * @cipherbox/crypto - File IPNS Derivation & File Metadata Tests
 *
 * Tests for:
 * - Deterministic file IPNS keypair derivation
 * - Domain separation between different fileIds and different userPrivateKeys
 * - File metadata encryption/decryption round-trip
 * - v2 folder metadata validation
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { deriveFileIpnsKeypair } from '../file/derive-ipns';
import { encryptFileMetadata, decryptFileMetadata } from '../file/metadata';
import {
  encryptFolderMetadata,
  decryptFolderMetadata,
  isV2Metadata,
  validateFolderMetadata,
} from '../folder/metadata';
import { generateFileKey } from '../utils';
import { CryptoError } from '../types';
import type { FileMetadata } from '../file/types';
import type { FolderMetadataV2 } from '../folder/types';
import type { FolderEntry, FolderMetadata } from '../folder/types';

/**
 * Generate a random secp256k1 private key for testing.
 */
function randomPrivateKey(): Uint8Array {
  return secp256k1.utils.randomPrivateKey();
}

/**
 * Create a sample FileMetadata for testing.
 */
function sampleFileMetadata(overrides?: Partial<FileMetadata>): FileMetadata {
  return {
    version: 'v1',
    cid: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
    fileKeyEncrypted: 'deadbeef1234567890abcdef',
    fileIv: 'aabbccddeeff00112233445566778899',
    size: 1048576,
    mimeType: 'application/pdf',
    createdAt: 1706054400000,
    modifiedAt: 1706140800000,
    ...overrides,
  };
}

// ─── deriveFileIpnsKeypair ─────────────────────────────────────────

describe('deriveFileIpnsKeypair', () => {
  const FILE_ID_1 = '550e8400-e29b-41d4-a716-446655440000';
  const FILE_ID_2 = '7c9e6679-7425-40de-944b-e07fc1f90ae7';

  it('same userPrivateKey + same fileId = same keypair (deterministic)', async () => {
    const privateKey = randomPrivateKey();

    const result1 = await deriveFileIpnsKeypair(privateKey, FILE_ID_1);
    const result2 = await deriveFileIpnsKeypair(privateKey, FILE_ID_1);

    expect(result1.privateKey).toEqual(result2.privateKey);
    expect(result1.publicKey).toEqual(result2.publicKey);
    expect(result1.ipnsName).toBe(result2.ipnsName);
  });

  it('same userPrivateKey + different fileId = different keypair (domain separation)', async () => {
    const privateKey = randomPrivateKey();

    const result1 = await deriveFileIpnsKeypair(privateKey, FILE_ID_1);
    const result2 = await deriveFileIpnsKeypair(privateKey, FILE_ID_2);

    expect(result1.ipnsName).not.toBe(result2.ipnsName);
    expect(result1.privateKey).not.toEqual(result2.privateKey);
    expect(result1.publicKey).not.toEqual(result2.publicKey);
  });

  it('different userPrivateKey + same fileId = different keypair', async () => {
    const privateKey1 = randomPrivateKey();
    const privateKey2 = randomPrivateKey();

    const result1 = await deriveFileIpnsKeypair(privateKey1, FILE_ID_1);
    const result2 = await deriveFileIpnsKeypair(privateKey2, FILE_ID_1);

    expect(result1.ipnsName).not.toBe(result2.ipnsName);
    expect(result1.privateKey).not.toEqual(result2.privateKey);
    expect(result1.publicKey).not.toEqual(result2.publicKey);
  });

  it('throws CryptoError with INVALID_KEY_SIZE for invalid key length', async () => {
    const shortKey = new Uint8Array(31);

    await expect(deriveFileIpnsKeypair(shortKey, FILE_ID_1)).rejects.toThrow(
      'Invalid private key size for file IPNS derivation'
    );

    try {
      await deriveFileIpnsKeypair(shortKey, FILE_ID_1);
    } catch (error) {
      expect(error).toBeInstanceOf(CryptoError);
      expect((error as CryptoError).code).toBe('INVALID_KEY_SIZE');
    }
  });

  it('throws CryptoError for empty fileId', async () => {
    const privateKey = randomPrivateKey();

    await expect(deriveFileIpnsKeypair(privateKey, '')).rejects.toThrow('Invalid fileId');

    try {
      await deriveFileIpnsKeypair(privateKey, '');
    } catch (error) {
      expect(error).toBeInstanceOf(CryptoError);
    }
  });

  it('throws CryptoError for short fileId (< 10 chars)', async () => {
    const privateKey = randomPrivateKey();

    await expect(deriveFileIpnsKeypair(privateKey, 'short')).rejects.toThrow('Invalid fileId');
  });

  it('returned ipnsName starts with k51 or bafzaa', async () => {
    const privateKey = randomPrivateKey();

    const result = await deriveFileIpnsKeypair(privateKey, FILE_ID_1);

    expect(result.ipnsName).toMatch(/^(k51|bafzaa)/);
  });
});

// ─── encryptFileMetadata / decryptFileMetadata ─────────────────────

describe('encryptFileMetadata / decryptFileMetadata', () => {
  it('round-trip: encrypt then decrypt returns identical FileMetadata', async () => {
    const folderKey = generateFileKey();
    const metadata = sampleFileMetadata();

    const encrypted = await encryptFileMetadata(metadata, folderKey);
    const decrypted = await decryptFileMetadata(encrypted, folderKey);

    expect(decrypted).toEqual({
      ...metadata,
      encryptionMode: 'GCM', // defaults to GCM
    });
  });

  it('round-trip with encryptionMode CTR preserves the field', async () => {
    const folderKey = generateFileKey();
    const metadata = sampleFileMetadata({ encryptionMode: 'CTR' });

    const encrypted = await encryptFileMetadata(metadata, folderKey);
    const decrypted = await decryptFileMetadata(encrypted, folderKey);

    expect(decrypted.encryptionMode).toBe('CTR');
  });

  it('round-trip without encryptionMode defaults to GCM after decrypt', async () => {
    const folderKey = generateFileKey();
    // Create metadata without encryptionMode set
    const metadata: FileMetadata = {
      version: 'v1',
      cid: 'bafybeiabc',
      fileKeyEncrypted: 'deadbeef',
      fileIv: 'aabbccddeeff',
      size: 512,
      mimeType: 'text/plain',
      createdAt: 1706054400000,
      modifiedAt: 1706054400000,
    };

    const encrypted = await encryptFileMetadata(metadata, folderKey);
    const decrypted = await decryptFileMetadata(encrypted, folderKey);

    expect(decrypted.encryptionMode).toBe('GCM');
  });

  it('wrong folderKey fails decryption (throws CryptoError)', async () => {
    const folderKey1 = generateFileKey();
    const folderKey2 = generateFileKey();
    const metadata = sampleFileMetadata();

    const encrypted = await encryptFileMetadata(metadata, folderKey1);

    await expect(decryptFileMetadata(encrypted, folderKey2)).rejects.toThrow('Decryption failed');
  });

  it('validates all fields present after decrypt', async () => {
    const folderKey = generateFileKey();
    const metadata = sampleFileMetadata();

    const encrypted = await encryptFileMetadata(metadata, folderKey);
    const decrypted = await decryptFileMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v1');
    expect(decrypted.cid).toBe(metadata.cid);
    expect(decrypted.fileKeyEncrypted).toBe(metadata.fileKeyEncrypted);
    expect(decrypted.fileIv).toBe(metadata.fileIv);
    expect(decrypted.size).toBe(metadata.size);
    expect(decrypted.mimeType).toBe(metadata.mimeType);
    expect(typeof decrypted.createdAt).toBe('number');
    expect(typeof decrypted.modifiedAt).toBe('number');
    expect(decrypted.encryptionMode).toBe('GCM');
  });
});

// ─── validateFolderMetadata (v2) ──────────────────────────────────

describe('validateFolderMetadata (v2)', () => {
  it('v2 metadata with FilePointer children validates correctly', () => {
    const data = {
      version: 'v2',
      children: [
        {
          type: 'file',
          id: '550e8400-e29b-41d4-a716-446655440000',
          name: 'report.pdf',
          fileMetaIpnsName: 'k51qzi5uqu5dh9jhgjfghjdfgh',
          createdAt: 1706054400000,
          modifiedAt: 1706140800000,
        },
      ],
    };

    const result = validateFolderMetadata(data);
    expect(result.version).toBe('v2');
    expect(result.children).toHaveLength(1);
    expect(result.children[0].type).toBe('file');
  });

  it('v2 metadata with FolderEntry children validates correctly', () => {
    const data = {
      version: 'v2',
      children: [
        {
          type: 'folder',
          id: '550e8400-e29b-41d4-a716-446655440001',
          name: 'Documents',
          ipnsName: 'k51qzi5uqu5dh9jhgjfghjdfgh',
          ipnsPrivateKeyEncrypted: 'deadbeef',
          folderKeyEncrypted: 'cafebabe',
          createdAt: 1706054400000,
          modifiedAt: 1706140800000,
        },
      ],
    };

    const result = validateFolderMetadata(data);
    expect(result.version).toBe('v2');
    expect(result.children).toHaveLength(1);
    expect(result.children[0].type).toBe('folder');
  });

  it('v2 metadata with mixed FilePointer + FolderEntry validates correctly', () => {
    const data = {
      version: 'v2',
      children: [
        {
          type: 'folder',
          id: 'folder-uuid-1',
          name: 'Documents',
          ipnsName: 'k51qzi5uqu5abc',
          ipnsPrivateKeyEncrypted: 'encrypted1',
          folderKeyEncrypted: 'encrypted2',
          createdAt: 1706054400000,
          modifiedAt: 1706054400000,
        },
        {
          type: 'file',
          id: 'file-uuid-1',
          name: 'report.pdf',
          fileMetaIpnsName: 'k51qzi5uqu5def',
          createdAt: 1706054400000,
          modifiedAt: 1706140800000,
        },
        {
          type: 'file',
          id: 'file-uuid-2',
          name: 'photo.jpg',
          fileMetaIpnsName: 'k51qzi5uqu5ghi',
          createdAt: 1706140800000,
          modifiedAt: 1706140800000,
        },
      ],
    };

    const result = validateFolderMetadata(data);
    expect(result.version).toBe('v2');
    expect(result.children).toHaveLength(3);
    expect(result.children[0].type).toBe('folder');
    expect(result.children[1].type).toBe('file');
    expect(result.children[2].type).toBe('file');
  });

  it('v1 metadata still validates correctly (backward compat)', () => {
    const data: FolderMetadata = {
      version: 'v1',
      children: [
        {
          type: 'file',
          id: 'file-uuid',
          name: 'test.txt',
          cid: 'bafybeiabc',
          fileKeyEncrypted: 'key123',
          fileIv: 'iv123',
          encryptionMode: 'GCM',
          size: 1024,
          createdAt: 1706054400000,
          modifiedAt: 1706054400000,
        },
      ],
    };

    const result = validateFolderMetadata(data);
    expect(result.version).toBe('v1');
  });

  it('v2 metadata encrypts and decrypts correctly', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadataV2 = {
      version: 'v2',
      children: [
        {
          type: 'folder',
          id: 'folder-uuid',
          name: 'Documents',
          ipnsName: 'k51qzi5uqu5abc',
          ipnsPrivateKeyEncrypted: 'encrypted1',
          folderKeyEncrypted: 'encrypted2',
          createdAt: 1706054400000,
          modifiedAt: 1706054400000,
        },
        {
          type: 'file',
          id: 'file-uuid',
          name: 'report.pdf',
          fileMetaIpnsName: 'k51qzi5uqu5def',
          createdAt: 1706054400000,
          modifiedAt: 1706140800000,
        },
      ],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v2');
    expect(decrypted.children).toHaveLength(2);
    expect(decrypted.children[0].type).toBe('folder');
    expect(decrypted.children[1].type).toBe('file');
    expect((decrypted.children[0] as FolderEntry).ipnsName).toBe('k51qzi5uqu5abc');
  });
});

// ─── isV2Metadata type guard ──────────────────────────────────────

describe('isV2Metadata', () => {
  it('returns true for v2 metadata', () => {
    const v2: FolderMetadataV2 = {
      version: 'v2',
      children: [],
    };

    expect(isV2Metadata(v2)).toBe(true);
  });

  it('returns false for v1 metadata', () => {
    const v1: FolderMetadata = {
      version: 'v1',
      children: [],
    };

    expect(isV2Metadata(v1)).toBe(false);
  });
});
