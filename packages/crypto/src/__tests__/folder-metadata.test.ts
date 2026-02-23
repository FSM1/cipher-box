/**
 * @cipherbox/crypto - Folder Metadata Tests
 *
 * Tests for folder metadata encryption and decryption (v2 schema only).
 */

import { describe, it, expect } from 'vitest';
import {
  encryptFolderMetadata,
  decryptFolderMetadata,
  validateFolderMetadata,
  generateFileKey, // Uses sync 32-byte key generation
  CryptoError,
  type FolderMetadata,
  type FolderEntry,
  type FilePointer,
} from '../index';

describe('encryptFolderMetadata', () => {
  it('produces valid encrypted structure', async () => {
    const folderKey = generateFileKey(); // 32-byte key suitable for AES-256
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);

    // Check structure
    expect(encrypted).toHaveProperty('iv');
    expect(encrypted).toHaveProperty('data');

    // IV should be hex string (24 chars for 12 bytes)
    expect(encrypted.iv).toMatch(/^[0-9a-f]{24}$/);

    // Data should be base64 string
    expect(typeof encrypted.data).toBe('string');
    expect(encrypted.data.length).toBeGreaterThan(0);
  });

  it('different encryptions produce different IVs', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted1 = await encryptFolderMetadata(metadata, folderKey);
    const encrypted2 = await encryptFolderMetadata(metadata, folderKey);

    // Each encryption should use a unique IV
    expect(encrypted1.iv).not.toBe(encrypted2.iv);
  });
});

describe('decryptFolderMetadata', () => {
  it('recovers original metadata', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted).toEqual(metadata);
  });

  it('round-trips preserves all folder entry fields', async () => {
    const folderKey = generateFileKey();
    const folderEntry: FolderEntry = {
      type: 'folder',
      id: '550e8400-e29b-41d4-a716-446655440000',
      name: 'Documents',
      ipnsName: 'k51qzi5uqu5dh9jhgjfghjdfgh',
      ipnsPrivateKeyEncrypted: 'deadbeef1234',
      folderKeyEncrypted: 'cafebabe5678',
      createdAt: 1706140800000,
      modifiedAt: 1706227200000,
    };

    const metadata: FolderMetadata = {
      version: 'v2',
      children: [folderEntry],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v2');
    expect(decrypted.children).toHaveLength(1);

    const recoveredFolder = decrypted.children[0] as FolderEntry;
    expect(recoveredFolder.type).toBe('folder');
    expect(recoveredFolder.id).toBe(folderEntry.id);
    expect(recoveredFolder.name).toBe(folderEntry.name);
    expect(recoveredFolder.ipnsName).toBe(folderEntry.ipnsName);
    expect(recoveredFolder.ipnsPrivateKeyEncrypted).toBe(folderEntry.ipnsPrivateKeyEncrypted);
    expect(recoveredFolder.folderKeyEncrypted).toBe(folderEntry.folderKeyEncrypted);
    expect(recoveredFolder.createdAt).toBe(folderEntry.createdAt);
    expect(recoveredFolder.modifiedAt).toBe(folderEntry.modifiedAt);
  });

  it('round-trips preserves all FilePointer fields', async () => {
    const folderKey = generateFileKey();
    const filePointer: FilePointer = {
      type: 'file',
      id: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
      name: 'report.pdf',
      fileMetaIpnsName: 'k51qzi5uqu5dh9jhgjfghjdfgh',
      createdAt: 1706054400000,
      modifiedAt: 1706140800000,
    };

    const metadata: FolderMetadata = {
      version: 'v2',
      children: [filePointer],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v2');
    expect(decrypted.children).toHaveLength(1);

    const recoveredFile = decrypted.children[0] as FilePointer;
    expect(recoveredFile.type).toBe('file');
    expect(recoveredFile.id).toBe(filePointer.id);
    expect(recoveredFile.name).toBe(filePointer.name);
    expect(recoveredFile.fileMetaIpnsName).toBe(filePointer.fileMetaIpnsName);
    expect(recoveredFile.createdAt).toBe(filePointer.createdAt);
    expect(recoveredFile.modifiedAt).toBe(filePointer.modifiedAt);
  });

  it('handles empty children array correctly', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v2');
    expect(decrypted.children).toEqual([]);
  });

  it('handles multiple children (mixed folders/files) correctly', async () => {
    const folderKey = generateFileKey();

    const folderEntry: FolderEntry = {
      type: 'folder',
      id: 'folder-uuid',
      name: 'Subfolder',
      ipnsName: 'k51qzi5uqu5abc',
      ipnsPrivateKeyEncrypted: 'encrypted1',
      folderKeyEncrypted: 'encrypted2',
      createdAt: 1706054400000,
      modifiedAt: 1706054400000,
    };

    const filePointer1: FilePointer = {
      type: 'file',
      id: 'file-uuid-1',
      name: 'document.txt',
      fileMetaIpnsName: 'k51qzi5uqu5def',
      createdAt: 1706054400000,
      modifiedAt: 1706054400000,
    };

    const filePointer2: FilePointer = {
      type: 'file',
      id: 'file-uuid-2',
      name: 'image.png',
      fileMetaIpnsName: 'k51qzi5uqu5ghi',
      createdAt: 1706140800000,
      modifiedAt: 1706140800000,
    };

    const metadata: FolderMetadata = {
      version: 'v2',
      children: [folderEntry, filePointer1, filePointer2],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.children).toHaveLength(3);

    // Verify types preserved
    expect(decrypted.children[0].type).toBe('folder');
    expect(decrypted.children[1].type).toBe('file');
    expect(decrypted.children[2].type).toBe('file');

    // Verify names preserved
    expect(decrypted.children[0].name).toBe('Subfolder');
    expect(decrypted.children[1].name).toBe('document.txt');
    expect(decrypted.children[2].name).toBe('image.png');
  });
});

describe('validateFolderMetadata', () => {
  it('rejects v1 metadata', () => {
    const data = {
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

    expect(() => validateFolderMetadata(data)).toThrow(CryptoError);
    expect(() => validateFolderMetadata(data)).toThrow('unsupported version');
  });

  it('rejects file children with cid instead of fileMetaIpnsName', () => {
    const data = {
      version: 'v2',
      children: [
        {
          type: 'file',
          id: 'file-uuid',
          name: 'test.txt',
          cid: 'bafybeiabc',
        },
      ],
    };

    expect(() => validateFolderMetadata(data)).toThrow(CryptoError);
    expect(() => validateFolderMetadata(data)).toThrow('fileMetaIpnsName');
  });

  it('accepts valid v2 metadata with FilePointer children', () => {
    const data = {
      version: 'v2',
      children: [
        {
          type: 'file',
          id: 'file-uuid',
          name: 'test.txt',
          fileMetaIpnsName: 'k51qzi5uqu5abc',
          createdAt: 1706054400000,
          modifiedAt: 1706054400000,
        },
      ],
    };

    const result = validateFolderMetadata(data);
    expect(result.version).toBe('v2');
    expect(result.children).toHaveLength(1);
  });

  it('rejects unknown version', () => {
    const data = {
      version: 'v3',
      children: [],
    };

    expect(() => validateFolderMetadata(data)).toThrow(CryptoError);
  });

  it('rejects non-object data', () => {
    expect(() => validateFolderMetadata(null)).toThrow(CryptoError);
    expect(() => validateFolderMetadata('string')).toThrow(CryptoError);
    expect(() => validateFolderMetadata(42)).toThrow(CryptoError);
  });
});

describe('Folder Metadata Security', () => {
  it('should handle large folder metadata', async () => {
    const folderKey = generateFileKey();

    // Create a large folder with 100 children (mixed folders and file pointers)
    const children: (FolderEntry | FilePointer)[] = [];

    for (let i = 0; i < 50; i++) {
      children.push({
        type: 'folder',
        id: `folder-uuid-${i}`,
        name: `Subfolder ${i} with a reasonably long name to simulate real usage`,
        ipnsName: `k51qzi5uqu5dh9jhgjfghjdfgh${i.toString().padStart(10, '0')}`,
        ipnsPrivateKeyEncrypted: 'a'.repeat(200), // Simulate ECIES ciphertext
        folderKeyEncrypted: 'b'.repeat(200),
        createdAt: Date.now() - i * 1000,
        modifiedAt: Date.now(),
      } as FolderEntry);

      children.push({
        type: 'file',
        id: `file-uuid-${i}`,
        name: `document-${i}-with-a-long-descriptive-filename.pdf`,
        fileMetaIpnsName: `k51qzi5uqu5dh9jhgjfghjdfghfile${i.toString().padStart(10, '0')}`,
        createdAt: Date.now() - i * 1000,
        modifiedAt: Date.now(),
      } as FilePointer);
    }

    const metadata: FolderMetadata = {
      version: 'v2',
      children,
    };

    // Encrypt and decrypt large metadata
    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    // Verify all children preserved
    expect(decrypted.children).toHaveLength(100);
    expect(decrypted.children.filter((c) => c.type === 'folder')).toHaveLength(50);
    expect(decrypted.children.filter((c) => c.type === 'file')).toHaveLength(50);

    // Verify first and last entries preserved correctly
    expect(decrypted.children[0].name).toBe(
      'Subfolder 0 with a reasonably long name to simulate real usage'
    );
    expect(decrypted.children[99].name).toBe('document-49-with-a-long-descriptive-filename.pdf');
  });

  it('different folder keys produce different ciphertext', async () => {
    const folderKey1 = generateFileKey();
    const folderKey2 = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted1 = await encryptFolderMetadata(metadata, folderKey1);
    const encrypted2 = await encryptFolderMetadata(metadata, folderKey2);

    // Different keys should produce different ciphertext
    // (even with same plaintext, IV is random)
    expect(encrypted1.data).not.toBe(encrypted2.data);
  });

  it('wrong key fails decryption with error', async () => {
    const folderKey1 = generateFileKey();
    const folderKey2 = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey1);

    // Decrypting with wrong key should fail
    await expect(decryptFolderMetadata(encrypted, folderKey2)).rejects.toThrow('Decryption failed');
  });

  it('corrupted ciphertext fails decryption', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);

    // Corrupt the base64 data (flip some bytes)
    const corrupted = {
      ...encrypted,
      data: 'AAA' + encrypted.data.slice(3), // Modify beginning
    };

    // Should fail decryption due to auth tag mismatch
    await expect(decryptFolderMetadata(corrupted, folderKey)).rejects.toThrow('Decryption failed');
  });

  it('corrupted IV fails decryption', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v2',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);

    // Corrupt the IV
    const corrupted = {
      ...encrypted,
      iv: '000000000000000000000000', // Different IV
    };

    // Should fail decryption due to wrong IV
    await expect(decryptFolderMetadata(corrupted, folderKey)).rejects.toThrow('Decryption failed');
  });
});
