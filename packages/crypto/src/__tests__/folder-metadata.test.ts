/**
 * @cipherbox/crypto - Folder Metadata Tests
 *
 * Tests for folder metadata encryption and decryption.
 */

import { describe, it, expect } from 'vitest';
import {
  encryptFolderMetadata,
  decryptFolderMetadata,
  generateFileKey, // Uses sync 32-byte key generation
  type FolderMetadata,
  type FolderEntry,
  type FileEntry,
} from '../index';

describe('encryptFolderMetadata', () => {
  it('produces valid encrypted structure', async () => {
    const folderKey = generateFileKey(); // 32-byte key suitable for AES-256
    const metadata: FolderMetadata = {
      version: 'v1',
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
      version: 'v1',
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
      version: 'v1',
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
      version: 'v1',
      children: [folderEntry],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v1');
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

  it('round-trips preserves all file entry fields', async () => {
    const folderKey = generateFileKey();
    const fileEntry: FileEntry = {
      type: 'file',
      id: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
      name: 'report.pdf',
      cid: 'bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4',
      fileKeyEncrypted: '1234567890abcdef',
      fileIv: 'aabbccddeeff00112233445566778899',
      encryptionMode: 'GCM',
      size: 1048576,
      createdAt: 1706054400000,
      modifiedAt: 1706140800000,
    };

    const metadata: FolderMetadata = {
      version: 'v1',
      children: [fileEntry],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v1');
    expect(decrypted.children).toHaveLength(1);

    const recoveredFile = decrypted.children[0] as FileEntry;
    expect(recoveredFile.type).toBe('file');
    expect(recoveredFile.id).toBe(fileEntry.id);
    expect(recoveredFile.name).toBe(fileEntry.name);
    expect(recoveredFile.cid).toBe(fileEntry.cid);
    expect(recoveredFile.fileKeyEncrypted).toBe(fileEntry.fileKeyEncrypted);
    expect(recoveredFile.fileIv).toBe(fileEntry.fileIv);
    expect(recoveredFile.encryptionMode).toBe('GCM');
    expect(recoveredFile.size).toBe(fileEntry.size);
    expect(recoveredFile.createdAt).toBe(fileEntry.createdAt);
    expect(recoveredFile.modifiedAt).toBe(fileEntry.modifiedAt);
  });

  it('handles empty children array correctly', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v1',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey);
    const decrypted = await decryptFolderMetadata(encrypted, folderKey);

    expect(decrypted.version).toBe('v1');
    expect(decrypted.children).toEqual([]);
  });

  it('handles multiple children (mixed files/folders) correctly', async () => {
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

    const fileEntry1: FileEntry = {
      type: 'file',
      id: 'file-uuid-1',
      name: 'document.txt',
      cid: 'bafybeiabc',
      fileKeyEncrypted: 'filekey1',
      fileIv: '001122334455667788990011',
      encryptionMode: 'GCM',
      size: 1024,
      createdAt: 1706054400000,
      modifiedAt: 1706054400000,
    };

    const fileEntry2: FileEntry = {
      type: 'file',
      id: 'file-uuid-2',
      name: 'image.png',
      cid: 'bafybeixyz',
      fileKeyEncrypted: 'filekey2',
      fileIv: 'aabbccddeeff00112233445566',
      encryptionMode: 'GCM',
      size: 2048,
      createdAt: 1706140800000,
      modifiedAt: 1706140800000,
    };

    const metadata: FolderMetadata = {
      version: 'v1',
      children: [folderEntry, fileEntry1, fileEntry2],
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

describe('Folder Metadata Security', () => {
  it('different folder keys produce different ciphertext', async () => {
    const folderKey1 = generateFileKey();
    const folderKey2 = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v1',
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
      version: 'v1',
      children: [],
    };

    const encrypted = await encryptFolderMetadata(metadata, folderKey1);

    // Decrypting with wrong key should fail
    await expect(decryptFolderMetadata(encrypted, folderKey2)).rejects.toThrow('Decryption failed');
  });

  it('corrupted ciphertext fails decryption', async () => {
    const folderKey = generateFileKey();
    const metadata: FolderMetadata = {
      version: 'v1',
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
      version: 'v1',
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
