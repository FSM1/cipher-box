import { describe, it, expect, vi, beforeEach } from 'vitest';
import { uploadFile } from '../upload';
import { createMockContext } from './helpers';

// Mock IPFS module
vi.mock('../ipfs', () => ({
  addToIpfs: vi.fn().mockResolvedValue({
    cid: 'QmUploadedCid',
    size: 100,
    recorded: true,
  }),
}));

// Mock file module
vi.mock('../file', () => ({
  createFileMetadata: vi.fn().mockResolvedValue({
    fileMetaIpnsName: 'k51-file-meta',
    ipnsRecord: {
      ipnsName: 'k51-file-meta',
      recordBase64: 'base64record',
      metadataCid: 'QmFileMeta',
    },
    ipnsPrivateKeyEncrypted: 'wrapped-ipns-key',
  }),
}));

// Mock crypto functions
vi.mock('@cipherbox/crypto', () => ({
  generateFileKey: vi.fn(() => new Uint8Array(32).fill(0xaa)),
  generateIv: vi.fn(() => new Uint8Array(12).fill(0xbb)),
  encryptAesGcm: vi.fn().mockResolvedValue(new Uint8Array([99, 99, 99])),
  wrapKey: vi.fn().mockResolvedValue(new Uint8Array([77, 77])),
  clearBytes: vi.fn(),
  bytesToHex: vi.fn((bytes: Uint8Array) =>
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  ),
}));

describe('Upload operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('uploadFile', () => {
    it('encrypts file, uploads to IPFS, and creates metadata', async () => {
      const ctx = createMockContext();
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const userPublicKey = new Uint8Array(65).fill(0x04);
      const folderKey = new Uint8Array(32).fill(0xcc);

      const result = await uploadFile({
        data,
        fileId: 'test-file-id',
        mimeType: 'text/plain',
        folderKey,
        userPublicKey,
        ctx,
      });

      expect(result.cid).toBe('QmUploadedCid');
      expect(result.encryptedSize).toBe(100);
      expect(result.fileMetaIpnsName).toBe('k51-file-meta');
      expect(result.ipnsPrivateKeyEncrypted).toBe('wrapped-ipns-key');

      // Verify crypto functions were called
      const { generateFileKey, generateIv, encryptAesGcm } = await import('@cipherbox/crypto');
      expect(generateFileKey).toHaveBeenCalled();
      expect(generateIv).toHaveBeenCalled();
      expect(encryptAesGcm).toHaveBeenCalledWith(
        data,
        expect.any(Uint8Array),
        expect.any(Uint8Array)
      );

      // Verify IPFS upload was called
      const { addToIpfs } = await import('../ipfs');
      expect(addToIpfs).toHaveBeenCalledWith(ctx, expect.any(Uint8Array), undefined);

      // Verify file metadata was created
      const { createFileMetadata } = await import('../file');
      expect(createFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({
          fileId: 'test-file-id',
          cid: 'QmUploadedCid',
          mimeType: 'text/plain',
        })
      );
    });

    it('clears file key from memory after upload', async () => {
      const ctx = createMockContext();
      const { clearBytes } = await import('@cipherbox/crypto');

      await uploadFile({
        data: new Uint8Array([1]),
        fileId: 'id',
        mimeType: 'text/plain',
        folderKey: new Uint8Array(32),
        userPublicKey: new Uint8Array(65),
        ctx,
      });

      expect(clearBytes).toHaveBeenCalled();
    });

    it('passes teeKeys when provided', async () => {
      const ctx = createMockContext();
      const { createFileMetadata } = await import('../file');

      await uploadFile({
        data: new Uint8Array([1]),
        fileId: 'id',
        mimeType: 'text/plain',
        folderKey: new Uint8Array(32),
        userPublicKey: new Uint8Array(65),
        ctx,
        teeKeys: {
          currentPublicKey: 'aabb',
          currentEpoch: 5,
        },
      });

      expect(createFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({
          teeKeys: { currentPublicKey: 'aabb', currentEpoch: 5 },
        })
      );
    });
  });
});
