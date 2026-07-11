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
    fileNodeId: 'file-node-uuid',
    fileReadKey: new Uint8Array(32).fill(0x11),
    fileWriteKey: new Uint8Array(32).fill(0x22),
    ipnsRecord: {
      ipnsName: 'k51-file-meta',
      recordBase64: 'base64record',
      metadataCid: 'QmFileMeta',
    },
    encryptedIpnsPrivateKey: 'wrapped-ipns-key',
  }),
}));

// Mock crypto functions
vi.mock('@cipherbox/crypto', () => ({
  generateFileKey: vi.fn(() => new Uint8Array(32).fill(0xaa)),
  generateIv: vi.fn(() => new Uint8Array(12).fill(0xbb)),
  encryptAesGcm: vi.fn().mockResolvedValue(new Uint8Array([99, 99, 99])),
  clearBytes: vi.fn(),
  bytesToHex: vi.fn((bytes: Uint8Array) =>
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  ),
  hexToBytes: vi.fn(() => new Uint8Array(12).fill(0xcc)),
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
      expect(result.encryptedIpnsPrivateKey).toBe('wrapped-ipns-key');

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

    it('uses encryptFn when provided and skips internal encryption', async () => {
      const ctx = createMockContext();
      const data = new Uint8Array([1, 2, 3]);
      const userPublicKey = new Uint8Array(65).fill(0x04);
      const folderKey = new Uint8Array(32).fill(0xcc);
      const externalFileKey = new Uint8Array(32).fill(0xdd);

      const encryptFn = vi.fn().mockResolvedValue({
        ciphertext: new Uint8Array([88, 88, 88]),
        wrappedKey: 'external-wrapped-key',
        iv: 'external-iv-hex',
        fileKey: externalFileKey,
        originalSize: 3,
        encryptedSize: 3,
      });

      const result = await uploadFile({
        data,
        fileId: 'encrypt-fn-test',
        mimeType: 'text/plain',
        folderKey,
        userPublicKey,
        ctx,
        encryptFn,
      });

      // encryptFn should have been called
      expect(encryptFn).toHaveBeenCalledWith({
        data,
        userPublicKey,
        encryptionMode: 'GCM',
      });

      // Internal crypto functions should NOT have been called
      const { generateFileKey, encryptAesGcm } = await import('@cipherbox/crypto');
      expect(generateFileKey).not.toHaveBeenCalled();
      expect(encryptAesGcm).not.toHaveBeenCalled();

      // Result should use the external file key
      expect(result.fileKey).toBe(externalFileKey);

      // IPFS upload should have been called with the external ciphertext
      const { addToIpfs } = await import('../ipfs');
      expect(addToIpfs).toHaveBeenCalledWith(ctx, new Uint8Array([88, 88, 88]), undefined);

      // clearBytes should NOT have been called for the internal key (none was generated)
      const { clearBytes } = await import('@cipherbox/crypto');
      expect(clearBytes).not.toHaveBeenCalled();
    });

    it('uses encryptFn result for file metadata creation', async () => {
      const ctx = createMockContext();
      const externalFileKey = new Uint8Array(32).fill(0xee);
      const encryptFn = vi.fn().mockResolvedValue({
        ciphertext: new Uint8Array([88]),
        wrappedKey: 'ext-wrapped',
        iv: 'ext-iv',
        fileKey: externalFileKey,
        originalSize: 1,
        encryptedSize: 1,
      });

      await uploadFile({
        data: new Uint8Array([1]),
        fileId: 'meta-test',
        mimeType: 'text/plain',
        folderKey: new Uint8Array(32),
        userPublicKey: new Uint8Array(65),
        ctx,
        encryptFn,
      });

      const { createFileMetadata } = await import('../file');
      expect(createFileMetadata).toHaveBeenCalledWith(
        expect.objectContaining({
          fileKey: externalFileKey,
          fileIv: expect.any(Uint8Array),
        })
      );
    });

    it('records correct file size even when encryptFn detaches the data buffer', async () => {
      const ctx = createMockContext();
      const originalData = new Uint8Array([1, 2, 3, 4, 5]);

      // Simulate Transferable detachment: encryptFn receives the buffer,
      // then the caller's Uint8Array becomes zero-length
      const encryptFn = vi.fn().mockImplementation(async (params: { data: Uint8Array }) => {
        // Simulate postMessage transfer — detach the ArrayBuffer
        const detached = new ArrayBuffer(0);
        Object.defineProperty(params.data, 'buffer', { value: detached });
        Object.defineProperty(params.data, 'length', { value: 0 });
        Object.defineProperty(params.data, 'byteLength', { value: 0 });

        return {
          ciphertext: new Uint8Array([99]),
          wrappedKey: 'detach-wrapped',
          iv: 'detach-iv',
          fileKey: new Uint8Array(32).fill(0xaa),
          originalSize: 5,
          encryptedSize: 1,
        };
      });

      await uploadFile({
        data: originalData,
        fileId: 'detach-test',
        mimeType: 'text/plain',
        folderKey: new Uint8Array(32),
        userPublicKey: new Uint8Array(65),
        ctx,
        encryptFn,
      });

      const { createFileMetadata } = await import('../file');
      // Size must be 5 (original), not 0 (post-detachment)
      expect(createFileMetadata).toHaveBeenCalledWith(expect.objectContaining({ size: 5 }));
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
