import { describe, it, expect, vi, beforeEach } from 'vitest';
import { downloadAndDecrypt } from '../download';
import { createMockContext } from './helpers';

// Mock IPFS module
vi.mock('../ipfs', () => ({
  fetchFromIpfs: vi.fn().mockResolvedValue(new Uint8Array([99, 99, 99])),
}));

// Mock crypto functions
vi.mock('@cipherbox/crypto', () => ({
  decryptAesGcm: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
  decryptAesCtr: vi.fn().mockResolvedValue(new Uint8Array([4, 5, 6])),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xdd)),
  hexToBytes: vi.fn((hex: string) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
  }),
  clearBytes: vi.fn(),
}));

describe('Download operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('downloadAndDecrypt', () => {
    it('fetches from IPFS and decrypts with GCM by default', async () => {
      const ctx = createMockContext();

      const result = await downloadAndDecrypt({
        cid: 'QmTestCid',
        fileKeyEncrypted: 'aabbccdd',
        fileIv: '112233',
        userPrivateKey: new Uint8Array(32),
        ctx,
      });

      // Verify IPFS fetch was called
      const { fetchFromIpfs } = await import('../ipfs');
      expect(fetchFromIpfs).toHaveBeenCalledWith(ctx, 'QmTestCid', undefined);

      // Verify GCM decryption was used (default)
      const { decryptAesGcm } = await import('@cipherbox/crypto');
      expect(decryptAesGcm).toHaveBeenCalled();

      expect(result).toEqual(new Uint8Array([1, 2, 3]));
    });

    it('uses CTR decryption when encryptionMode is CTR', async () => {
      const ctx = createMockContext();

      const result = await downloadAndDecrypt({
        cid: 'QmCtrCid',
        fileKeyEncrypted: 'aabb',
        fileIv: '1122',
        userPrivateKey: new Uint8Array(32),
        encryptionMode: 'CTR',
        ctx,
      });

      const { decryptAesCtr } = await import('@cipherbox/crypto');
      expect(decryptAesCtr).toHaveBeenCalled();

      expect(result).toEqual(new Uint8Array([4, 5, 6]));
    });

    it('clears file key from memory after decryption', async () => {
      const ctx = createMockContext();
      const { clearBytes } = await import('@cipherbox/crypto');

      await downloadAndDecrypt({
        cid: 'QmCid',
        fileKeyEncrypted: 'aabb',
        fileIv: '1122',
        userPrivateKey: new Uint8Array(32),
        ctx,
      });

      expect(clearBytes).toHaveBeenCalled();
    });

    it('passes progress callback to fetchFromIpfs', async () => {
      const ctx = createMockContext();
      const onProgress = vi.fn();

      await downloadAndDecrypt({
        cid: 'QmCid',
        fileKeyEncrypted: 'aabb',
        fileIv: '1122',
        userPrivateKey: new Uint8Array(32),
        ctx,
        onProgress,
      });

      const { fetchFromIpfs } = await import('../ipfs');
      expect(fetchFromIpfs).toHaveBeenCalledWith(ctx, 'QmCid', onProgress);
    });
  });
});
