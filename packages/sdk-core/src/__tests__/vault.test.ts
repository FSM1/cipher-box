import { describe, it, expect, vi, beforeEach } from 'vitest';
import { publishVaultKeyBlob, loadVaultKeyBlob } from '../vault';
import type { SdkContext } from '../types';

// Mock dependencies
vi.mock('../ipfs', () => ({
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
}));

vi.mock('@cipherbox/crypto', async () => {
  const actual = await vi.importActual<typeof import('@cipherbox/crypto')>('@cipherbox/crypto');
  return {
    ...actual,
    deriveVaultKeyIpnsKeypair: vi.fn().mockResolvedValue({
      ipnsName: 'k51vaultkey',
      publicKey: new Uint8Array(32).fill(1),
      privateKey: new Uint8Array(32).fill(2),
    }),
    wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xec, 0x01, 0x02, 0x03])),
    unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xaa)),
  };
});

// D-05: v3 blob format — mock serializeVaultBlobV3 / deserializeVaultBlobV3 only.
// v2 helpers (serializeVaultBlobV2, deserializeVaultBlobV2, detectBlobVersion) are
// retired; if any import of them appears it is a regression.
vi.mock('@cipherbox/core', async () => {
  const actual = await vi.importActual<typeof import('@cipherbox/core')>('@cipherbox/core');
  return {
    ...actual,
    serializeVaultBlobV3: vi.fn().mockReturnValue(new Uint8Array([0x03])),
    deserializeVaultBlobV3: vi.fn().mockReturnValue({
      encryptedRootReadKey: new Uint8Array([0xec, 0x01]),
      encryptedRootWriteKey: new Uint8Array([0xec, 0x02]),
    }),
  };
});

import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';

const mockCtx: SdkContext = {
  apiUrl: 'http://localhost:3000',
  getAccessToken: async () => 'test-token',
};

describe('vault key blob operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // S3 zeroization guard (D-05 / T-47-01): publishVaultKeyBlob is the terminal
  // owner of vaultKeyKeypair.privateKey (derived internally, not passed by caller).
  // It must zero the private key buffer on all exit paths.
  describe('publishVaultKeyBlob zeroization (S3/D-05)', () => {
    // Test C: the derived privateKey buffer is zeroed after a successful publish
    it('C: zeroes the derived vaultKeyKeypair.privateKey after successful publish', async () => {
      const { deriveVaultKeyIpnsKeypair } = await import('@cipherbox/crypto');

      // Fresh non-zero private key buffer for this test
      const privateKeyBuf = new Uint8Array(32).fill(0xab);
      vi.mocked(deriveVaultKeyIpnsKeypair).mockResolvedValueOnce({
        ipnsName: 'k51vaultkey',
        publicKey: new Uint8Array(32).fill(1),
        privateKey: privateKeyBuf,
      });

      vi.mocked(addToIpfs).mockResolvedValue({ cid: 'bafyvaultblob', size: 64, recorded: true });
      vi.mocked(createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 0n,
      });

      await publishVaultKeyBlob({
        userPrivateKey: new Uint8Array(32).fill(0x01),
        userPublicKey: new Uint8Array(33).fill(0x02),
        rootReadKey: new Uint8Array(32).fill(0x03),
        rootWriteKey: new Uint8Array(32).fill(0x04),
        ctx: mockCtx,
      });

      // T-47-01: terminal owner must zero the buffer after returning
      expect(privateKeyBuf.every((b) => b === 0)).toBe(true);
    });

    // Test D: the derived privateKey buffer is zeroed even when publish fails
    // (the finally block runs on the rejection path).
    it('D: zeroes the derived vaultKeyKeypair.privateKey when publish fails', async () => {
      const { deriveVaultKeyIpnsKeypair } = await import('@cipherbox/crypto');

      const privateKeyBuf = new Uint8Array(32).fill(0xcd);
      vi.mocked(deriveVaultKeyIpnsKeypair).mockResolvedValueOnce({
        ipnsName: 'k51vaultkey-fail',
        publicKey: new Uint8Array(32).fill(1),
        privateKey: privateKeyBuf,
      });
      vi.mocked(addToIpfs).mockResolvedValueOnce({
        cid: 'QmVaultKeyBlob',
        size: 64,
        recorded: true,
      });
      vi.mocked(createAndPublishIpnsRecord).mockRejectedValueOnce(new Error('publish failed'));

      await expect(
        publishVaultKeyBlob({
          userPrivateKey: new Uint8Array(32).fill(0x01),
          userPublicKey: new Uint8Array(33).fill(0x02),
          rootReadKey: new Uint8Array(32).fill(0x03),
          rootWriteKey: new Uint8Array(32).fill(0x04),
          ctx: mockCtx,
        })
      ).rejects.toThrow('publish failed');

      // T-47-01: terminal owner must zero the buffer on the failure path too.
      expect(privateKeyBuf.every((b) => b === 0)).toBe(true);
    });
  });

  describe('publishVaultKeyBlob', () => {
    it('publishes vault key blob and returns IPNS name', async () => {
      vi.mocked(addToIpfs).mockResolvedValue({ cid: 'bafyvaultblob', size: 64, recorded: true });
      vi.mocked(createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 0n,
      });

      const result = await publishVaultKeyBlob({
        userPrivateKey: new Uint8Array(32).fill(0x01),
        userPublicKey: new Uint8Array(33).fill(0x02),
        rootReadKey: new Uint8Array(32).fill(0x03),
        rootWriteKey: new Uint8Array(32).fill(0x04),
        ctx: mockCtx,
      });

      expect(result.ipnsName).toBe('k51vaultkey');
      expect(addToIpfs).toHaveBeenCalledOnce();
      expect(createAndPublishIpnsRecord).toHaveBeenCalledWith(
        expect.objectContaining({
          ipnsName: 'k51vaultkey',
          metadataCid: 'bafyvaultblob',
          sequenceNumber: 1n,
        })
      );
    });

    it('throws when IPNS publish fails', async () => {
      vi.mocked(addToIpfs).mockResolvedValue({ cid: 'bafyvaultblob', size: 64, recorded: true });
      vi.mocked(createAndPublishIpnsRecord).mockResolvedValue({
        success: false,
        sequenceNumber: 0n,
      });

      await expect(
        publishVaultKeyBlob({
          userPrivateKey: new Uint8Array(32).fill(0x01),
          userPublicKey: new Uint8Array(33).fill(0x02),
          rootReadKey: new Uint8Array(32).fill(0x03),
          rootWriteKey: new Uint8Array(32).fill(0x04),
          ctx: mockCtx,
        })
      ).rejects.toThrow('Failed to publish vault key blob to IPNS');
    });
  });

  describe('loadVaultKeyBlob', () => {
    it('resolves IPNS, fetches blob, and returns decrypted rootReadKey and rootWriteKey', async () => {
      vi.mocked(resolveIpnsRecord).mockResolvedValue({
        cid: 'bafyvaultblob',
        sequenceNumber: 0n,
        signatureVerified: true,
      });
      vi.mocked(fetchFromIpfs).mockResolvedValue(new Uint8Array([0x03, 0x01, 0x02, 0x03]));

      const result = await loadVaultKeyBlob({
        userPrivateKey: new Uint8Array(32).fill(0x01),
        ctx: mockCtx,
      });

      expect(result).not.toBeNull();
      expect(result!.ipnsName).toBe('k51vaultkey');
      // unwrapKey is mocked to return 0xaa fill for both rootReadKey and rootWriteKey
      expect(result!.rootReadKey).toEqual(new Uint8Array(32).fill(0xaa));
      expect(result!.rootWriteKey).toEqual(new Uint8Array(32).fill(0xaa));
      expect(resolveIpnsRecord).toHaveBeenCalledWith('k51vaultkey', mockCtx);
      expect(fetchFromIpfs).toHaveBeenCalledWith(mockCtx, 'bafyvaultblob');
    });

    it('returns null when IPNS record does not exist', async () => {
      vi.mocked(resolveIpnsRecord).mockResolvedValue(null);

      const result = await loadVaultKeyBlob({
        userPrivateKey: new Uint8Array(32).fill(0x01),
        ctx: mockCtx,
      });

      expect(result).toBeNull();
      expect(fetchFromIpfs).not.toHaveBeenCalled();
    });

    it('propagates deserializeVaultBlobV3 error when blob is invalid', async () => {
      vi.mocked(resolveIpnsRecord).mockResolvedValue({
        cid: 'bafyvaultblob',
        sequenceNumber: 0n,
        signatureVerified: true,
      });
      vi.mocked(fetchFromIpfs).mockResolvedValue(new Uint8Array([0x01, 0x01, 0x02, 0x03]));
      const { deserializeVaultBlobV3 } = await import('@cipherbox/core');
      vi.mocked(deserializeVaultBlobV3).mockImplementationOnce(() => {
        throw new Error('invalid v3 blob format');
      });

      await expect(
        loadVaultKeyBlob({
          userPrivateKey: new Uint8Array(32).fill(0x01),
          ctx: mockCtx,
        })
      ).rejects.toThrow('invalid v3 blob format');
    });
  });
});
