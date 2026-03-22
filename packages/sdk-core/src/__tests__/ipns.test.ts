import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';

// Mock the api-client functions
vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerPublishRecord: vi.fn(),
  ipnsControllerPublishBatch: vi.fn(),
  ipnsControllerResolveRecord: vi.fn(),
}));

// Mock the core functions
vi.mock('@cipherbox/core', () => ({
  createIpnsRecord: vi.fn().mockResolvedValue({ value: '/ipfs/QmTest' }),
  marshalIpnsRecord: vi.fn().mockReturnValue(new Uint8Array([1, 2, 3])),
  IPNS_SIGNATURE_PREFIX: new TextEncoder().encode('ipns-signature:'),
}));

// Mock crypto functions
vi.mock('@cipherbox/crypto', () => ({
  verifyEd25519: vi.fn().mockResolvedValue(true),
  concatBytes: vi.fn((...args: Uint8Array[]) => {
    const total = args.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of args) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }),
}));

describe('IPNS operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createAndPublishIpnsRecord', () => {
    it('creates and publishes IPNS record with correct params', async () => {
      const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerPublishRecord).mockResolvedValue({
        success: true,
        sequenceNumber: '2',
        cid: 'QmTest',
        ipnsName: 'k51testname',
      });

      const result = await createAndPublishIpnsRecord({
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51testname',
        metadataCid: 'QmMetaCid',
        sequenceNumber: 1n,
      });

      expect(ipnsControllerPublishRecord).toHaveBeenCalledWith(
        expect.objectContaining({
          ipnsName: 'k51testname',
          metadataCid: 'QmMetaCid',
        }),
        undefined
      );
      expect(result.success).toBe(true);
      expect(result.sequenceNumber).toBe(2n);
    });

    it('passes TEE-encrypted key when provided', async () => {
      const { ipnsControllerPublishRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerPublishRecord).mockResolvedValue({
        success: true,
        sequenceNumber: '1',
        cid: 'QmTest',
        ipnsName: 'k51test',
      });

      await createAndPublishIpnsRecord({
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51test',
        metadataCid: 'QmCid',
        sequenceNumber: 0n,
        encryptedIpnsPrivateKey: 'aabbccdd',
        keyEpoch: 3,
      });

      expect(ipnsControllerPublishRecord).toHaveBeenCalledWith(
        expect.objectContaining({
          encryptedIpnsPrivateKey: 'aabbccdd',
          keyEpoch: 3,
        }),
        undefined
      );
    });
  });

  describe('resolveIpnsRecord', () => {
    it('resolves IPNS name and returns CID with sequence number', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: true,
        cid: 'QmResolvedCid',
        sequenceNumber: '5',
        source: 'network',
      });

      const result = await resolveIpnsRecord('k51resolve');

      expect(result).not.toBeNull();
      expect(result!.cid).toBe('QmResolvedCid');
      expect(result!.sequenceNumber).toBe(5n);
    });

    it('returns null when IPNS name not found', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerResolveRecord).mockResolvedValue({
        success: false,
        cid: '',
        sequenceNumber: '0',
        source: 'none',
      });

      const result = await resolveIpnsRecord('k51notfound');

      expect(result).toBeNull();
    });

    it('returns null on 404 error', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      const error = new Error('Not found') as Error & { status: number };
      error.status = 404;
      vi.mocked(ipnsControllerResolveRecord).mockRejectedValue(error);

      const result = await resolveIpnsRecord('k51missing');

      expect(result).toBeNull();
    });

    it('propagates non-404 errors', async () => {
      const { ipnsControllerResolveRecord } = await import('@cipherbox/api-client');
      vi.mocked(ipnsControllerResolveRecord).mockRejectedValue(new Error('Server error'));

      await expect(resolveIpnsRecord('k51error')).rejects.toThrow('Server error');
    });
  });
});
