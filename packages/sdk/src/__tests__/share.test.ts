import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createShareKey, revokeShare, reWrapForRecipients, revokeSharesForItems } from '../share';

// Mock crypto
vi.mock('@cipherbox/crypto', () => ({
  wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xaa, 0xbb, 0xcc])),
  bytesToHex: vi.fn().mockReturnValue('aabbcc'),
  hexToBytes: vi.fn().mockReturnValue(new Uint8Array(33).fill(9)),
}));

const shareCtx = {
  ctx: { apiUrl: 'http://localhost:3000', getAccessToken: async () => 'token' },
  userPrivateKey: new Uint8Array(32),
  userPublicKey: new Uint8Array(33),
};

describe('share operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('createShareKey', () => {
    it('wraps folder key with recipient public key', async () => {
      const result = await createShareKey({
        folderKey: new Uint8Array(32).fill(1),
        recipientPublicKey: new Uint8Array(33).fill(2),
        folderIpnsName: 'k51folder',
        shareCtx,
      });

      expect(result.encryptedKey).toBe('aabbcc');
    });
  });

  describe('revokeShare', () => {
    it('calls the provided revoke function', async () => {
      const revokeFn = vi.fn().mockResolvedValue(undefined);

      await revokeShare({ shareId: 'share-123', revokeShareFn: revokeFn });

      expect(revokeFn).toHaveBeenCalledWith('share-123');
    });
  });

  describe('reWrapForRecipients', () => {
    it('returns empty when no covering shares', async () => {
      const result = await reWrapForRecipients({
        coveringShares: [],
        newItems: [{ keyType: 'file', itemId: 'f1', plaintextKey: new Uint8Array(32) }],
        addShareKeysFn: vi.fn(),
      });

      expect(result.failedRecipients).toEqual([]);
    });

    it('wraps keys for each share and calls addShareKeysFn', async () => {
      const addFn = vi.fn().mockResolvedValue(undefined);

      const result = await reWrapForRecipients({
        coveringShares: [
          {
            shareId: 's1',
            recipientPublicKey: 'aabb',
            itemType: 'folder',
            ipnsName: 'k51',
            itemName: 'Shared',
          },
        ],
        newItems: [{ keyType: 'file', itemId: 'f1', plaintextKey: new Uint8Array(32) }],
        addShareKeysFn: addFn,
      });

      expect(addFn).toHaveBeenCalledWith('s1', [
        { keyType: 'file', itemId: 'f1', encryptedKey: 'aabbcc' },
      ]);
      expect(result.failedRecipients).toEqual([]);
    });

    it('handles 0x-prefixed recipient keys', async () => {
      const addFn = vi.fn().mockResolvedValue(undefined);

      await reWrapForRecipients({
        coveringShares: [
          {
            shareId: 's1',
            recipientPublicKey: '0xaabb',
            itemType: 'folder',
            ipnsName: 'k51',
            itemName: 'Shared',
          },
        ],
        newItems: [{ keyType: 'folder', itemId: 'd1', plaintextKey: new Uint8Array(32) }],
        addShareKeysFn: addFn,
      });

      const { hexToBytes } = await import('@cipherbox/crypto');
      expect(hexToBytes).toHaveBeenCalledWith('aabb');
    });

    it('collects failed recipients without throwing', async () => {
      const addFn = vi.fn().mockRejectedValue(new Error('API error'));

      const result = await reWrapForRecipients({
        coveringShares: [
          {
            shareId: 's1',
            recipientPublicKey: 'aabb',
            itemType: 'folder',
            ipnsName: 'k51',
            itemName: 'Shared',
          },
        ],
        newItems: [{ keyType: 'file', itemId: 'f1', plaintextKey: new Uint8Array(32) }],
        addShareKeysFn: addFn,
      });

      expect(result.failedRecipients).toEqual(['aabb']);
    });
  });

  describe('revokeSharesForItems', () => {
    it('no-ops on an empty list without calling revokeFn', async () => {
      const revokeFn = vi.fn().mockResolvedValue(undefined);
      await revokeSharesForItems({ ipnsNames: [], revokeFn });
      expect(revokeFn).not.toHaveBeenCalled();
    });

    it('sends a sub-cap subtree in a single batch', async () => {
      const revokeFn = vi.fn().mockResolvedValue(undefined);
      const names = ['k51a', 'k51b', 'k51c'];
      await revokeSharesForItems({ ipnsNames: names, revokeFn });
      expect(revokeFn).toHaveBeenCalledTimes(1);
      expect(revokeFn).toHaveBeenCalledWith(names);
    });

    it('chunks subtrees larger than 5000 into sequential ≤5000 batches', async () => {
      const revokeFn = vi.fn().mockResolvedValue(undefined);
      // 5000 + 5000 + 1 -> three batches of [5000, 5000, 1].
      const names = Array.from({ length: 10001 }, (_, i) => `k51-${i}`);
      await revokeSharesForItems({ ipnsNames: names, revokeFn });
      expect(revokeFn).toHaveBeenCalledTimes(3);
      expect(revokeFn.mock.calls[0][0]).toHaveLength(5000);
      expect(revokeFn.mock.calls[1][0]).toHaveLength(5000);
      expect(revokeFn.mock.calls[2][0]).toHaveLength(1);
      // No overlap / loss across batches.
      const flattened = revokeFn.mock.calls.flatMap((c) => c[0] as string[]);
      expect(flattened).toEqual(names);
    });

    it('stops at the first failing batch and rethrows (fail-closed)', async () => {
      const revokeFn = vi
        .fn()
        .mockResolvedValueOnce(undefined) // batch 1 ok
        .mockRejectedValue(new Error('boom')); // batch 2 fails every attempt
      const names = Array.from({ length: 5001 }, (_, i) => `k51-${i}`);
      await expect(revokeSharesForItems({ ipnsNames: names, revokeFn })).rejects.toThrow('boom');
      // Batch 1 (1 call) + batch 2 exhausting 3 attempts = 4; batch never reaches a 3rd chunk.
      expect(revokeFn).toHaveBeenCalledTimes(4);
    });

    it('retries transient failures then succeeds', async () => {
      const revokeFn = vi
        .fn()
        .mockRejectedValueOnce(new Error('network'))
        .mockResolvedValue(undefined);
      await revokeSharesForItems({ ipnsNames: ['k51a'], revokeFn, maxAttempts: 3 });
      expect(revokeFn).toHaveBeenCalledTimes(2);
    });

    it('does NOT retry a non-retryable 4xx — rethrows on the first attempt', async () => {
      // A plain (non-Error) rejection is wrapped, surfacing the original as `cause`.
      const err = { response: { status: 400 } };
      const revokeFn = vi.fn().mockRejectedValue(err);
      await expect(
        revokeSharesForItems({ ipnsNames: ['k51a'], revokeFn, maxAttempts: 3 })
      ).rejects.toMatchObject({ cause: err });
      // Short-circuits: a single attempt, no backoff/retry burned.
      expect(revokeFn).toHaveBeenCalledTimes(1);
    });

    it('rethrows a non-retryable 4xx Error instance unchanged', async () => {
      const err = Object.assign(new Error('bad request'), { response: { status: 400 } });
      const revokeFn = vi.fn().mockRejectedValue(err);
      await expect(
        revokeSharesForItems({ ipnsNames: ['k51a'], revokeFn, maxAttempts: 3 })
      ).rejects.toBe(err);
      expect(revokeFn).toHaveBeenCalledTimes(1);
    });

    it('still retries a 5xx (transient) up to maxAttempts before throwing', async () => {
      const err = Object.assign(new Error('unavailable'), { response: { status: 503 } });
      const revokeFn = vi.fn().mockRejectedValue(err);
      await expect(
        revokeSharesForItems({ ipnsNames: ['k51a'], revokeFn, maxAttempts: 3 })
      ).rejects.toBe(err);
      expect(revokeFn).toHaveBeenCalledTimes(3);
    });
  });
});
