import { describe, it, expect, vi } from 'vitest';
import { createShareKey, revokeShare, reWrapForRecipients } from '../share';

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
});
