/**
 * Client shared-write unit tests (REQ-3).
 *
 * The client owns shared-folder state in a sibling sharedFolderTree keyed by
 * shareId. Each shared method:
 *  - reads state from sharedFolderTree.get(shareId) (throws if absent),
 *  - builds a SharedWriteContext from that state,
 *  - delegates the actual write to the existing share/shared-write.ts function
 *    (which routes through publishWithCas — no second retry loop here),
 *  - writes publishedChildren/newSequenceNumber back into sharedFolderTree,
 *  - emits exactly one sharedFolder:updated event.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { SdkEvent } from '../events';
import type { SharedFolderState } from '../types';
import type { FolderChild } from '@cipherbox/core';
import { createTestConfig } from './helpers';

vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn(),
  hexToBytes: vi.fn(),
}));

// Mock the share module — stub the shared-write delegate while keeping
// buildSharedWriteContext real so the context wiring is exercised.
vi.mock('../share', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../share')>();
  return {
    ...actual,
    uploadToSharedFolder: vi.fn(),
  };
});

import * as shareOps from '../share';

const PUBLISHED_CHILDREN: FolderChild[] = [
  {
    type: 'file',
    id: 'newfile',
    name: 'doc.txt',
    fileMetaIpnsName: 'k51newfile',
    ipnsPrivateKeyEncrypted: 'enc',
    createdAt: 1,
    modifiedAt: 1,
  },
];

function seedSharedFolder(
  client: CipherBoxClient,
  overrides?: Partial<SharedFolderState>
): SharedFolderState {
  const state: SharedFolderState = {
    shareId: 'share-1',
    ipnsName: 'k51shared',
    folderKey: new Uint8Array(32).fill(1),
    ipnsPrivateKey: new Uint8Array(64).fill(2),
    sequenceNumber: 3n,
    children: [],
    ownerPublicKey: new Uint8Array(33).fill(3),
    recipientPublicKey: new Uint8Array(33).fill(4),
    addShareKeysFn: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
  client.loadSharedFolder(state.shareId, state);
  return state;
}

describe('CipherBoxClient - shared write', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('uploadToSharedFolder', () => {
    it('reads state, delegates to shared-write, writes back, emits sharedFolder:updated', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      seedSharedFolder(client);

      vi.mocked(shareOps.uploadToSharedFolder).mockResolvedValue({
        publishedChildren: PUBLISHED_CHILDREN,
        newSequenceNumber: 4n,
        filePointer: PUBLISHED_CHILDREN[0] as never,
      });

      await client.uploadToSharedFolder('share-1', {
        data: new Uint8Array([1, 2, 3]),
        fileName: 'doc.txt',
      });

      // Delegated exactly once, with a context built from the seeded state.
      expect(shareOps.uploadToSharedFolder).toHaveBeenCalledTimes(1);
      const [swCtx, params] = vi.mocked(shareOps.uploadToSharedFolder).mock.calls[0];
      expect(swCtx).toMatchObject({
        ipnsName: 'k51shared',
        shareId: 'share-1',
        sequenceNumber: 3n,
      });
      expect(params).toMatchObject({ fileName: 'doc.txt' });

      // State advanced to the returned sequence + adopted publishedChildren.
      const state = client.getSharedFolderState('share-1');
      expect(state?.sequenceNumber).toBe(4n);
      expect(state?.children).toEqual(PUBLISHED_CHILDREN);

      // Exactly one sharedFolder:updated event with the published snapshot.
      const updates = events.filter((e) => e.type === 'sharedFolder:updated');
      expect(updates).toHaveLength(1);
      const updated = updates[0] as Extract<SdkEvent, { type: 'sharedFolder:updated' }>;
      expect(updated.shareId).toBe('share-1');
      expect(updated.ipnsName).toBe('k51shared');
      expect(updated.sequenceNumber).toBe(4n);
      expect(updated.children).toEqual(PUBLISHED_CHILDREN);
    });

    it('throws "Shared folder not loaded" when the share is not loaded', async () => {
      await expect(
        client.uploadToSharedFolder('absent-share', {
          data: new Uint8Array([1]),
          fileName: 'x.txt',
        })
      ).rejects.toThrow('Shared folder not loaded');
    });
  });
});
