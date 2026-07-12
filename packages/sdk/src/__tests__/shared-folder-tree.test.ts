/**
 * SharedFolderTree unit tests — per-share isolation + key-zeroing.
 *
 * The shared-folder tree is keyed by `shareId` (NOT `ipnsName`) so two shares
 * that collide on the same ipnsName stay independent and never bleed key
 * material or write context into each other (D REQ-3, A4; T-48-06 / T-48-07).
 */
import { describe, it, expect } from 'vitest';
import { SharedFolderTree } from '../state/shared-folder-tree';
import type { SharedFolderState } from '../types';
import type { PublishedNode } from '@cipherbox/core';

const stubPublishedNode: PublishedNode = {
  schema: 'node/v3',
  kind: 'folder',
  id: 'stub-node-id',
  generation: 0,
  aeadVersion: 1,
  readSealed: 'dGVzdA==',
};

function makeState(overrides?: Partial<SharedFolderState>): SharedFolderState {
  return {
    shareId: 'share-A',
    ipnsName: 'k51shared',
    folderKey: new Uint8Array(32).fill(1),
    ipnsPrivateKey: new Uint8Array(64).fill(2),
    writeKey: new Uint8Array(32).fill(5),
    publishedNode: stubPublishedNode,
    sequenceNumber: 1n,
    children: [],
    ownerPublicKey: new Uint8Array(33).fill(3),
    recipientPublicKey: new Uint8Array(33).fill(4),
    ...overrides,
  };
}

describe('SharedFolderTree', () => {
  it('keys entries by shareId — two shares with the SAME ipnsName coexist', () => {
    const tree = new SharedFolderTree();
    tree.set('share-A', makeState({ shareId: 'share-A', ipnsName: 'k51same', sequenceNumber: 5n }));
    tree.set('share-B', makeState({ shareId: 'share-B', ipnsName: 'k51same', sequenceNumber: 9n }));

    expect(tree.has('share-A')).toBe(true);
    expect(tree.has('share-B')).toBe(true);
    expect(tree.get('share-A')?.sequenceNumber).toBe(5n);
    expect(tree.get('share-B')?.sequenceNumber).toBe(9n);
    expect(tree.getAll().size).toBe(2);
  });

  it('set() clones key buffers so caller buffers are not zeroed by delete()', () => {
    const tree = new SharedFolderTree();
    const callerFolderKey = new Uint8Array(32).fill(7);
    const callerIpnsKey = new Uint8Array(64).fill(8);
    tree.set('share-A', makeState({ folderKey: callerFolderKey, ipnsPrivateKey: callerIpnsKey }));

    tree.delete('share-A');

    // Caller buffers untouched (clone was zeroed, not the originals)
    expect(callerFolderKey.every((b) => b === 7)).toBe(true);
    expect(callerIpnsKey.every((b) => b === 8)).toBe(true);
  });

  it('delete(shareId) zeros that entry key material and leaves the other entry intact', () => {
    const tree = new SharedFolderTree();
    tree.set('share-A', makeState({ shareId: 'share-A', ipnsName: 'k51same' }));
    tree.set('share-B', makeState({ shareId: 'share-B', ipnsName: 'k51same' }));

    // Capture the stored (cloned) buffers for share-A before deletion
    const storedA = tree.get('share-A')!;
    const aFolderKey = storedA.folderKey;
    const aIpnsKey = storedA.ipnsPrivateKey;

    tree.delete('share-A');

    // share-A removed and its key material zeroed
    expect(tree.has('share-A')).toBe(false);
    expect(aFolderKey.every((b) => b === 0)).toBe(true);
    expect(aIpnsKey.every((b) => b === 0)).toBe(true);

    // share-B untouched — no cross-share bleed
    expect(tree.has('share-B')).toBe(true);
    const storedB = tree.get('share-B')!;
    expect(storedB.folderKey.every((b) => b === 0)).toBe(false);
    expect(storedB.ipnsPrivateKey.every((b) => b === 0)).toBe(false);
  });

  it('clear() zeros all entries key material', () => {
    const tree = new SharedFolderTree();
    tree.set('share-A', makeState({ shareId: 'share-A' }));
    tree.set('share-B', makeState({ shareId: 'share-B' }));
    const aFolderKey = tree.get('share-A')!.folderKey;
    const bFolderKey = tree.get('share-B')!.folderKey;

    tree.clear();

    expect(tree.getAll().size).toBe(0);
    expect(aFolderKey.every((b) => b === 0)).toBe(true);
    expect(bFolderKey.every((b) => b === 0)).toBe(true);
  });

  // D-08 item 11: the active-depth seed generation is the mechanism the client's
  // loadSharedFolder guard uses to reject a superseded descent's late seed.
  describe('active-depth seed generation (D-08 item 11)', () => {
    it('nextSeedGeneration is monotonic and per-share; currentSeedGeneration starts at 0', () => {
      const tree = new SharedFolderTree();
      expect(tree.currentSeedGeneration('share-A')).toBe(0);
      expect(tree.currentSeedGeneration('share-B')).toBe(0);

      expect(tree.nextSeedGeneration('share-A')).toBe(1);
      expect(tree.nextSeedGeneration('share-A')).toBe(2);
      expect(tree.currentSeedGeneration('share-A')).toBe(2);

      // Independent per share — no cross-share bleed.
      expect(tree.nextSeedGeneration('share-B')).toBe(1);
      expect(tree.currentSeedGeneration('share-A')).toBe(2);
    });

    it('delete() bumps the generation so an in-flight seed racing an unload is stale', () => {
      const tree = new SharedFolderTree();
      tree.set('share-A', makeState({ shareId: 'share-A' }));
      const genBeforeUnload = tree.nextSeedGeneration('share-A'); // a descent captures this
      tree.delete('share-A');
      // The unload advanced the generation past the captured token, so a late
      // seed that re-creates the entry would be recognised as superseded.
      expect(tree.currentSeedGeneration('share-A')).toBeGreaterThan(genBeforeUnload);
    });
  });
});
