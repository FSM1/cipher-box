/**
 * CipherBoxClient.loadSharedFolder — descent-vs-restore seed-generation guard
 * (D-08 item 11 / SC3c).
 *
 * The SDK is the AUTHORITATIVE holder of the active shared-folder depth. A
 * subfolder descent captures a seed generation at the START of its async
 * resolve; if a newer navigation (navigateUp / breadcrumb / share-enter /
 * unload) bumps the generation while the descent is in flight, the descent's
 * late seed MUST be rejected so it cannot repoint the active writeKey/depth to
 * the superseded target and misroute the next write.
 */
import { describe, it, expect } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
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
    ipnsName: 'k51parent',
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

describe('CipherBoxClient.loadSharedFolder — seed-generation guard (D-08 item 11)', () => {
  it('accepts a seed whose generation is current, and an unguarded seed always applies', () => {
    const client = new CipherBoxClient(createTestConfig());

    // Unguarded seed (no token) always applies — legacy / same-depth callers.
    expect(client.loadSharedFolder('share-A', makeState({ ipnsName: 'k51parent' }))).toBe(true);
    expect(client.getSharedFolderState('share-A')?.ipnsName).toBe('k51parent');

    // A seed stamped with the CURRENT generation is accepted.
    const token = client.nextSharedFolderSeedGeneration('share-A');
    expect(client.loadSharedFolder('share-A', makeState({ ipnsName: 'k51child' }), token)).toBe(
      true
    );
    expect(client.getSharedFolderState('share-A')?.ipnsName).toBe('k51child');
  });

  it('rejects a descent seed superseded by a newer navigation (the race)', () => {
    const client = new CipherBoxClient(createTestConfig());
    client.loadSharedFolder('share-A', makeState({ ipnsName: 'k51parent' }));

    // A descent into a child captures its generation at the START of its async
    // resolve.
    const descentToken = client.nextSharedFolderSeedGeneration('share-A');

    // While the descent is in flight, a navigateUp/breadcrumb restore bumps the
    // generation and re-seeds the (shallower) parent depth.
    const restoreToken = client.nextSharedFolderSeedGeneration('share-A');
    expect(
      client.loadSharedFolder('share-A', makeState({ ipnsName: 'k51parent' }), restoreToken)
    ).toBe(true);

    // The descent finally resolves and tries to seed the CHILD depth with its
    // now-stale token — it MUST be rejected so the active depth stays at the
    // restored parent (no writeKey/depth repointing).
    const applied = client.loadSharedFolder(
      'share-A',
      makeState({ ipnsName: 'k51child', folderKey: new Uint8Array(32).fill(9) }),
      descentToken
    );
    expect(applied).toBe(false);
    expect(client.getSharedFolderState('share-A')?.ipnsName).toBe('k51parent');
    expect(client.getSharedFolderState('share-A')?.folderKey.every((b) => b === 1)).toBe(true);
  });

  it('an unload (delete) bumps the generation so a late descent seed cannot re-create the entry', () => {
    const client = new CipherBoxClient(createTestConfig());
    client.loadSharedFolder('share-A', makeState());
    const descentToken = client.nextSharedFolderSeedGeneration('share-A');

    // navigateToRoot / unmount unloads the share while the descent is in flight.
    client.unloadSharedFolder('share-A');

    // The descent resolves and tries to seed — rejected, entry stays absent.
    const applied = client.loadSharedFolder('share-A', makeState(), descentToken);
    expect(applied).toBe(false);
    expect(client.hasSharedFolder('share-A')).toBe(false);
  });
});
