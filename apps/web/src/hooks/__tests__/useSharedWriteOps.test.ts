/**
 * Shared-folder write hook projection tests (REQ-3, phase 48).
 *
 * The shared write path is PROJECTION-ONLY: `useSharedWriteOps` routes every
 * mutation through the SDK client's shared methods and reads NOTHING back. The
 * `folderChildrenRef`/`sequenceNumberRef` projections are written ONLY by the
 * `sharedFolder:updated` subscription (`subscribeSharedFolderProjection`),
 * filtered on the active shareId.
 *
 * The web vitest environment is `node` (no React render harness — mirrors the
 * owned-path `folder.store` projection tests), so these tests exercise the pure
 * mechanism that makes the hook projection-only and per-share isolated:
 *  - `seedSharedFolder` -> `client.loadSharedFolder` (SDK is the single owner).
 *  - `subscribeSharedFolderProjection` only mutates the projection on a matching
 *    shareId event, never from a write call, and ignores other shares' events.
 *
 * See: phase 48 REQ-3; analog phase 47 folder.store.test.ts.
 */

import { describe, it, expect, vi } from 'vitest';
import type { FolderChild } from '@cipherbox/core';
import type { SdkEvent, SdkEventHandler } from '@cipherbox/sdk';
import {
  seedSharedFolder,
  subscribeSharedFolderProjection,
  parsePublicKey,
  type SharedFolderClient,
} from '../shared-folder-projection';

/** Build a FolderChild file pointer fixture with a recognizable name. */
function makeChild(name: string): FolderChild {
  return {
    type: 'file',
    id: `id-${name}`,
    name,
    fileMetaIpnsName: `k51file-${name}`,
    createdAt: 1,
    modifiedAt: 1000,
  };
}

/**
 * Fake client capturing the `sharedFolder:updated` handler and recording calls
 * to the five shared write methods + `loadSharedFolder`.
 */
function makeFakeClient(): {
  client: SharedFolderClient;
  emit: (event: SdkEvent) => void;
  calls: { method: string; shareId: string; args: unknown }[];
  loaded: { shareId: string; state: unknown }[];
} {
  let captured: SdkEventHandler | null = null;
  const calls: { method: string; shareId: string; args: unknown }[] = [];
  const loaded: { shareId: string; state: unknown }[] = [];

  const record =
    (method: string) =>
    async (shareId: string, args: unknown): Promise<void> => {
      calls.push({ method, shareId, args });
    };

  const client = {
    on(handler: SdkEventHandler): () => void {
      captured = handler;
      return () => {
        captured = null;
      };
    },
    loadSharedFolder(shareId: string, state: unknown): void {
      loaded.push({ shareId, state });
    },
    unloadSharedFolder: vi.fn(),
    uploadToSharedFolder: record('uploadToSharedFolder'),
    createSharedSubfolder: record('createSharedSubfolder'),
    renameInSharedFolder: record('renameInSharedFolder'),
    deleteFromSharedFolder: record('deleteFromSharedFolder'),
    updateSharedFile: record('updateSharedFile'),
  } as unknown as SharedFolderClient;

  return {
    client,
    emit: (event) => {
      if (!captured) throw new Error('handler not subscribed');
      captured(event);
    },
    calls,
    loaded,
  };
}

describe('shared-folder projection (REQ-3) — write hook reads nothing back', () => {
  it('seedSharedFolder routes through client.loadSharedFolder keyed by shareId', () => {
    const fake = makeFakeClient();
    const folderKey = new Uint8Array(32).fill(1);
    const ipnsPrivateKey = new Uint8Array(32).fill(2);
    const recipientPublicKey = new Uint8Array(33).fill(3);
    const ownerPublicKey = parsePublicKey('0x' + 'ab'.repeat(33));
    const addShareKeysFn = vi.fn(async () => {});

    seedSharedFolder(fake.client, {
      shareId: 'share-1',
      ipnsName: 'k51folder',
      folderKey,
      ipnsPrivateKey,
      sequenceNumber: 5n,
      children: [makeChild('a')],
      ownerPublicKey,
      recipientPublicKey,
      addShareKeysFn,
    });

    expect(fake.loaded).toHaveLength(1);
    expect(fake.loaded[0].shareId).toBe('share-1');
    expect(fake.loaded[0].state).toMatchObject({
      shareId: 'share-1',
      ipnsName: 'k51folder',
      sequenceNumber: 5n,
    });
  });

  it('a write call (client method) does NOT mutate the projection refs directly', async () => {
    const fake = makeFakeClient();

    // Simulate the projection target (what the hook subscribes into).
    const refs = { children: [] as FolderChild[], sequenceNumber: null as bigint | null };
    subscribeSharedFolderProjection(
      fake.client,
      () => 'share-1',
      (children, sequenceNumber) => {
        refs.children = children;
        refs.sequenceNumber = sequenceNumber;
      }
    );

    // The write hook calls a client method and reads nothing back.
    await fake.client.uploadToSharedFolder('share-1', {
      data: new Uint8Array([1]),
      fileName: 'f.txt',
    });

    expect(fake.calls).toEqual([
      {
        method: 'uploadToSharedFolder',
        shareId: 'share-1',
        args: { data: new Uint8Array([1]), fileName: 'f.txt' },
      },
    ]);
    // The mutation itself did NOT touch the projection (no write-back).
    expect(refs.children).toEqual([]);
    expect(refs.sequenceNumber).toBeNull();
  });

  it('refs update ONLY when a sharedFolder:updated event for the active share fires', () => {
    const fake = makeFakeClient();
    const refs = { children: [] as FolderChild[], sequenceNumber: null as bigint | null };

    subscribeSharedFolderProjection(
      fake.client,
      () => 'share-1',
      (children, sequenceNumber) => {
        refs.children = children;
        refs.sequenceNumber = sequenceNumber;
      }
    );

    const updated = [makeChild('new')];
    fake.emit({
      type: 'sharedFolder:updated',
      shareId: 'share-1',
      ipnsName: 'k51folder',
      children: updated,
      sequenceNumber: 9n,
    });

    expect(refs.children).toEqual(updated);
    expect(refs.sequenceNumber).toBe(9n);
  });

  it('ignores a sharedFolder:updated event for a DIFFERENT shareId (per-share isolation)', () => {
    const fake = makeFakeClient();
    const refs = {
      children: [makeChild('orig')] as FolderChild[],
      sequenceNumber: 1n as bigint | null,
    };

    subscribeSharedFolderProjection(
      fake.client,
      () => 'share-1',
      (children, sequenceNumber) => {
        refs.children = children;
        refs.sequenceNumber = sequenceNumber;
      }
    );

    fake.emit({
      type: 'sharedFolder:updated',
      shareId: 'share-OTHER',
      ipnsName: 'k51other',
      children: [makeChild('leak')],
      sequenceNumber: 99n,
    });

    // Active share's projection untouched — no cross-share state bleed (T-48-10).
    expect(refs.children.map((c) => c.name)).toEqual(['orig']);
    expect(refs.sequenceNumber).toBe(1n);
  });

  it('updateSharedFile file-only event (unchanged children/sequence) is a safe re-resolve signal', () => {
    const fake = makeFakeClient();
    const original = [makeChild('doc')];
    const refs = { children: original, sequenceNumber: 4n as bigint | null };

    subscribeSharedFolderProjection(
      fake.client,
      () => 'share-1',
      (children, sequenceNumber) => {
        refs.children = children;
        refs.sequenceNumber = sequenceNumber;
      }
    );

    // updateSharedFile emits with the SAME children/sequence (file-only publish).
    fake.emit({
      type: 'sharedFolder:updated',
      shareId: 'share-1',
      ipnsName: 'k51folder',
      children: original,
      sequenceNumber: 4n,
    });

    expect(refs.children).toEqual(original);
    expect(refs.sequenceNumber).toBe(4n);
  });

  it('unsubscribe stops further projection updates', () => {
    const fake = makeFakeClient();
    const refs = { children: [] as FolderChild[], sequenceNumber: null as bigint | null };

    const unsub = subscribeSharedFolderProjection(
      fake.client,
      () => 'share-1',
      (children, sequenceNumber) => {
        refs.children = children;
        refs.sequenceNumber = sequenceNumber;
      }
    );
    unsub();

    expect(() =>
      fake.emit({
        type: 'sharedFolder:updated',
        shareId: 'share-1',
        ipnsName: 'k51folder',
        children: [makeChild('new')],
        sequenceNumber: 2n,
      })
    ).toThrow('handler not subscribed');

    expect(refs.children).toEqual([]);
  });
});
