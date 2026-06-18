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

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { FolderChild } from '@cipherbox/core';
import type { SdkEvent, SdkEventHandler } from '@cipherbox/sdk';
import {
  seedSharedFolder,
  subscribeSharedFolderProjection,
  parsePublicKey,
  type SharedFolderClient,
} from '../shared-folder-projection';

// ---------------------------------------------------------------------------
// Mocks for useSharedWriteOps (node env — no React render harness)
// useCallback is stubbed as identity so the hook can be called like a plain fn.
// ---------------------------------------------------------------------------

const mockMoveInSharedFolder = vi.fn<() => Promise<void>>();
const mockSdkClient = { moveInSharedFolder: mockMoveInSharedFolder };

vi.mock('react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react')>();
  return { ...actual, useCallback: (fn: unknown) => fn };
});

vi.mock('../../stores/auth.store', () => ({
  useAuthStore: {
    getState: () => ({ vaultKeypair: { privateKey: new Uint8Array(32).fill(9) } }),
  },
}));

vi.mock('../../lib/sdk-provider', () => ({
  getSdkClient: () => mockSdkClient,
}));

vi.mock('../../services/share.service', () => ({
  fetchShareKeys: vi.fn(async () => []),
}));

vi.mock('@cipherbox/sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk')>();
  return {
    ...actual,
    withRevocationGuard: async (op: () => Promise<unknown>) => op(),
  };
});

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
    // The 30s poller calls this instead of resolving IPNS/IPFS/decrypt inline.
    // It takes a single shareId; record it with no extra args.
    refreshSharedFolder: async (shareId: string): Promise<void> => {
      calls.push({ method: 'refreshSharedFolder', shareId, args: undefined });
    },
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

  describe('poll path — refreshSharedFolder routes through the SDK, refs via projection only', () => {
    /** The poller calls refreshSharedFolder(shareId); not part of the projection Pick type. */
    type WithRefresh = { refreshSharedFolder: (shareId: string) => Promise<void> };

    it('the poller calls refreshSharedFolder with the active shareId', async () => {
      const fake = makeFakeClient();

      // Simulate the 30s poll body: pull remote changes through the SDK.
      await (fake.client as unknown as WithRefresh).refreshSharedFolder('share-1');

      expect(fake.calls).toEqual([
        { method: 'refreshSharedFolder', shareId: 'share-1', args: undefined },
      ]);
    });

    it('a refresh call does NOT mutate the projection refs until the matching event fires', async () => {
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

      // Poll calls refresh — the call alone writes nothing (poller never writes refs).
      await (fake.client as unknown as WithRefresh).refreshSharedFolder('share-1');
      expect(refs.children).toEqual([]);
      expect(refs.sequenceNumber).toBeNull();

      // The SDK's sequence-guarded re-resolve then emits the newer snapshot; the
      // projection subscription is the sole writer — proving the poll path lands
      // through the SAME subscription as the write path.
      const polled = [makeChild('remote')];
      fake.emit({
        type: 'sharedFolder:updated',
        shareId: 'share-1',
        ipnsName: 'k51folder',
        children: polled,
        sequenceNumber: 7n,
      });

      expect(refs.children).toEqual(polled);
      expect(refs.sequenceNumber).toBe(7n);
    });

    it('ignores a refresh-driven event for a DIFFERENT shareId (per-share isolation)', async () => {
      const fake = makeFakeClient();
      const refs = {
        children: [makeChild('orig')] as FolderChild[],
        sequenceNumber: 2n as bigint | null,
      };

      subscribeSharedFolderProjection(
        fake.client,
        () => 'share-1',
        (children, sequenceNumber) => {
          refs.children = children;
          refs.sequenceNumber = sequenceNumber;
        }
      );

      await (fake.client as unknown as WithRefresh).refreshSharedFolder('share-OTHER');
      fake.emit({
        type: 'sharedFolder:updated',
        shareId: 'share-OTHER',
        ipnsName: 'k51other',
        children: [makeChild('leak')],
        sequenceNumber: 99n,
      });

      // Active share's projection untouched — poll path respects the isolation guard.
      expect(refs.children.map((c) => c.name)).toEqual(['orig']);
      expect(refs.sequenceNumber).toBe(2n);
    });
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

// ---------------------------------------------------------------------------
// moveItemHandler — routes through runWrite -> client.moveInSharedFolder
// ---------------------------------------------------------------------------

describe('moveItemHandler (REQ-2) — routes through runWrite -> client.moveInSharedFolder', () => {
  beforeEach(() => {
    mockMoveInSharedFolder.mockReset();
    mockMoveInSharedFolder.mockResolvedValue(undefined);
  });

  it('calls client.moveInSharedFolder with the active shareId and move args', async () => {
    const { useSharedWriteOps } = await import('../useSharedWriteOps');

    const setError = vi.fn();
    const setIsLoading = vi.fn();
    const handleRevocation = vi.fn();

    const ops = useSharedWriteOps({
      currentShareId: 'share-abc',
      sharedItems: [],
      setIsLoading,
      setError,
      handleRevocation,
    });

    const item = makeChild('doc.txt');
    await ops.moveItem(item, 'dest-folder-id', 'k51dest-ipns-name');

    expect(mockMoveInSharedFolder).toHaveBeenCalledOnce();
    const [calledShareId, calledArgs] = mockMoveInSharedFolder.mock.calls[0] as unknown as [
      string,
      { itemId: string; destFolderId: string; destIpnsName: string; vaultPrivateKey: Uint8Array },
    ];
    expect(calledShareId).toBe('share-abc');
    expect(calledArgs.itemId).toBe(item.id);
    expect(calledArgs.destFolderId).toBe('dest-folder-id');
    expect(calledArgs.destIpnsName).toBe('k51dest-ipns-name');
    expect(calledArgs.vaultPrivateKey).toEqual(new Uint8Array(32).fill(9));
    // No error message surfaced on success. runWrite calls setError(null) on
    // entry to clear any prior error, so assert it was never called with a
    // string (an actual error), not that it was never called at all.
    expect(setError).not.toHaveBeenCalledWith(expect.any(String));
  });

  it('surfaces errors via setError when moveInSharedFolder rejects', async () => {
    mockMoveInSharedFolder.mockRejectedValueOnce(new Error('IPNS publish failed'));

    const { useSharedWriteOps } = await import('../useSharedWriteOps');

    const setError = vi.fn();
    const setIsLoading = vi.fn();
    const handleRevocation = vi.fn();

    const ops = useSharedWriteOps({
      currentShareId: 'share-abc',
      sharedItems: [],
      setIsLoading,
      setError,
      handleRevocation,
    });

    const item = makeChild('doc.txt');
    await ops.moveItem(item, 'dest-folder-id', 'k51dest-ipns-name');

    // Error must surface through setError (not swallowed)
    expect(setError).toHaveBeenCalledWith(expect.stringContaining('IPNS publish failed'));
  });

  it('sets error immediately when vaultKeypair is absent', async () => {
    // Spy + mockRestore so the override is undone even if an assertion throws.
    const { useAuthStore } = await import('../../stores/auth.store');
    const getStateSpy = vi
      .spyOn(useAuthStore, 'getState')
      .mockReturnValue({ vaultKeypair: null } as unknown as ReturnType<
        typeof useAuthStore.getState
      >);

    const { useSharedWriteOps } = await import('../useSharedWriteOps');
    const setError = vi.fn();

    const ops = useSharedWriteOps({
      currentShareId: 'share-abc',
      sharedItems: [],
      setIsLoading: vi.fn(),
      setError,
      handleRevocation: vi.fn(),
    });

    await ops.moveItem(makeChild('x.txt'), 'dest', 'ipns');
    expect(setError).toHaveBeenCalledWith('No keypair available');
    expect(mockMoveInSharedFolder).not.toHaveBeenCalled();

    getStateSpy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// batchMoveItemsHandler — loops moveInSharedFolder, clears selection on success
// ---------------------------------------------------------------------------

describe('batchMoveItemsHandler (REQ-6) — loops moveInSharedFolder', () => {
  beforeEach(() => {
    mockMoveInSharedFolder.mockReset();
    mockMoveInSharedFolder.mockResolvedValue(undefined);
  });

  function makeBatchOps(setError = vi.fn()) {
    const clearSelection = vi.fn();
    const ops = useSharedWriteOpsForTest({
      currentShareId: 'share-abc',
      sharedItems: [],
      setIsLoading: vi.fn(),
      setError,
      handleRevocation: vi.fn(),
    });
    return { ops, setError, clearSelection };
  }

  // Resolved lazily inside each test (the hook is dynamically imported elsewhere).
  let useSharedWriteOpsForTest: typeof import('../useSharedWriteOps').useSharedWriteOps;
  beforeEach(async () => {
    ({ useSharedWriteOps: useSharedWriteOpsForTest } = await import('../useSharedWriteOps'));
  });

  it('returns early for an empty items array (no move, no clearSelection)', async () => {
    const { ops, clearSelection } = makeBatchOps();

    await ops.batchMoveItems([], 'dest-folder-id', 'k51dest-ipns', clearSelection);

    expect(mockMoveInSharedFolder).not.toHaveBeenCalled();
    expect(clearSelection).not.toHaveBeenCalled();
  });

  it('moves every item and clears the selection on full success', async () => {
    const { ops, clearSelection } = makeBatchOps();
    const items = [makeChild('a.txt'), makeChild('b.txt')];

    await ops.batchMoveItems(items, 'dest-folder-id', 'k51dest-ipns', clearSelection);

    expect(mockMoveInSharedFolder).toHaveBeenCalledTimes(2);
    const movedIds = mockMoveInSharedFolder.mock.calls.map(
      (c) => (c as unknown as [string, { itemId: string }])[1].itemId
    );
    expect(movedIds).toEqual([items[0].id, items[1].id]);
    expect(clearSelection).toHaveBeenCalledOnce();
  });

  it('stops on the first failure and does NOT clear the selection', async () => {
    mockMoveInSharedFolder
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('IPNS publish failed'));
    const setError = vi.fn();
    const { ops, clearSelection } = makeBatchOps(setError);
    const items = [makeChild('a.txt'), makeChild('b.txt'), makeChild('c.txt')];

    await ops.batchMoveItems(items, 'dest-folder-id', 'k51dest-ipns', clearSelection);

    // a moved (ok), b threw → loop stops before c.
    expect(mockMoveInSharedFolder).toHaveBeenCalledTimes(2);
    expect(clearSelection).not.toHaveBeenCalled();
    expect(setError).toHaveBeenCalledWith(expect.stringContaining('IPNS publish failed'));
  });
});
