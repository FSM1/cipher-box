/**
 * D-03 poll-invalidation freshness leg — behavioral coverage.
 *
 * `invalidateOpenFolder` is the poll leg of D-03's belt-and-suspenders
 * freshness: layered on top of the existing 30s poll (`useSyncPolling`'s
 * `doSync`), it re-resolves the CURRENTLY OPEN folder via the SDK's gated
 * `listFolder`/`ensureFolderLoaded` so a folder left open (no navigation
 * event to trigger the nav-triggered re-resolve leg, `useFolderNavigation.ts`)
 * still picks up remote changes (e.g. a write from another device).
 *
 * These tests simulate a poll tick observing a HIGHER `sequenceNumber` for
 * the open folder and assert the store's projection (children/rawChildren/
 * sequenceNumber) is actually invalidated and re-projected — not just that
 * the `listFolder` call site exists (closing the gap flagged in
 * `.planning/todos/pending/2026-07-06-d03-poll-invalidation-lacks-automated-coverage.md`,
 * per the "grep-based ACs can force runtime-broken impls" project landmine).
 *
 * Uses the REAL `useFolderStore` (a plain Zustand store, no React render
 * harness needed — mirrors `folder.store.test.ts`'s own pattern) with only
 * the SDK client boundary (`../lib/sdk-provider`) mocked.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ResolvedChild } from '@cipherbox/sdk';
import { useFolderStore, type FolderNode } from '../../stores/folder.store';
import { invalidateOpenFolder } from '../useSyncPolling';

const mockListFolder = vi.fn();
const mockEnsureFolderLoaded = vi.fn();
let mockHasSdkClient = true;

vi.mock('../../lib/sdk-provider', () => ({
  hasSdkClient: () => mockHasSdkClient,
  getSdkClient: () => ({
    listFolder: mockListFolder,
    ensureFolderLoaded: mockEnsureFolderLoaded,
  }),
}));

/** Build a ResolvedChild fixture with a recognizable name. */
function makeResolvedChild(name: string): ResolvedChild {
  return {
    ipnsName: `k51file-${name}`,
    name,
    kind: 'file',
    createdAt: 0,
    modifiedAt: 0,
    sequence: 0,
  };
}

/** Build a FolderNode fixture, loaded, for seeding the store. */
function makeOpenFolder(overrides: Partial<FolderNode>): FolderNode {
  return {
    id: 'f1',
    name: 'Folder',
    ipnsName: 'k51folder',
    parentId: 'root',
    children: [makeResolvedChild('old')],
    isLoaded: true,
    isLoading: false,
    sequenceNumber: 5n,
    folderKey: new Uint8Array(32).fill(1),
    ipnsPrivateKey: new Uint8Array(32).fill(2),
    ...overrides,
  };
}

describe('invalidateOpenFolder (D-03 poll-invalidation leg)', () => {
  beforeEach(() => {
    useFolderStore.setState({
      folders: {},
      currentFolderId: null,
      breadcrumbs: [],
      pendingPublishes: new Set<string>(),
    });
    mockListFolder.mockReset();
    mockEnsureFolderLoaded.mockReset();
    mockHasSdkClient = true;
  });

  it('re-resolves and re-projects the open folder when the poll observes a higher sequenceNumber', async () => {
    const folder = makeOpenFolder({});
    useFolderStore.getState().setFolder(folder);
    useFolderStore.getState().setCurrentFolder('f1');

    const newResolved = [makeResolvedChild('new')];
    const rawChildren = [
      {
        name: 'new',
        ipnsName: 'k51file-new',
        generation: 1,
        versionFloor: 0n,
        readKeySealed: 'AA',
      },
    ];
    mockListFolder.mockResolvedValue(newResolved);
    mockEnsureFolderLoaded.mockResolvedValue({
      children: rawChildren,
      sequenceNumber: 9n, // higher than the store's current 5n
    });

    await invalidateOpenFolder();

    expect(mockListFolder).toHaveBeenCalledWith('k51folder', { forceResolve: true });
    expect(mockEnsureFolderLoaded).toHaveBeenCalledWith('k51folder', { forceResolve: true });

    const after = useFolderStore.getState().folders['f1'];
    expect(after.children).toEqual(newResolved);
    expect(after.rawChildren).toEqual(rawChildren);
    expect(after.sequenceNumber).toBe(9n);
  });

  it('is a no-op when no folder is currently tracked as open', async () => {
    await invalidateOpenFolder();
    expect(mockListFolder).not.toHaveBeenCalled();
    expect(mockEnsureFolderLoaded).not.toHaveBeenCalled();
  });

  it('is a no-op when the tracked open folder has not finished loading', async () => {
    const folder = makeOpenFolder({ isLoaded: false });
    useFolderStore.getState().setFolder(folder);
    useFolderStore.getState().setCurrentFolder('f1');

    await invalidateOpenFolder();

    expect(mockListFolder).not.toHaveBeenCalled();
  });

  it('is a no-op when the SDK client has not been initialized yet', async () => {
    mockHasSdkClient = false;
    const folder = makeOpenFolder({});
    useFolderStore.getState().setFolder(folder);
    useFolderStore.getState().setCurrentFolder('f1');

    await invalidateOpenFolder();

    expect(mockListFolder).not.toHaveBeenCalled();
  });

  it('is best-effort — a resolve failure never throws out of the poll tick', async () => {
    const folder = makeOpenFolder({});
    useFolderStore.getState().setFolder(folder);
    useFolderStore.getState().setCurrentFolder('f1');

    mockListFolder.mockRejectedValue(new Error('IPNS resolve failed'));
    mockEnsureFolderLoaded.mockResolvedValue(null);

    await expect(invalidateOpenFolder()).resolves.toBeUndefined();

    // Store untouched on failure — the projection never reflects a broken resolve.
    const after = useFolderStore.getState().folders['f1'];
    expect(after.children).toEqual(folder.children);
    expect(after.sequenceNumber).toBe(5n);
  });

  it('discards a stale in-flight resolve if the open folder changed while awaiting', async () => {
    const folderA = makeOpenFolder({ id: 'f1', ipnsName: 'k51folder-a' });
    const folderB = makeOpenFolder({
      id: 'f2',
      ipnsName: 'k51folder-b',
      children: [makeResolvedChild('b-old')],
      sequenceNumber: 1n,
    });
    useFolderStore.getState().setFolder(folderA);
    useFolderStore.getState().setFolder(folderB);
    useFolderStore.getState().setCurrentFolder('f1');

    let releaseListFolder: (value: ResolvedChild[]) => void = () => {};
    mockListFolder.mockImplementation(
      () =>
        new Promise<ResolvedChild[]>((resolve) => {
          releaseListFolder = resolve;
        })
    );
    mockEnsureFolderLoaded.mockResolvedValue({
      children: [],
      sequenceNumber: 99n,
    });

    const invalidation = invalidateOpenFolder();

    // The user navigates away from folder A to folder B while the resolve is in flight.
    useFolderStore.getState().setCurrentFolder('f2');

    releaseListFolder([makeResolvedChild('a-stale')]);
    await invalidation;

    // Folder A's stale resolve must NOT have landed — the store no longer
    // considers it the open folder.
    const afterA = useFolderStore.getState().folders['f1'];
    expect(afterA.sequenceNumber).toBe(5n);
    expect(afterA.children).toEqual(folderA.children);
  });
});
