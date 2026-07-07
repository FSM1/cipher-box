/**
 * TDD tests for Phase 68 Plan 05: scope-exit read-key rotation and
 * reconcile-before-publish wiring at the SDK client chokepoint (client.ts).
 *
 * Covers:
 *  - Task 1: ReconcileStaleError / reconcile-before-publish (SC#3 / D-04)
 *  - Task 2: maybeRotateOnScopeExit wiring + injection seam (SC#2 / SC#4)
 *  - Task 3: moveItem dest-before-source publish ordering (D-12)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient, ReconcileStaleError } from '../client';
import { createTestConfig, setupFolder } from './helpers';
import { SequenceRegressionError } from '../state/rotation-high-water';
import type { RotationHighWater } from '../state/rotation-high-water';
import type { FolderState } from '../types';

// ── crypto mock ──────────────────────────────────────────────────────────
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x55)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(hex.length / 2)),
}));

// ── sdk-core mock ────────────────────────────────────────────────────────
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    renameInFolder: vi.fn(),
    deleteFromFolder: vi.fn(),
    moveItem: vi.fn(),
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    rotateReadFromNode: vi.fn(),
  };
});

// ── @cipherbox/core mock (moveItem's FLAG-63-U2 re-seal) ────────────────
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    sealChildReadKey: vi.fn().mockResolvedValue('resealed-dest-hex'),
    unsealChildReadKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0x42)),
  };
});

// ── bin / share mocks (not under test, silence missing-module errors) ────
vi.mock('../bin', () => ({
  loadBin: vi.fn(),
  addToBin: vi.fn(),
  restoreFromBin: vi.fn(),
  permanentDeleteFromBin: vi.fn(),
  emptyBin: vi.fn(),
  purgeExpiredEntries: vi.fn(),
}));

vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import * as binOps from '../bin';

const FOLDER_IPNS = 'folder-ipns';
const SRC_IPNS = 'src-ipns';
const DEST_IPNS = 'dest-ipns';

/** Mock resolveIpnsRecord to return a matching sequenceNumber for every call. */
function mockResolveMatching(sequenceNumber: bigint) {
  vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
    cid: 'bafyresolved',
    sequenceNumber,
    signatureVerified: true,
  });
}

describe('CipherBoxClient — reconcile-before-publish (SC#3 / D-04, Task 1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('ReconcileStaleError is instanceof-distinguishable with a stable name', () => {
    const err = new ReconcileStaleError('k51x', 1n, 2n);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ReconcileStaleError');
  });

  it('renameItem defers with ReconcileStaleError when the network sequence is AHEAD of the in-memory entry', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(2n); // network ahead of local (1n)

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
  });

  it('renameItem defers with ReconcileStaleError when the LOCAL entry is ahead of the network', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(0n); // network behind local (1n)

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('renameItem proceeds to publish when the sequences agree', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(1n); // agrees
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('renameItem proceeds when resolveIpnsRecord returns null (no record to reconcile against)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('deleteItem defers with ReconcileStaleError on sequence mismatch', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const child = setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: child,
    });
    mockResolveMatching(5n);

    await expect(client.deleteItem(FOLDER_IPNS, 'file1')).rejects.toThrow(ReconcileStaleError);
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('deleteToBin defers with ReconcileStaleError on sequence mismatch (before addToBin publishes)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(binOps.loadBin).mockResolvedValue({
      entries: [],
      sequenceNumber: 0,
      ipnsName: 'k51bin',
    });
    mockResolveMatching(9n);

    await expect(client.deleteToBin(FOLDER_IPNS, 'file1', 'My Vault')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(binOps.addToBin).not.toHaveBeenCalled();
  });

  it('moveItem defers with ReconcileStaleError when the SOURCE folder sequence mismatches', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS); // sequenceNumber: 1n
    setupFolder(client, DEST_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === SRC_IPNS) return { cid: 'x', sequenceNumber: 99n, signatureVerified: true };
      return { cid: 'x', sequenceNumber: 1n, signatureVerified: true };
    });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, 'file1')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('moveItem defers with ReconcileStaleError when the DEST folder sequence mismatches', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS); // sequenceNumber: 1n
    setupFolder(client, DEST_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === DEST_IPNS) return { cid: 'x', sequenceNumber: 99n, signatureVerified: true };
      return { cid: 'x', sequenceNumber: 1n, signatureVerified: true };
    });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, 'file1')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });
});

describe('CipherBoxClient — scope-exit rotation wiring (SC#2 / SC#4, Task 2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveMatching(1n); // reconcile always agrees in these tests
  });

  it('renameItem rotates exactly once when the folder has a covering grant', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set([FOLDER_IPNS]),
          getLocalGrantRecord: () => null,
          persistJob: vi.fn(),
        },
      })
    );
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue(undefined);

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    expect(sdkCore.rotateReadFromNode).toHaveBeenCalledTimes(1);
  });

  it('renameItem performs zero rotation when uncovered (default no-op callbacks)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
  });

  it('renameItem rotates when covered via the local grant record cross-check alone (T-63-17)', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set(), // relay omits it
          getLocalGrantRecord: (ipnsName) =>
            ipnsName === FOLDER_IPNS ? { rootIpnsName: FOLDER_IPNS } : null,
          persistJob: vi.fn(),
        },
      })
    );
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue(undefined);

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    expect(sdkCore.rotateReadFromNode).toHaveBeenCalledTimes(1);
  });

  it('deleteItem rotates exactly once when covered', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set([FOLDER_IPNS]),
          getLocalGrantRecord: () => null,
          persistJob: vi.fn(),
        },
      })
    );
    const child = setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: child,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue(undefined);

    await client.deleteItem(FOLDER_IPNS, 'file1');

    expect(sdkCore.rotateReadFromNode).toHaveBeenCalledTimes(1);
  });

  it('deleteToBin performs zero rotation when uncovered', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(binOps.loadBin).mockResolvedValue({
      entries: [],
      sequenceNumber: 0,
      ipnsName: 'k51bin',
    });
    vi.mocked(binOps.addToBin).mockResolvedValue({
      removedItem: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
      updatedBinState: { entries: [], sequenceNumber: 1, ipnsName: 'k51bin' },
    });

    await client.deleteToBin(FOLDER_IPNS, 'file1', 'My Vault');

    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
  });

  it('moveItem rotates the SOURCE folder exactly once when the source has a covering grant', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set([SRC_IPNS]),
          getLocalGrantRecord: () => null,
          persistJob: vi.fn(),
        },
      })
    );
    setupFolder(client, SRC_IPNS);
    setupFolder(client, DEST_IPNS);
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [
        { name: 'x', ipnsName: 'k51file', generation: 0, versionFloor: 0n, readKeySealed: 'x' },
      ],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ id: 'file1', kind: 'file' }))
    );
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue(undefined);

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'file1');

    expect(sdkCore.rotateReadFromNode).toHaveBeenCalledTimes(1);
  });

  it('moveItem performs zero rotation when uncovered', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS);
    setupFolder(client, DEST_IPNS);
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [
        { name: 'x', ipnsName: 'k51file', generation: 0, versionFloor: 0n, readKeySealed: 'x' },
      ],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ id: 'file1', kind: 'file' }))
    );
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'file1');

    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
  });
});

describe('CipherBoxClient — folderTree refresh after scope-exit rotation (Gap 2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveMatching(1n); // reconcile always agrees unless a test overrides it
  });

  it('refreshes the folderTree entry with the rotated readKey/generation/sequenceNumber after a covered mutation', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set([FOLDER_IPNS]),
          getLocalGrantRecord: () => null,
          persistJob: vi.fn(),
        },
      })
    );
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n, nodeGeneration: 0
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    const rotatedReadKey = new Uint8Array(32).fill(0x99);
    // Snapshot the expected bytes BEFORE the call: performScopeExitRotation is
    // now the terminal owner of `rotationResult.readKey` (Task 1, T-70-13) and
    // zeroes `rotatedReadKey` IN PLACE by the time this resolves, so comparing
    // against the live `rotatedReadKey` reference post-call would compare
    // zeroed bytes against themselves.
    const expectedRotatedBytes = new Uint8Array(rotatedReadKey);
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue({
      readKey: rotatedReadKey,
      generation: 5,
      sequenceNumber: 10n,
    });

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    const state = client.getFolderTree().get(FOLDER_IPNS);
    expect(state).toBeDefined();
    expect(state?.folderKey).toEqual(expectedRotatedBytes);
    expect(state?.sequenceNumber).toBe(10n);
    expect(state?.nodeGeneration).toBe(5);
  });

  it('T-70-13 / SC#6: zeroes rotationResult.readKey as terminal owner without touching the folderTree copy or the caller-owned rootReadKey (paired zeroization invariant)', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set([FOLDER_IPNS]),
          getLocalGrantRecord: () => null,
          persistJob: vi.fn(),
        },
      })
    );
    setupFolder(client, FOLDER_IPNS); // seeds folderKey = new Uint8Array(32).fill(1)

    // Capture the CALLER-OWNED rootReadKey buffer reference BEFORE the
    // mutation. `performScopeExitRotation` is invoked with
    // `rootReadKey: folder.folderKey`, which (until `FolderTree.set`'s
    // defensive-copy swap replaces the map entry) is the exact same object
    // reference as this pre-mutation folderTree entry's `folderKey`.
    const beforeState = client.getFolderTree().get(FOLDER_IPNS)!;
    const callerRootReadKeyRef = beforeState.folderKey;
    const callerRootReadKeySnapshot = new Uint8Array(callerRootReadKeyRef);

    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    const rotationEngineReadKey = new Uint8Array(32).fill(0x77);
    const rotationEngineReadKeySnapshot = new Uint8Array(rotationEngineReadKey);
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue({
      readKey: rotationEngineReadKey,
      generation: 3,
      sequenceNumber: 7n,
    });

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    // (a) the engine-returned readKey IS zeroed by its new terminal owner.
    expect(rotationEngineReadKey).toEqual(new Uint8Array(32).fill(0));

    // (b) the folderTree's OWN independent defensive copy is UNCHANGED --
    // still holds the rotated bytes, never zeroed.
    const afterState = client.getFolderTree().get(FOLDER_IPNS);
    expect(afterState?.folderKey).toEqual(rotationEngineReadKeySnapshot);
    expect(afterState?.folderKey).not.toBe(rotationEngineReadKey); // distinct buffer

    // (c) the caller-owned rootReadKey buffer is UNCHANGED (never zeroed).
    expect(callerRootReadKeyRef).toEqual(callerRootReadKeySnapshot);
  });

  it('a second same-folder mutation after a covered rotation does NOT throw ReconcileStaleError (self-heals without a page reload)', async () => {
    const client = new CipherBoxClient(
      createTestConfig({
        rotationCallbacks: {
          getActiveGrantRootIpnsNames: async () => new Set([FOLDER_IPNS]),
          getLocalGrantRecord: () => null,
          persistJob: vi.fn(),
        },
      })
    );
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    // The rotation republish advances the REAL network sequence to 3n (root cut).
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue({
      readKey: new Uint8Array(32).fill(0x99),
      generation: 1,
      sequenceNumber: 3n,
    });
    mockResolveMatching(1n); // first mutation's reconcile agrees with pre-rotation state

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    // Second mutation: the network now resolves at the ROTATED sequence (3n).
    // Pre-68-12 the in-memory folderTree would still read 2n (never refreshed
    // by the rotation) and this reconcile would throw ReconcileStaleError.
    mockResolveMatching(3n);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew2',
      newSequenceNumber: 4n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockResolvedValue(undefined);

    await client.renameItem(FOLDER_IPNS, 'file1', 'renamed-again.txt');

    expect(client.getFolderTree().get(FOLDER_IPNS)?.sequenceNumber).toBe(4n);
  });

  it('leaves folderTree unchanged when the mutation is uncovered (rotateReadFromNode not invoked)', async () => {
    const client = new CipherBoxClient(createTestConfig()); // no rotationCallbacks => NOOP => never covered
    setupFolder(client, FOLDER_IPNS);
    const before = client.getFolderTree().get(FOLDER_IPNS)!;
    const beforeFolderKeyCopy = new Uint8Array(before.folderKey);

    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await client.renameItem(FOLDER_IPNS, 'file1', 'new.txt');

    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
    const after = client.getFolderTree().get(FOLDER_IPNS);
    expect(after?.folderKey).toEqual(beforeFolderKeyCopy);
    expect(after?.nodeGeneration).toBe(0);
    expect(after?.sequenceNumber).toBe(2n); // advanced only by the mutation's own publish
  });
});

describe('CipherBoxClient — RootKeyStaleError top-down re-navigation fallback (Plan 70-07 Task 2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveMatching(1n); // reconcile always agrees in these tests
  });

  function rotationCoveredConfig() {
    return createTestConfig({
      rotationCallbacks: {
        getActiveGrantRootIpnsNames: async () => new Set([FOLDER_IPNS]),
        getLocalGrantRecord: () => null,
        persistJob: vi.fn(),
      },
    });
  }

  it('recovers via top-down re-navigation and does not fail the (already-published) mutation', async () => {
    const client = new CipherBoxClient(rotationCoveredConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockRejectedValue(
      new sdkCore.RootKeyStaleError('root record exists but unseal failed with the supplied key')
    );
    // Only the FALLBACK call (triggered from inside performScopeExitRotation's
    // catch block) is stubbed — the FIRST call (requireFolder's own
    // pre-mutation cache-hit load) must call through to the real
    // implementation, or `folder` would come back missing folderKey/nodeId/
    // ipnsKeypair and the mutation itself could never proceed.
    const realEnsureFolderLoaded = client.ensureFolderLoaded.bind(client);
    let ensureFolderLoadedCalls = 0;
    const ensureFolderLoadedSpy = vi
      .spyOn(client, 'ensureFolderLoaded')
      .mockImplementation(async (ipnsName, opts) => {
        ensureFolderLoadedCalls += 1;
        if (ensureFolderLoadedCalls === 1) return realEnsureFolderLoaded(ipnsName, opts);
        return { ipnsName: FOLDER_IPNS } as FolderState;
      });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();

    // The mutation (rename) itself already published successfully BEFORE
    // performScopeExitRotation ran — the stale-key recovery on the SECONDARY
    // rotation step must not fail it (Gap-2's folderTree refresh is simply
    // skipped on this path: rotationResult stays undefined, and rotation
    // itself is deferred to the NEXT covered scope-exit mutation).
    expect(sdkCore.rotateReadFromNode).toHaveBeenCalledTimes(1);
    expect(ensureFolderLoadedSpy).toHaveBeenCalledWith(FOLDER_IPNS);
  });

  it('surfaces a clear, actionable error (not a generic AEAD failure) when top-down re-navigation also cannot recover the root', async () => {
    const client = new CipherBoxClient(rotationCoveredConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    const staleErr = new sdkCore.RootKeyStaleError(
      'root record exists but unseal failed with the supplied key'
    );
    vi.mocked(sdkCore.rotateReadFromNode).mockRejectedValue(staleErr);
    // As above: only the FALLBACK call resolves null (unrecoverable); the
    // FIRST call (requireFolder's pre-mutation load) calls through for real.
    const realEnsureFolderLoaded = client.ensureFolderLoaded.bind(client);
    let ensureFolderLoadedCalls = 0;
    const ensureFolderLoadedSpy = vi
      .spyOn(client, 'ensureFolderLoaded')
      .mockImplementation(async (ipnsName, opts) => {
        ensureFolderLoadedCalls += 1;
        if (ensureFolderLoadedCalls === 1) return realEnsureFolderLoaded(ipnsName, opts);
        return null;
      });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      /top-down|re-navigation|vault root/i
    );
    expect(ensureFolderLoadedSpy).toHaveBeenCalledWith(FOLDER_IPNS);
  });

  it('does not catch a non-RootKeyStaleError from rotateReadFromNode — propagates as-is without attempting re-navigation', async () => {
    const client = new CipherBoxClient(rotationCoveredConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
    vi.mocked(sdkCore.rotateReadFromNode).mockRejectedValue(
      new Error('AEAD authentication failed')
    );
    const ensureFolderLoadedSpy = vi.spyOn(client, 'ensureFolderLoaded');

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      'AEAD authentication failed'
    );
    // requireFolder's OWN earlier ensureFolderLoaded call (cache hit) happens
    // regardless — assert the fallback path's SECOND call never fires by
    // checking it was never called with a fresh mock-return override tied to
    // recovery (i.e. call count stays at the single pre-rotation load).
    expect(ensureFolderLoadedSpy).toHaveBeenCalledTimes(1);
  });
});

describe('CipherBoxClient.moveItem — dest-before-source publish ordering (D-12, Task 3)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResolveMatching(1n); // reconcile always agrees in these tests
  });

  it('publishes the DESTINATION folder before the SOURCE folder', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS);
    setupFolder(client, DEST_IPNS);
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [
        { name: 'x', ipnsName: 'k51file', generation: 0, versionFloor: 0n, readKeySealed: 'x' },
      ],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ id: 'file1', kind: 'file' }))
    );

    const order: string[] = [];
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (params) => {
      order.push(params.ipnsName === DEST_IPNS ? 'publish:dest' : 'publish:source');
      return { cid: 'bafynew', newSequenceNumber: 2n, publishedChildren: [] };
    });

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'file1');

    expect(order).toEqual(['publish:dest', 'publish:source']);
  });

  it('does not invoke descendant enumeration for a moved FILE (kind !== folder/root)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS);
    setupFolder(client, DEST_IPNS);
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [
        { name: 'x', ipnsName: 'k51file', generation: 0, versionFloor: 0n, readKeySealed: 'x' },
      ],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    // kind: 'file' -- enumerateMoveDescendants must short-circuit and never
    // issue a SECOND resolveIpnsRecord/fetchFromIpfs round for descendants.
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ id: 'file1', kind: 'file' }))
    );
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'file1');
    // Flush the fire-and-forget microtask queue so a would-be second call
    // to fetchFromIpfs (if the file-kind short-circuit were missing) has a
    // chance to happen before we assert.
    await Promise.resolve();
    await Promise.resolve();

    // Exactly one resolveIpnsRecord/fetchFromIpfs round for the moved child's
    // own id/kind (FLAG-63-U2) plus the two reconcile calls (source, dest) --
    // no additional descendant-walk calls for a file-kind move.
    expect(sdkCore.fetchFromIpfs).toHaveBeenCalledTimes(1);
  });
});

describe('CipherBoxClient — reconcile-time enforceResolved fail-closed (Gap 1 / SC#4)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  /** A fake RotationHighWater whose enforceResolved is a controllable vi.fn(). */
  function fakeRotationHighWater(enforceResolved: RotationHighWater['enforceResolved']) {
    return {
      getGenerationFloor: vi.fn(),
      bumpGeneration: vi.fn(),
      seedFromGrant: vi.fn(),
      getSeqFloor: vi.fn(),
      bumpSeq: vi.fn(),
      enforceResolved: vi.fn(enforceResolved),
    } satisfies RotationHighWater;
  }

  it('renameItem rejects with SequenceRegressionError when enforceResolved throws on a below-floor resolve, and rotateReadFromNode is NOT called', async () => {
    const rotationHighWater = fakeRotationHighWater(async ({ nodeId, seq }) => {
      throw new SequenceRegressionError(nodeId, 999, seq);
    });
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n, nodeGeneration: 0
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(1n); // agrees with expectedSequence -- enforceResolved is the sole gate here

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      SequenceRegressionError
    );
    expect(rotationHighWater.enforceResolved).toHaveBeenCalledTimes(1);
    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('renameItem proceeds to publish when enforceResolved resolves (above-floor resolve)', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(1n);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();
    expect(rotationHighWater.enforceResolved).toHaveBeenCalledTimes(1);
    expect(rotationHighWater.enforceResolved).toHaveBeenCalledWith(
      expect.objectContaining({
        nodeId: FOLDER_IPNS,
        seq: 1,
        generation: 0,
        versionFloor: 1,
      })
    );
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('renameItem refuses to gate floors on an UNVERIFIED resolve — throws before enforceResolved is ever called', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    // A relay returning an unverified record with a forged, inflated seq must
    // never reach enforceResolved -- it would bump the durable floor and
    // permanently wedge every future mutation behind SequenceRegressionError.
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafyforged',
      sequenceNumber: 999999n,
      signatureVerified: false,
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      /unverified record/
    );
    expect(rotationHighWater.enforceResolved).not.toHaveBeenCalled();
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('renameItem never invokes enforceResolved when the client has no rotationHighWater configured (backward-compat)', async () => {
    const client = new CipherBoxClient(createTestConfig()); // no rotationHighWater
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(1n);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });
});
