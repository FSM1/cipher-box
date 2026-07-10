import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { Node, SealedChildRef } from '@cipherbox/core';

// Mock sdk-core: keep everything real except the functions we need to control.
// - loadFolderMetadata: driven per-test to simulate on-demand fetch
// - updateFolderMetadataAndPublish: mocked to avoid real IPFS/IPNS calls in deleteItem
// - deleteFromFolder: mocked to return the removed item without real state mutation
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    deleteFromFolder: vi.fn(),
    // Phase 68 reconcile-before-publish (SC#3/D-04) now calls resolveIpnsRecord
    // ahead of every publish; mock it so deleteItem doesn't hit the real network.
    resolveIpnsRecord: vi.fn(),
  };
});

// Mock crypto: keep everything real except unwrapKey/hexToBytes/clearBytes which
// the on-demand traversal calls to unwrap subfolder keys. Return values are
// irrelevant — loadFolderMetadata is mocked, so the "decrypted" key is never
// used to actually decrypt anything.
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(9)),
    hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
    clearBytes: vi.fn(),
  };
});

// Mock api-client: ipnsControllerUnenrollBatch is called fire-and-forget by
// fireAndForgetUnenroll. Capture calls to verify the collected IPNS names.
vi.mock('@cipherbox/api-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/api-client')>();
  return {
    ...actual,
    ipnsControllerUnenrollBatch: vi.fn().mockResolvedValue(undefined),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import { ipnsControllerUnenrollBatch } from '@cipherbox/api-client';

const ROOT = 'k51root';
const PARENT = 'k51parent';
const SUBFOLDER = 'k51sub';
const SUBFOLDER_FILE = 'k51subfile';
const SIBLING_A = 'k51sibA';
const SIBLING_A_FILE = 'k51sibAfile';
const SIBLING_B = 'k51sibB';

function folderEntry(ipnsName: string, name: string): SealedChildRef {
  return {
    name,
    ipnsName,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: `sealed-${ipnsName}`,
  };
}

function filePointer(fileMetaIpnsName: string, name: string): SealedChildRef {
  return {
    name,
    ipnsName: fileMetaIpnsName,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: `sealed-${fileMetaIpnsName}`,
  };
}

function metadata(children: SealedChildRef[], nodeId: string): Node {
  return {
    schema: 'node/v3',
    kind: 'folder',
    id: nodeId,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children,
  };
}

/** Drive loadFolderMetadata to return canned metadata keyed by IPNS name. */
function mockTree(tree: Record<string, SealedChildRef[]>) {
  vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async ({ ipnsName }) => {
    const children = tree[ipnsName];
    if (!children) return null;
    return {
      metadata: metadata(children, `node-${ipnsName}`),
      sequenceNumber: 1n,
      cid: `cid-${ipnsName}`,
    };
  });
}

const rootIpnsKeypair = {
  publicKey: new Uint8Array(32).fill(7),
  privateKey: new Uint8Array(64).fill(8),
};

describe.skip('collectSubtreeIpnsNamesAsync — D-03 on-demand traversal — TODO(phase 65)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The failure-path tests intentionally exercise console.warn (e.g. "could not
    // load metadata ... skipping children"). Silence it to keep CI stderr clean;
    // the test(s) that trigger it assert on the call explicitly below.
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    // Restore defaults after clearAllMocks
    vi.mocked(ipnsControllerUnenrollBatch).mockResolvedValue(undefined as never);
    // Default deleteItem publish mock: returns updated children list, seq number, and cid
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      newSequenceNumber: 2n,
      publishedChildren: [],
      cid: 'cid-new',
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Test A: PARENT in folderTree with a FolderEntry child (SUBFOLDER) that is NOT
   * in folderTree. loadFolderMetadata returns SUBFOLDER's metadata with one file child.
   * The collected names must include PARENT, SUBFOLDER, and SUBFOLDER_FILE.
   *
   * RED: current sync collectSubtreeIpnsNames returns early on the folderTree miss
   * and returns only [PARENT], missing SUBFOLDER and SUBFOLDER_FILE.
   */
  it('Test A: collects names from unloaded subfolder via on-demand fetch', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsName: ROOT, rootIpnsKeypair }));

    // Seed folderTree with PARENT containing a FolderEntry for SUBFOLDER.
    // SUBFOLDER itself is NOT in folderTree (unloaded subtree).
    client.getFolderTree().set(PARENT, {
      ipnsName: PARENT,
      folderKey: new Uint8Array(32).fill(1),
      // All-zero: legacy zero-fallback writeKey (see FolderState doc comment
      // in types.ts) so getWriteBodyParams short-circuits to `{}` for these
      // deleteItem-driven traversal tests instead of requiring a real
      // IPNS-resolve/fetch mock.
      writeKey: new Uint8Array(32),
      ipnsKeypair: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(64).fill(2) },
      sequenceNumber: 1n,
      children: [folderEntry(SUBFOLDER, 'SubFolder')],
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: '',
      nodeGeneration: 0,
    });

    // loadFolderMetadata returns SUBFOLDER's metadata (one file child).
    mockTree({
      [SUBFOLDER]: [filePointer(SUBFOLDER_FILE, 'file.txt')],
    });

    // deleteFromFolder must return the SUBFOLDER FolderEntry as the removedItem
    // so that collectRemovedItemIpnsNames runs the folder subtree collection path.
    const removedFolder = folderEntry(SUBFOLDER, 'SubFolder');
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: removedFolder,
    });

    // Delete SUBFOLDER (the FolderEntry child) from PARENT.
    // This triggers collectRemovedItemIpnsNames -> collectSubtreeIpnsNames/Async for the FolderEntry.
    await client.deleteItem(PARENT, `id-${SUBFOLDER}`);

    // Wait for fire-and-forget async traversal to complete
    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    // Collect all names passed to unenrollBatch across all calls
    const allNames = vi
      .mocked(ipnsControllerUnenrollBatch)
      .mock.calls.flatMap((call) => call[0].ipnsNames);

    // Must include SUBFOLDER (the deleted folder), AND SUBFOLDER_FILE (loaded on demand).
    // RED: current sync code omits SUBFOLDER_FILE because it stops at the folderTree miss.
    expect(allNames).toContain(SUBFOLDER);
    expect(allNames).toContain(SUBFOLDER_FILE);
  });

  /**
   * Test B: Two sibling subfolders A and B, both NOT in folderTree.
   * loadFolderMetadata rejects for B, but resolves for A.
   * Collection must still contain A's file IPNS name, and must not throw.
   *
   * RED: current sync code returns early on folderTree miss for both A and B,
   * so SIBLING_A_FILE is never collected.
   */
  it('Test B: one child fetch failure does not abort sibling collection', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsName: ROOT, rootIpnsKeypair }));

    // GRANDPARENT has PARENT as its child. PARENT has SIBLING_A and SIBLING_B.
    // Neither PARENT nor the siblings are in folderTree (unloaded subtrees).
    const GRANDPARENT = 'k51grand';
    client.getFolderTree().set(GRANDPARENT, {
      ipnsName: GRANDPARENT,
      folderKey: new Uint8Array(32).fill(1),
      // All-zero: legacy zero-fallback writeKey (see FolderState doc comment
      // in types.ts) so getWriteBodyParams short-circuits to `{}` for these
      // deleteItem-driven traversal tests instead of requiring a real
      // IPNS-resolve/fetch mock.
      writeKey: new Uint8Array(32),
      ipnsKeypair: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(64).fill(2) },
      sequenceNumber: 1n,
      children: [folderEntry(PARENT, 'Parent')],
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: '',
      nodeGeneration: 0,
    });

    // loadFolderMetadata for PARENT returns two sibling children.
    // SIBLING_A resolves with a file child; SIBLING_B throws.
    vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async ({ ipnsName }) => {
      if (ipnsName === PARENT) {
        return {
          metadata: metadata(
            [folderEntry(SIBLING_A, 'SibA'), folderEntry(SIBLING_B, 'SibB')],
            `node-${ipnsName}`
          ),
          sequenceNumber: 1n,
          cid: `cid-${ipnsName}`,
        };
      }
      if (ipnsName === SIBLING_A) {
        return {
          metadata: metadata([filePointer(SIBLING_A_FILE, 'afile.txt')], `node-${ipnsName}`),
          sequenceNumber: 1n,
          cid: `cid-${ipnsName}`,
        };
      }
      // SIBLING_B fails
      throw new Error(`simulated fetch failure for ${ipnsName}`);
    });

    // deleteFromFolder returns PARENT FolderEntry as removedItem
    const removedParent = folderEntry(PARENT, 'Parent');
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: removedParent,
    });

    // Should not throw — deletion continues even when SIBLING_B fetch fails
    await expect(client.deleteItem(GRANDPARENT, `id-${PARENT}`)).resolves.not.toThrow();

    // Wait for fire-and-forget async traversal to complete
    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    // SIBLING_B's fetch failure is intentional — assert the warning was emitted so it
    // is asserted-intentional noise, not silent. The spy in beforeEach swallows it.
    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining(`could not load metadata for ${SIBLING_B}`)
    );

    const allNames = vi
      .mocked(ipnsControllerUnenrollBatch)
      .mock.calls.flatMap((call) => call[0].ipnsNames);

    // PARENT was deleted — must be unenrolled
    expect(allNames).toContain(PARENT);
    // SIBLING_A fetched successfully — its file IPNS must be unenrolled
    // RED: current sync code never calls loadFolderMetadata so SIBLING_A_FILE is missing
    expect(allNames).toContain(SIBLING_A_FILE);
    // SIBLING_B fetch failed — its own IPNS name must still be unenrolled
    expect(allNames).toContain(SIBLING_B);
  });

  /**
   * Test C: The on-demand traversal must NOT write to folderTree.
   * After collection, folderTree must not contain SUBFOLDER (which was loaded
   * on demand but must NOT be written to the shared folderTree map).
   *
   * GREEN trivially for the sync version (it doesn't call loadFolderMetadata at all),
   * but the async version MUST actively avoid writing fetched metadata to folderTree.
   */
  it('Test C: on-demand traversal does not mutate folderTree', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsName: ROOT, rootIpnsKeypair }));

    // Seed only PARENT in folderTree.
    client.getFolderTree().set(PARENT, {
      ipnsName: PARENT,
      folderKey: new Uint8Array(32).fill(1),
      // All-zero: legacy zero-fallback writeKey (see FolderState doc comment
      // in types.ts) so getWriteBodyParams short-circuits to `{}` for these
      // deleteItem-driven traversal tests instead of requiring a real
      // IPNS-resolve/fetch mock.
      writeKey: new Uint8Array(32),
      ipnsKeypair: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(64).fill(2) },
      sequenceNumber: 1n,
      children: [folderEntry(SUBFOLDER, 'SubFolder')],
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: '',
      nodeGeneration: 0,
    });

    mockTree({
      [SUBFOLDER]: [filePointer(SUBFOLDER_FILE, 'file.txt')],
    });

    const removedFolder = folderEntry(SUBFOLDER, 'SubFolder');
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: removedFolder,
    });

    await client.deleteItem(PARENT, `id-${SUBFOLDER}`);

    // Wait for fire-and-forget async traversal to complete (signalled by the
    // unenroll call that fires once collection finishes).
    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    // SUBFOLDER was fetched on demand but must NOT be written to folderTree.
    // The async traversal keeps fetched metadata locally — NOT in this.folderTree.
    expect(client.getFolderTree().has(SUBFOLDER)).toBe(false);
    // folderTree must only contain PARENT (the folder we seeded), not SUBFOLDER
    expect(client.getFolderTree().has(PARENT)).toBe(true);
  });

  /**
   * Test D (CR-01 regression): a cyclic folder graph A→B→A must terminate.
   *
   * Folder A's metadata lists folder B as a child, and B's metadata lists A.
   * Without the `visited` cycle guard this recurses until the call stack is
   * exhausted (RangeError: Maximum call stack size exceeded) or hangs fetching
   * the same IPNS names forever. With the guard, traversal terminates and each
   * IPNS name is collected exactly once (also covers IN-02 de-dup).
   */
  it('Test D: A→B→A folder cycle terminates and collects each name once', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsName: ROOT, rootIpnsKeypair }));

    const FOLDER_A = 'k51cycleA';
    const FOLDER_B = 'k51cycleB';

    // Seed PARENT in folderTree containing FOLDER_A (the deleted folder).
    client.getFolderTree().set(PARENT, {
      ipnsName: PARENT,
      folderKey: new Uint8Array(32).fill(1),
      // All-zero: legacy zero-fallback writeKey (see FolderState doc comment
      // in types.ts) so getWriteBodyParams short-circuits to `{}` for these
      // deleteItem-driven traversal tests instead of requiring a real
      // IPNS-resolve/fetch mock.
      writeKey: new Uint8Array(32),
      ipnsKeypair: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(64).fill(2) },
      sequenceNumber: 1n,
      children: [folderEntry(FOLDER_A, 'FolderA')],
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: '',
      nodeGeneration: 0,
    });

    // A lists B as a child; B lists A as a child — a cycle.
    mockTree({
      [FOLDER_A]: [folderEntry(FOLDER_B, 'FolderB')],
      [FOLDER_B]: [folderEntry(FOLDER_A, 'FolderA')],
    });

    const removedFolder = folderEntry(FOLDER_A, 'FolderA');
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: removedFolder,
    });

    // Must terminate (no stack overflow / no hang).
    await expect(client.deleteItem(PARENT, `id-${FOLDER_A}`)).resolves.not.toThrow();

    // Wait for fire-and-forget async traversal to complete
    await vi.waitFor(() => expect(ipnsControllerUnenrollBatch).toHaveBeenCalled());

    const allNames = vi
      .mocked(ipnsControllerUnenrollBatch)
      .mock.calls.flatMap((call) => call[0].ipnsNames);

    // Both folders collected.
    expect(allNames).toContain(FOLDER_A);
    expect(allNames).toContain(FOLDER_B);
    // Each name collected exactly once despite the cycle (visited de-dup, IN-02).
    expect(allNames.filter((n) => n === FOLDER_A)).toHaveLength(1);
    expect(allNames.filter((n) => n === FOLDER_B)).toHaveLength(1);
  });
});
