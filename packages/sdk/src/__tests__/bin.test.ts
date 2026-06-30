import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadBin, addToBin, restoreFromBin, permanentDeleteFromBin, emptyBin } from '../bin';
import type { BinOperationContext, BinState } from '../bin';
import { FolderTree } from '../state/folder-tree';

// Mock sdk-core
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    deleteFromFolder: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    addToIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    resolveFileMetadata: vi.fn(),
    updateFileMetadata: vi.fn(),
    loadFolderMetadata: vi.fn(),
  };
});

// Mock @cipherbox/core: keep sealChildReadKey real for AEAD asymmetry proof;
// mock ECIES helpers (they require live secp256k1 keys we do not have in unit tests)
// and mock unsealChildReadKey so basic flow tests do not need valid AES-GCM blobs.
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    encryptBinMetadata: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    decryptBinMetadata: vi
      .fn()
      .mockResolvedValue({ version: 'v1', sequenceNumber: 1, entries: [] }),
    deriveBinIpnsKeypair: vi.fn().mockResolvedValue({
      ipnsName: 'k51bin',
      privateKey: new Uint8Array(64).fill(5),
      publicKey: new Uint8Array(32).fill(6),
    }),
    // unsealChildReadKey is mocked so flow tests can inject any key without
    // a real AES-GCM blob; AEAD test overrides via vi.importActual.
    unsealChildReadKey: vi.fn(),
  };
});

// Mock @cipherbox/crypto: keep real AES-GCM primitives so sealChildReadKey /
// unsealChildReadKey (from @cipherbox/core) work in the AEAD asymmetry test;
// mock only ECIES helpers that require live secp256k1 keys.
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    bytesToHex: vi.fn().mockReturnValue('aabb'),
    hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
    wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xaa])),
    unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(7)),
    clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import { unsealChildReadKey } from '@cipherbox/core';

const binCtx: BinOperationContext = {
  ctx: { apiUrl: 'http://localhost:3000', getAccessToken: async () => 'token' },
  userPrivateKey: new Uint8Array(32).fill(1),
  userPublicKey: new Uint8Array(33).fill(2),
  rootFolderKey: new Uint8Array(32).fill(3),
};

describe('bin operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('loadBin', () => {
    it('returns in-memory empty state WITHOUT publishing when no IPNS record exists', async () => {
      // A null resolve is NOT a reliable "bin is empty" signal — publishing an
      // empty record here is destructive (the bin publish path carries no
      // expectedSequenceNumber, so the API blindly increments and overwrites the
      // real record's CID, wiping every entry). loadBin must therefore return an
      // in-memory empty state and NEVER publish on a null resolve. The bounded
      // retry resolves null on every attempt here (genuinely-new bin).
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

      const result = await loadBin({ binCtx });

      // Empty in-memory state with seq 0 so the first addToBin publishes at
      // 0 + 1 = 1, matching the API create-path.
      expect(result.entries).toEqual([]);
      expect(result.sequenceNumber).toBe(0);
      expect(result.ipnsName).toBe('k51bin');
      // Critically: NO publish happened — no empty bin was written.
      expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
      expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
    });

    it('retries the resolve before falling back to empty state, without publishing', async () => {
      // Bounded retry on a persistent null: still falls back to the empty
      // in-memory state, and still never publishes.
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

      const result = await loadBin({ binCtx });

      // resolveIpnsRecord retried up to the bounded maximum (6 attempts).
      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(6);
      expect(result.sequenceNumber).toBe(0);
      // No publish on any attempt.
      expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
    });

    it('does NOT clobber a real record when the first resolve is a transient (cold-cache) null', async () => {
      // The first resolve misses (e.g. cold resolve cache right after a reload),
      // but the bin actually holds a deleted entry at sequenceNumber 2. The bounded
      // retry must surface it WITHOUT publishing the destructive empty-bin record.
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce(null) // transient miss on initial load
        .mockResolvedValueOnce({ cid: 'bafyreal', sequenceNumber: 2n, signatureVerified: true }); // retry finds the real record
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(new Uint8Array([9]));
      const { decryptBinMetadata } = await import('@cipherbox/core');
      vi.mocked(decryptBinMetadata).mockResolvedValue({
        version: 'v1',
        sequenceNumber: 2,
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'f.txt',
            originalParentIpnsName: 'sub-ipns',
            originalPath: 'My Vault / sub',
            deletedAt: Date.now(),
            size: 0,
            mimeType: '',
          },
        ],
      });

      const result = await loadBin({ binCtx });

      expect(result.entries.map((e) => e.name)).toEqual(['f.txt']);
      expect(result.sequenceNumber).toBe(2);
      // Critically: no empty-bin publish happened, so the real record is preserved.
      expect(sdkCore.createAndPublishIpnsRecord).not.toHaveBeenCalled();
      expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
    });

    it('returns existing bin state when IPNS record found', async () => {
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 3n,
        signatureVerified: true,
      });
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(new Uint8Array([1]));

      const { decryptBinMetadata } = await import('@cipherbox/core');
      vi.mocked(decryptBinMetadata).mockResolvedValue({
        version: 'v1',
        sequenceNumber: 3,
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
      });

      const result = await loadBin({ binCtx });

      expect(result.entries).toHaveLength(1);
      expect(result.sequenceNumber).toBe(3);
    });
  });

  describe('addToBin', () => {
    // Shared SealedChildRef fixture for file child
    const fileRef = {
      name: 'doc.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'sealed-base64-placeholder',
    };

    // PublishedNode JSON bytes returned by fetchFromIpfs for the child's IPNS record.
    // addToBin reads id and kind from the plaintext envelope to build AAD for
    // unsealChildReadKey (mirrors the moveItem pattern in client.ts lines 589-606).
    const childPublishedNode = new TextEncoder().encode(
      JSON.stringify({
        schema: 'node/v3',
        kind: 'file',
        id: 'node-id-f1',
        generation: 0,
        aeadVersion: 1,
        readSealed: 'aaaa',
      })
    );

    const capturedNodeReadKey = new Uint8Array(32).fill(0xbc);

    function setupAddToBinMocks() {
      // Child IPNS resolve + fetch (for id/kind extraction)
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce({ cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true }) // child resolve
        .mockResolvedValue({ cid: 'bafybin', sequenceNumber: 1n, signatureVerified: true }); // bin verify
      vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(childPublishedNode);
      // deleteFromFolder is a pure sync transform in sdk-core
      vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
        updatedChildren: [],
        removedItem: fileRef,
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 1n,
      });
      // unsealChildReadKey returns the captured nodeReadKey for basic flow tests
      vi.mocked(unsealChildReadKey).mockResolvedValue(capturedNodeReadKey);
    }

    it('removes item from source folder, captures nodeReadKey, and stores it in the bin entry', async () => {
      setupAddToBinMocks();

      const folderTree = new FolderTree();
      folderTree.set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32).fill(0x11),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [fileRef],
        metadata: null,
        lastLoadedAt: Date.now(),
        nodeId: 'parent-node-id',
        nodeGeneration: 0,
      });

      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      const result = await addToBin({
        folderIpnsName: 'folder-ipns',
        childId: 'k51child',
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
      });

      expect(result.removedItem).toEqual(fileRef);
      expect(result.updatedBinState.entries).toHaveLength(1);
      const entry = result.updatedBinState.entries[0];
      expect(entry.name).toBe('doc.txt');
      expect(entry.nodeIpnsName).toBe('k51child');
      // nodeReadKey recovered from the source ref
      expect(entry.nodeReadKey).toEqual(capturedNodeReadKey);
      expect(result.updatedBinState.sequenceNumber).toBe(1);
    });

    it('revokes shares for the child BEFORE the destructive folder publish', async () => {
      setupAddToBinMocks();

      const folderTree = new FolderTree();
      folderTree.set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [fileRef],
        metadata: null,
        lastLoadedAt: Date.now(),
        nodeId: 'parent-node-id',
        nodeGeneration: 0,
      });

      const revokeSharesForItemsFn = vi.fn().mockResolvedValue(undefined);
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await addToBin({
        folderIpnsName: 'folder-ipns',
        childId: 'k51child',
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
        revokeSharesForItemsFn,
      });

      // Revoke called with the child's ipnsName
      expect(revokeSharesForItemsFn).toHaveBeenCalledWith(['k51child']);
      // Revoke happened BEFORE the folder publish
      const revokeOrder = revokeSharesForItemsFn.mock.invocationCallOrder[0];
      const publishOrder = vi.mocked(sdkCore.updateFolderMetadataAndPublish).mock
        .invocationCallOrder[0];
      expect(revokeOrder).toBeLessThan(publishOrder);
    });

    it('aborts without folder publish when share revocation fails', async () => {
      // Self-contained: set up all upstream mocks so the flow reaches revocation
      // independently of test execution order.
      setupAddToBinMocks();

      const folderTree = new FolderTree();
      folderTree.set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32),
        ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
        sequenceNumber: 1n,
        children: [fileRef],
        metadata: null,
        lastLoadedAt: Date.now(),
        nodeId: 'parent-node-id',
        nodeGeneration: 0,
      });

      const revokeSharesForItemsFn = vi.fn().mockRejectedValue(new Error('revoke failed'));
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        addToBin({
          folderIpnsName: 'folder-ipns',
          childId: 'k51child',
          parentPath: 'My Vault',
          folderTree,
          binState,
          binCtx,
          revokeSharesForItemsFn,
        })
      ).rejects.toThrow('revoke failed');

      // Destructive folder mutation must NOT have run
      expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
    });

    it('throws when folder is not loaded', async () => {
      const folderTree = new FolderTree();
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        addToBin({
          folderIpnsName: 'nonexistent',
          childId: 'k51child',
          parentPath: '/',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('Folder not loaded');
    });
  });

  describe('restoreFromBin', () => {
    // Shared node metadata fixture — carried on BinEntry.nodeRef for AAD binding
    // NOTE: id must be a valid UUID (uuidToBytes validates format for real sealChildReadKey)
    const nodeRef = {
      schema: 'node/v3' as const,
      kind: 'file' as const,
      id: '00000000-0000-0000-0000-000000000001',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
    };
    const nodeReadKey = new Uint8Array(32).fill(0xaa);
    const PLACEHOLDER_TARGET = {
      ipnsName: 'target-ipns',
      folderKey: new Uint8Array(32),
      ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
      sequenceNumber: 1n,
      children: [] as import('@cipherbox/core').SealedChildRef[],
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: 'target-node-id',
      nodeGeneration: 0,
    };

    function makeBasicBinState(
      extras: Partial<import('../bin').BinState['entries'][number]> = {}
    ): import('../bin').BinState {
      return {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'doc.txt',
            originalParentIpnsName: 'source-ipns',
            originalPath: '/old',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            nodeReadKey,
            nodeIpnsName: 'k51child',
            nodeRef,
            ...extras,
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };
    }

    function setupRestoreMocks() {
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });
    }

    it('restores item to target folder by re-sealing nodeReadKey under destination parent readKey', async () => {
      setupRestoreMocks();
      // sealChildReadKey is real (from importOriginal spread); spy and mock for this flow test.
      // Use sealSpy.mockRestore() (NOT vi.restoreAllMocks) to avoid resetting module-level
      // vi.fn() mocks (deriveBinIpnsKeypair etc.) that subsequent tests depend on.
      const fakeSealedKey = 'c2VhbGVkLWtleS1iYXNlNjQ='; // valid base64
      const coreModule = await import('@cipherbox/core');
      const sealSpy = vi.spyOn(coreModule, 'sealChildReadKey').mockResolvedValue(fakeSealedKey);

      const folderTree = new FolderTree();
      folderTree.set('target-ipns', PLACEHOLDER_TARGET);

      const result = await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState: makeBasicBinState(),
        binCtx,
      });

      // Entry removed from bin
      expect(result.updatedBinState.entries).toHaveLength(0);
      // Restored item is a SealedChildRef with correct fields
      expect(result.restoredItem.name).toBe('doc.txt');
      expect(result.restoredItem.ipnsName).toBe('k51child');
      expect(result.restoredItem.readKeySealed).toBe(fakeSealedKey);

      // Restore only this spy so subsequent tests get the real sealChildReadKey
      sealSpy.mockRestore();
    });

    it('re-link AEAD asymmetry: restoredItem.readKeySealed unseals under dest parent and fails under source parent', async () => {
      // This test uses the REAL sealChildReadKey and unsealChildReadKey so the
      // AEAD property is proven with actual AES-256-GCM (role 0x02 child-readkey AAD).
      // sealChildReadKey is real (spread from importOriginal in the @cipherbox/core mock).
      // unsealChildReadKey is retrieved via vi.importActual to bypass the flow-test mock.
      const { unsealChildReadKey: realUnseal } =
        await vi.importActual<typeof import('@cipherbox/core')>('@cipherbox/core');

      setupRestoreMocks();

      const destParentReadKey = new Uint8Array(32).fill(0x22);
      const sourceParentReadKey = new Uint8Array(32).fill(0x11); // different — must NOT unseal

      const folderTree = new FolderTree();
      folderTree.set('target-ipns', {
        ...PLACEHOLDER_TARGET,
        folderKey: destParentReadKey,
      });

      const result = await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState: makeBasicBinState(),
        binCtx,
      });

      // Re-link is bound to destParentReadKey — unseals under dest, rejects under source
      await expect(
        realUnseal(result.restoredItem.readKeySealed, destParentReadKey, nodeRef.id, 'file', 0)
      ).resolves.toBeDefined();
      await expect(
        realUnseal(result.restoredItem.readKeySealed, sourceParentReadKey, nodeRef.id, 'file', 0)
      ).rejects.toThrow();
    });

    it('throws when bin entry is not found', async () => {
      const folderTree = new FolderTree();
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        restoreFromBin({
          entryId: 'nonexistent',
          targetFolderIpnsName: 'k51',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('Bin entry not found');
    });

    it('throws when target folder is not loaded', async () => {
      const folderTree = new FolderTree(); // target NOT in tree

      await expect(
        restoreFromBin({
          entryId: 'e1',
          targetFolderIpnsName: 'target-ipns',
          folderTree,
          binState: makeBasicBinState(),
          binCtx,
        })
      ).rejects.toThrow('Folder not loaded');
    });

    it('throws when nodeReadKey is missing on the bin entry', async () => {
      const folderTree = new FolderTree();
      folderTree.set('target-ipns', PLACEHOLDER_TARGET);

      await expect(
        restoreFromBin({
          entryId: 'e1',
          targetFolderIpnsName: 'target-ipns',
          folderTree,
          binState: makeBasicBinState({ nodeReadKey: undefined }),
          binCtx,
        })
      ).rejects.toThrow(/nodeReadKey/);
    });

    it('is idempotent on retry — does not duplicate restored child if already present in target folder', async () => {
      // Simulates: folder publish succeeded, then saveBinMetadata failed.
      // On retry the item is already in the target folder; restore must NOT append a duplicate.
      setupRestoreMocks();
      const fakeSealedKey = 'c2VhbGVkLWtleS1iYXNlNjQ=';
      const coreModule = await import('@cipherbox/core');
      const sealSpy = vi.spyOn(coreModule, 'sealChildReadKey').mockResolvedValue(fakeSealedKey);

      const existingRef: import('@cipherbox/core').SealedChildRef = {
        name: 'doc.txt',
        ipnsName: 'k51child', // same ipnsName as entry.nodeIpnsName
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'already-sealed-key',
      };

      const folderTree = new FolderTree();
      folderTree.set('target-ipns', {
        ...PLACEHOLDER_TARGET,
        children: [existingRef], // item already in folder
      });

      const result = await restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: 'target-ipns',
        folderTree,
        binState: makeBasicBinState(),
        binCtx,
      });

      // Publish was still called (may need to complete the CAS / sequence bump)
      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledOnce();
      // Children passed to publish contain exactly ONE entry for this ipnsName (no duplicate)
      const [publishCall] = vi.mocked(sdkCore.updateFolderMetadataAndPublish).mock.calls;
      const published = publishCall[0].children;
      expect(published.filter((c) => c.ipnsName === 'k51child')).toHaveLength(1);

      // Bin cleanup still ran — entry removed from bin state
      expect(result.updatedBinState.entries).toHaveLength(0);

      sealSpy.mockRestore();
    });

    // Legacy placeholder block kept for reference — these tests remain
    it('throws when bin entry not found', async () => {
      const folderTree = new FolderTree();
      const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };

      await expect(
        restoreFromBin({
          entryId: 'nonexistent',
          targetFolderIpnsName: 'k51',
          folderTree,
          binState,
          binCtx,
        })
      ).rejects.toThrow('Bin entry not found');
    });
  });

  describe('permanentDeleteFromBin', () => {
    it('removes entry from bin and unpins CID', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      // publishWithVerify will call resolveIpnsRecord to verify
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 100,
            mimeType: '',
            contentCid: 'bafycontent',
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      const result = await permanentDeleteFromBin({ entryId: 'e1', binState, binCtx });

      expect(result.updatedBinState.entries).toHaveLength(0);
      expect(sdkCore.unpinFromIpfs).toHaveBeenCalledWith(binCtx.ctx, 'bafycontent');
    });

    it('unpins content AND every version CID (prior bug: versions were never looped)', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'x.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 100,
            mimeType: '',
            contentCid: 'bafycontent',
            versionCids: [
              { cid: 'bafyv1', size: 50 },
              { cid: 'bafyv2', size: 40 },
            ],
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await permanentDeleteFromBin({ entryId: 'e1', binState, binCtx });

      const unpinned = vi.mocked(sdkCore.unpinFromIpfs).mock.calls.map((c) => c[1]);
      expect(unpinned).toEqual(['bafycontent', 'bafyv1', 'bafyv2']);
    });

    it('unpins every descendant CID of a deleted folder entry', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 2n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'folder',
            name: 'Sub',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            descendantCids: [
              { cid: 'bafyd1', size: 10 },
              { cid: 'bafyd2', size: 20 },
            ],
          },
        ],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      await permanentDeleteFromBin({ entryId: 'e1', binState, binCtx });

      const unpinned = vi.mocked(sdkCore.unpinFromIpfs).mock.calls.map((c) => c[1]);
      expect(unpinned).toEqual(['bafyd1', 'bafyd2']);
    });
  });

  describe('emptyBin', () => {
    it('removes all entries and publishes empty bin', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 3n,
      });
      // publishWithVerify will call resolveIpnsRecord to verify
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 3n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'a.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            contentCid: 'bafya',
          },
          {
            id: 'e2',
            itemType: 'file',
            name: 'b.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
          },
        ],
        sequenceNumber: 2,
        ipnsName: 'k51bin',
      };

      const result = await emptyBin({ binState, binCtx });

      expect(result.updatedBinState.entries).toHaveLength(0);
      expect(result.updatedBinState.sequenceNumber).toBe(3);
    });

    it('unpins content + version + descendant CIDs across all entries', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 3n,
      });
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafybin',
        sequenceNumber: 3n,
        signatureVerified: true,
      });

      const binState: BinState = {
        entries: [
          {
            id: 'e1',
            itemType: 'file',
            name: 'a.txt',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            contentCid: 'bafya',
            versionCids: [{ cid: 'bafyav1', size: 1 }],
          },
          {
            id: 'e2',
            itemType: 'folder',
            name: 'Sub',
            originalParentIpnsName: 'k51',
            originalPath: '/',
            deletedAt: 0,
            size: 0,
            mimeType: '',
            descendantCids: [{ cid: 'bafyd1', size: 2 }],
          },
        ],
        sequenceNumber: 2,
        ipnsName: 'k51bin',
      };

      await emptyBin({ binState, binCtx });

      const unpinned = vi.mocked(sdkCore.unpinFromIpfs).mock.calls.map((c) => c[1]);
      expect(new Set(unpinned)).toEqual(new Set(['bafya', 'bafyav1', 'bafyd1']));
    });

    it('publishWithVerify retries when verify fails', async () => {
      vi.useFakeTimers();

      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 2n,
      });
      // Verify fails first time, succeeds second time
      vi.mocked(sdkCore.resolveIpnsRecord)
        .mockResolvedValueOnce(null) // first verify fails
        .mockResolvedValueOnce({ cid: 'bafybin', sequenceNumber: 2n, signatureVerified: true }); // second verify succeeds

      const binState: BinState = {
        entries: [],
        sequenceNumber: 1,
        ipnsName: 'k51bin',
      };

      const resultPromise = emptyBin({ binState, binCtx });

      // Advance timers to handle backoff delay
      await vi.advanceTimersByTimeAsync(2000);

      const result = await resultPromise;

      expect(result.updatedBinState.sequenceNumber).toBe(2);
      // Publish called once (no re-publish on verify failure)
      expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledTimes(1);
      // resolveIpnsRecord called twice: first verify fails, second succeeds
      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(2);

      vi.useRealTimers();
    });
  });
});
