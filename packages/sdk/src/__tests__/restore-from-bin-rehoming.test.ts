/**
 * TDD tests for 72-05 (SC#3): restoreFromBin cross-folder WriteChildRef
 * re-homing.
 *
 * Closes the structural gap where `restoreFromBin` only ever loaded the
 * TARGET folder — a file restored into a DIFFERENT parent than the one it
 * was soft-deleted from stayed write-capable only under the ORIGINAL
 * parent's write-body (the WriteChildRef was never moved), making the
 * restored item permanently un-editable in its new home. This suite proves
 * `binOps.restoreFromBin` now accepts an optional source `FolderState` and,
 * when both folders have a real writeKey, unseals the moved child's
 * WriteChildRef under the SOURCE writeKey, removes it from the source
 * write-body, and re-seals it under the DESTINATION (target) writeKey into
 * the target write-body — reusing moveItem's (68.1-31) dest-before-source
 * pattern, keyed strictly by the node's own UUID (BinEntry.nodeRef.id, never
 * the ipnsName-based `entryId`/`nodeIpnsName`).
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`, `addToIpfs`, `createAndPublishIpnsRecord`) and the folder
 * publish call (`updateFolderMetadataAndPublish`, mocked to CAPTURE its
 * writeChildren argument) are mocked — every `@cipherbox/core` seal/unseal
 * primitive stays real so fixtures are genuine AAD-bound envelopes (mirrors
 * move-write-link-rehoming.test.ts's 68.1-31 pattern).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { restoreFromBin } from '../bin';
import type { BinOperationContext, BinState } from '../bin';
import { FolderTree } from '../state/folder-tree';
import type { FolderState } from '../types';
import { sealChildWriteKey, unsealChildWriteKey, type WriteChildRef } from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    addToIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
  };
});

// Spy on the REAL unsealChildWriteKey (capturing every returned buffer
// reference) so the zeroization test can assert the terminal-owner
// `finally` actually zeroed the recovered child writeKey in place — every
// other @cipherbox/core primitive stays real via importOriginal.
const recoveredWriteKeyBuffers: Uint8Array[] = [];
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
    unsealChildWriteKey: vi.fn(async (...args: Parameters<typeof actual.unsealChildWriteKey>) => {
      const result = await actual.unsealChildWriteKey(...args);
      recoveredWriteKeyBuffers.push(result);
      return result;
    }),
  };
});

vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    bytesToHex: vi.fn().mockReturnValue('aabb'),
    hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
    wrapKey: vi.fn().mockResolvedValue(new Uint8Array([0xaa])),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const SOURCE_IPNS = 'k51source';
const TARGET_IPNS = 'k51target';
const CHILD_IPNS = 'k51child';
const NODE_UUID = '11111111-1111-4111-8111-111111111111';
const GEN = 0;

const binCtx: BinOperationContext = {
  ctx: { apiUrl: 'http://localhost:3000', getAccessToken: async () => 'token' },
  userPrivateKey: new Uint8Array(32).fill(1),
  userPublicKey: new Uint8Array(33).fill(2),
  rootFolderKey: new Uint8Array(32).fill(3),
};

interface CapturedPublishArgs {
  ipnsName: string;
  writeKey?: Uint8Array;
  writeChildren?: WriteChildRef[];
  baseWriteChildren?: WriteChildRef[];
  children: unknown[];
}

/**
 * Installs a fresh `updateFolderMetadataAndPublish` mock recording calls IN
 * ORDER. `restoreFromBin`'s dest-before-source publish contract means call 0
 * is always the TARGET (restore destination) publish and call 1 (only when
 * re-homing actually ran) is the SOURCE (original parent) publish.
 */
function mockPublishCapture(): {
  target: () => CapturedPublishArgs | null;
  source: () => CapturedPublishArgs | null;
  count: () => number;
} {
  const calls: CapturedPublishArgs[] = [];
  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (params) => {
    calls.push(params as unknown as CapturedPublishArgs);
    return {
      cid: 'bafynew',
      newSequenceNumber: BigInt(calls.length + 1),
      publishedChildren: params.children,
      publishedWriteChildren: params.writeKey ? params.writeChildren : undefined,
    };
  });
  return {
    target: () => calls[0] ?? null,
    source: () => calls[1] ?? null,
    count: () => calls.length,
  };
}

function makeFolderState(
  ipnsName: string,
  opts: { writeKey: Uint8Array; writeChildren: WriteChildRef[]; nodeId: string }
): FolderState {
  return {
    ipnsName,
    folderKey: new Uint8Array(32).fill(0x99),
    writeKey: opts.writeKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: opts.nodeId,
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren: opts.writeChildren },
    },
    lastLoadedAt: Date.now(),
    nodeId: opts.nodeId,
    nodeGeneration: 0,
  };
}

function makeBinState(): BinState {
  return {
    entries: [
      {
        id: 'e1',
        itemType: 'file',
        name: 'doc.txt',
        originalParentIpnsName: SOURCE_IPNS,
        originalPath: '/old',
        deletedAt: 0,
        size: 0,
        mimeType: '',
        nodeReadKey: new Uint8Array(32).fill(0xaa),
        nodeIpnsName: CHILD_IPNS,
        nodeRef: {
          schema: 'node/v3' as const,
          kind: 'file' as const,
          id: NODE_UUID,
          generation: GEN,
          createdAt: 0,
          modifiedAt: 0,
        },
      },
    ],
    sequenceNumber: 1,
    ipnsName: 'k51bin',
  };
}

async function seedRestore(
  opts: {
    sourceWriteKey?: Uint8Array;
    targetWriteKey?: Uint8Array;
    includeSourceWriteChildRef?: boolean;
    childWriteKey?: Uint8Array;
  } = {}
): Promise<{
  folderTree: FolderTree;
  sourceFolder: FolderState;
  targetFolder: FolderState;
  binState: BinState;
  sourceWriteKey: Uint8Array;
  targetWriteKey: Uint8Array;
  childWriteKey: Uint8Array;
  captured: ReturnType<typeof mockPublishCapture>;
}> {
  const sourceWriteKey = opts.sourceWriteKey ?? new Uint8Array(32).fill(0x33);
  const targetWriteKey = opts.targetWriteKey ?? new Uint8Array(32).fill(0x44);
  const childWriteKey = opts.childWriteKey ?? new Uint8Array(32).fill(0x77);
  const includeSourceWriteChildRef = opts.includeSourceWriteChildRef ?? true;

  let sourceWriteChildren: WriteChildRef[] = [];
  if (includeSourceWriteChildRef) {
    const writeKeySealed = await sealChildWriteKey(
      childWriteKey,
      sourceWriteKey,
      NODE_UUID,
      'file',
      GEN
    );
    sourceWriteChildren = [{ childId: NODE_UUID, writeKeySealed }];
  }

  const sourceFolder = makeFolderState(SOURCE_IPNS, {
    writeKey: sourceWriteKey,
    writeChildren: sourceWriteChildren,
    nodeId: 'source-node-id',
  });
  const targetFolder = makeFolderState(TARGET_IPNS, {
    writeKey: targetWriteKey,
    writeChildren: [],
    nodeId: 'target-node-id',
  });

  const folderTree = new FolderTree();
  folderTree.set(TARGET_IPNS, targetFolder);

  // Verify-resolve step (restoreFromBin's best-effort post-restore check) —
  // resolvable so it never warns/blocks.
  vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
    cid: 'bafyverify',
    sequenceNumber: 1n,
    signatureVerified: true,
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(new Uint8Array([1]));
  vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
  vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
    success: true,
    sequenceNumber: 2n,
  });

  const captured = mockPublishCapture();

  return {
    folderTree,
    sourceFolder,
    targetFolder,
    binState: makeBinState(),
    sourceWriteKey,
    targetWriteKey,
    childWriteKey,
    captured,
  };
}

describe('binOps.restoreFromBin write-link re-homing (72-05, SC#3)', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    recoveredWriteKeyBuffers.length = 0;
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it('re-homes the WriteChildRef into the TARGET write-body, unsealable under the target writeKey', async () => {
    const {
      folderTree,
      sourceFolder,
      targetFolder,
      binState,
      targetWriteKey,
      childWriteKey,
      captured,
    } = await seedRestore();

    await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    const targetWriteChildRef = captured
      .target()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(targetWriteChildRef).toBeDefined();
    const recovered = await unsealChildWriteKey(
      targetWriteChildRef!.writeKeySealed,
      targetWriteKey,
      NODE_UUID,
      'file',
      GEN
    );
    expect(recovered).toEqual(childWriteKey);
  });

  it('removes the WriteChildRef from the SOURCE write-body', async () => {
    const { folderTree, sourceFolder, targetFolder, binState, captured } = await seedRestore();

    await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    const sourceWriteChildRef = captured
      .source()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(sourceWriteChildRef).toBeUndefined();
  });

  it('publishes TARGET before SOURCE (dest-before-source, D-12)', async () => {
    const { folderTree, sourceFolder, targetFolder, binState, captured } = await seedRestore();

    await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    expect(captured.count()).toBe(2);
    expect(captured.target()?.ipnsName).toBe(TARGET_IPNS);
    expect(captured.source()?.ipnsName).toBe(SOURCE_IPNS);
  });

  it('threads baseWriteChildren for both folders so the CAS merge prunes the source-side drop', async () => {
    const { folderTree, sourceFolder, targetFolder, binState, captured } = await seedRestore();

    await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    expect(captured.source()?.baseWriteChildren?.some((wc) => wc.childId === NODE_UUID)).toBe(true);
  });

  it('zeroization: the recovered child writeKey buffer is zeroed after the operation', async () => {
    const { folderTree, sourceFolder, targetFolder, binState, childWriteKey } = await seedRestore();

    await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    expect(recoveredWriteKeyBuffers.length).toBe(1);
    const recoveredBuffer = recoveredWriteKeyBuffers[0];
    expect(recoveredBuffer.length).toBe(childWriteKey.length);
    expect(recoveredBuffer.every((b) => b === 0)).toBe(true);

    // Folder-owned source/target writeKeys are NEVER zeroed (caller/tree-owned).
    expect(sourceFolder.writeKey.every((b) => b === 0)).toBe(false);
    expect(targetFolder.writeKey.every((b) => b === 0)).toBe(false);
  });

  it('edge: no sourceFolder supplied (original parent unresolvable) -- resolves read-plane-only, single publish', async () => {
    const { folderTree, targetFolder, binState, captured } = await seedRestore();

    await expect(
      restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: targetFolder.ipnsName,
        folderTree,
        binState,
        binCtx,
        // sourceFolder intentionally omitted -- fail-open path (T-72-05-03)
      })
    ).resolves.toBeDefined();

    expect(captured.count()).toBe(1);
    expect(captured.target()?.writeChildren ?? []).toEqual([]);
  });

  it('edge: source is read-only (zero writeKey) -- warns, no re-homing, single publish', async () => {
    const zeroWriteKey = new Uint8Array(32);
    const { folderTree, sourceFolder, targetFolder, binState, captured } = await seedRestore({
      sourceWriteKey: zeroWriteKey,
    });

    await expect(
      restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: targetFolder.ipnsName,
        folderTree,
        binState,
        binCtx,
        sourceFolder,
      })
    ).resolves.toBeDefined();

    // Source is read-only -- getWriteBodyParams returns {} -- no re-homing, no second publish.
    expect(captured.count()).toBe(1);
    expect(captured.target()?.writeChildren ?? []).toEqual([]);
    expect(warnSpy).toHaveBeenCalled();
  });

  it('edge: no source WriteChildRef for this node -- resolves without throwing, no re-homing, single publish', async () => {
    const { folderTree, sourceFolder, targetFolder, binState, captured } = await seedRestore({
      includeSourceWriteChildRef: false,
    });

    await expect(
      restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: targetFolder.ipnsName,
        folderTree,
        binState,
        binCtx,
        sourceFolder,
      })
    ).resolves.toBeDefined();

    expect(captured.count()).toBe(1);
    expect(captured.target()?.writeChildren ?? []).toEqual([]);
  });

  it('fail-open: a source getWriteBodyParams failure never blocks the restore (never throws)', async () => {
    const { folderTree, sourceFolder, targetFolder, binState, captured } = await seedRestore();

    // Force the source folder's write-body resolve to blow up: strip the
    // in-memory writeBody mirror so getWriteBodyParams falls through to a
    // network resolve, then make that resolve throw.
    sourceFolder.metadata = null;
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === SOURCE_IPNS) throw new Error('network blip');
      return { cid: 'bafyverify', sequenceNumber: 1n, signatureVerified: true };
    });

    const result = await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    expect(result.restoredItem).toBeDefined();
    // Restore still fully completed (bin entry removed).
    expect(result.updatedBinState.entries).toHaveLength(0);
    // Only the target publish ran -- re-homing was skipped, not retried/blocked.
    expect(captured.count()).toBe(1);
    expect(warnSpy).toHaveBeenCalled();
  });

  it('fail-closed: an AEAD failure unsealing the source WriteChildRef THROWS (does not silently downgrade to read-plane-only)', async () => {
    const { folderTree, sourceFolder, targetFolder, binState } = await seedRestore();

    // Re-seal the source WriteChildRef under a DIFFERENT (wrong) key so
    // unsealChildWriteKey fails GCM auth under the folder's real writeKey --
    // this simulates a tampered / wrong-key write-body. Per Finding 1, this
    // must FAIL CLOSED and propagate, never be silently downgraded to a
    // read-plane-only restore (mirrors walkChildWriteKey's 72-08 precedent).
    const wrongKey = new Uint8Array(32).fill(0x66);
    const tamperedSealed = await sealChildWriteKey(wrongKey, wrongKey, NODE_UUID, 'file', GEN);
    sourceFolder.metadata!.writeBody!.writeChildren = [
      { childId: NODE_UUID, writeKeySealed: tamperedSealed },
    ];

    await expect(
      restoreFromBin({
        entryId: 'e1',
        targetFolderIpnsName: targetFolder.ipnsName,
        folderTree,
        binState,
        binCtx,
        sourceFolder,
      })
    ).rejects.toThrow();
  });

  it('best-effort: a SOURCE-side cleanup publish failure never blocks the restore (bin entry still removed)', async () => {
    const { folderTree, sourceFolder, targetFolder, binState } = await seedRestore();

    // Target publish (call 0) succeeds normally; SOURCE publish (call 1,
    // dropping the stale WriteChildRef from the original parent) throws --
    // a network blip / CAS exhaustion. Per Finding 2 this must be
    // best-effort: the restore already succeeded via the target publish, so
    // this failure must be swallowed (logged) and the bin-entry removal
    // below must still run.
    let call = 0;
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (params) => {
      call += 1;
      if (call === 2) throw new Error('network blip');
      return {
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: params.children,
        publishedWriteChildren: params.writeKey ? params.writeChildren : undefined,
      };
    });

    const result = await restoreFromBin({
      entryId: 'e1',
      targetFolderIpnsName: targetFolder.ipnsName,
      folderTree,
      binState,
      binCtx,
      sourceFolder,
    });

    expect(result.restoredItem).toBeDefined();
    expect(result.updatedBinState.entries).toHaveLength(0);
    expect(warnSpy).toHaveBeenCalled();
  });
});
