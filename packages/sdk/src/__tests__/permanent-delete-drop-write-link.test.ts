/**
 * TDD tests for 72-05 (SC#1 symmetry / RESEARCH.md Open Question 1):
 * permanentDeleteFromBin drops the lingering WriteChildRef from the bin
 * entry's original parent.
 *
 * addToBin (soft-delete) RETAINS the removed child's WriteChildRef in the
 * original parent's write-body (so a later restoreFromBin can re-home it —
 * SC#3, Plan 05 Task 1). That means a permanently-deleted item that was
 * NEVER restored leaves an orphaned WriteChildRef sitting in the original
 * parent forever — unbounded write-body growth, the bin-path analog of the
 * SC#1 gap `deleteItem` closed for hard-delete. Permanent removal is the
 * symmetric release point: this suite proves `permanentDeleteFromBin` now
 * accepts the original parent's `FolderState` and, when supplied, drops the
 * matching `WriteChildRef` by the node's own UUID (`BinEntry.nodeRef.id`,
 * captured at addToBin time — Pitfall 4: use the captured witness, never a
 * fresh resolve). Fails open on any failure — a permanent-delete must never
 * be blocked by an unresolvable original parent or a write-body error.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { permanentDeleteFromBin } from '../bin';
import type { BinOperationContext, BinState } from '../bin';
import type { FolderState } from '../types';
import { sealChildWriteKey, type WriteChildRef } from '@cipherbox/core';

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
}

function mockPublishCapture(): {
  calls: () => CapturedPublishArgs[];
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
  return { calls: () => calls };
}

function makeFolderState(opts: {
  writeKey: Uint8Array;
  writeChildren: WriteChildRef[];
}): FolderState {
  return {
    ipnsName: SOURCE_IPNS,
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
      id: 'source-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren: opts.writeChildren },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'source-node-id',
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

function setupNetworkMocks() {
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
}

describe('binOps.permanentDeleteFromBin drops the lingering WriteChildRef (72-05, SC#1 symmetry)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('drops the lingering WriteChildRef from the original parent write-body, threading baseWriteChildren', async () => {
    const sourceWriteKey = new Uint8Array(32).fill(0x33);
    const childWriteKey = new Uint8Array(32).fill(0x77);
    const writeKeySealed = await sealChildWriteKey(
      childWriteKey,
      sourceWriteKey,
      NODE_UUID,
      'file',
      GEN
    );
    const originalParent = makeFolderState({
      writeKey: sourceWriteKey,
      writeChildren: [{ childId: NODE_UUID, writeKeySealed }],
    });

    setupNetworkMocks();
    const captured = mockPublishCapture();

    await permanentDeleteFromBin({
      entryId: 'e1',
      binState: makeBinState(),
      binCtx,
      originalParent,
    });

    expect(captured.calls()).toHaveLength(1);
    const [publishCall] = captured.calls();
    expect(publishCall.ipnsName).toBe(SOURCE_IPNS);
    expect(publishCall.writeChildren?.some((wc) => wc.childId === NODE_UUID)).toBe(false);
    expect(publishCall.baseWriteChildren?.some((wc) => wc.childId === NODE_UUID)).toBe(true);
  });

  it('unpins CIDs and removes the bin entry regardless of the write-body drop', async () => {
    const sourceWriteKey = new Uint8Array(32).fill(0x33);
    const childWriteKey = new Uint8Array(32).fill(0x77);
    const writeKeySealed = await sealChildWriteKey(
      childWriteKey,
      sourceWriteKey,
      NODE_UUID,
      'file',
      GEN
    );
    const originalParent = makeFolderState({
      writeKey: sourceWriteKey,
      writeChildren: [{ childId: NODE_UUID, writeKeySealed }],
    });

    setupNetworkMocks();
    mockPublishCapture();

    const result = await permanentDeleteFromBin({
      entryId: 'e1',
      binState: makeBinState(),
      binCtx,
      originalParent,
    });

    expect(result.updatedBinState.entries).toHaveLength(0);
  });

  it('does not publish when the original parent has no lingering WriteChildRef for this node', async () => {
    const sourceWriteKey = new Uint8Array(32).fill(0x33);
    const originalParent = makeFolderState({ writeKey: sourceWriteKey, writeChildren: [] });

    setupNetworkMocks();
    const captured = mockPublishCapture();

    await permanentDeleteFromBin({
      entryId: 'e1',
      binState: makeBinState(),
      binCtx,
      originalParent,
    });

    expect(captured.calls()).toHaveLength(0);
  });

  it('does not throw when the original parent is not supplied (fail-open, existing behavior preserved)', async () => {
    setupNetworkMocks();

    const result = await permanentDeleteFromBin({
      entryId: 'e1',
      binState: makeBinState(),
      binCtx,
      // originalParent intentionally omitted
    });

    expect(result.updatedBinState.entries).toHaveLength(0);
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('fail-open: an original-parent write-body resolve failure never blocks permanent delete', async () => {
    const originalParent = makeFolderState({
      writeKey: new Uint8Array(32).fill(0x33),
      writeChildren: [],
    });
    // Strip the in-memory writeBody mirror so getWriteBodyParams falls
    // through to a network resolve, then make that resolve throw.
    originalParent.metadata = null;

    vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);
    vi.mocked(sdkCore.addToIpfs).mockResolvedValue({ cid: 'bafybin', size: 3, recorded: true });
    vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
      success: true,
      sequenceNumber: 2n,
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === SOURCE_IPNS) throw new Error('network blip');
      return { cid: 'bafybin', sequenceNumber: 2n, signatureVerified: true };
    });

    const result = await permanentDeleteFromBin({
      entryId: 'e1',
      binState: makeBinState(),
      binCtx,
      originalParent,
    });

    // Entry removal + CID cleanup still completed despite the resolve failure.
    expect(result.updatedBinState.entries).toHaveLength(0);
  });
});
