/**
 * TDD tests for SC#2: `getWriteBodyParams` fails CLOSED on a transient IPNS
 * resolve miss when a real writeKey is present, instead of returning
 * `writeChildren: []` and letting the next publish seal an empty write-body
 * that silently discards the entire write chain (72-04).
 *
 * Scope discipline (72-RESEARCH.md Pitfall 3 / Assumption A1): the throw
 * applies ONLY to the genuine `!resolved` transient-miss branch AND only
 * when a real (non-zero, 32-byte) writeKey is present. TWO existing
 * fail-open paths must stay unchanged:
 *   1. the zero/absent-writeKey read-only-device fallback (returns `{}`)
 *   2. a resolved record with no `writeSealed` field (structurally
 *      never-write-capable, pre-D-03) -- returns `writeChildren: []`
 *
 * `getWriteBodyParams` is private in both copies. This file covers the
 * `client.ts` copy first (Task 1), exercised through `renameItem` (calls
 * `getWriteBodyParams(folder)` directly with no other write-plane side
 * effects to disentangle). The `bin/index.ts` twin (Task 2, exercised
 * through `addToBin`) is added in a second describe block below.
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`) and the publish call (`updateFolderMetadataAndPublish`)
 * are mocked -- mirrors delete-item.test.ts / client-write-plane-recovery.test.ts.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { addToBin } from '../bin';
import type { BinOperationContext, BinState } from '../bin';
import { FolderTree } from '../state/folder-tree';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import type { SealedChildRef } from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    deleteFromFolder: vi.fn(),
    addToIpfs: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
  };
});

// bin/index.ts's getWriteBodyParams twin (Task 2) is exercised through
// addToBin, which also touches these @cipherbox/core seams -- mock only the
// ones addToBin needs beyond the client.ts describe block above (which never
// unseals a read key or derives a bin keypair).
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    encryptBinMetadata: vi.fn().mockResolvedValue(new Uint8Array([1, 2, 3])),
    deriveBinIpnsKeypair: vi.fn().mockResolvedValue({
      ipnsName: 'k51bin',
      privateKey: new Uint8Array(64).fill(5),
      publicKey: new Uint8Array(32).fill(6),
    }),
    unsealChildReadKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xbc)),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const FOLDER_IPNS = 'folder-ipns';
const CHILD_IPNS = 'k51file';

/** Real (non-zero, 32-byte) writeKey -- the "write-capable folder" case. */
function realWriteKey(): Uint8Array {
  return new Uint8Array(32).fill(0x33);
}

/** Zero writeKey -- the legitimate read-only-device fallback case. */
function zeroWriteKey(): Uint8Array {
  return new Uint8Array(32);
}

function seedRenameFixture(client: CipherBoxClient, writeKey: Uint8Array): SealedChildRef {
  const child: SealedChildRef = {
    name: 'old.txt',
    ipnsName: CHILD_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'sealed-key-hex',
  };
  const state: FolderState = {
    ipnsName: FOLDER_IPNS,
    folderKey: new Uint8Array(32).fill(1),
    writeKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [child],
    // No metadata.writeBody mirror -- forces getWriteBodyParams to hit the
    // network resolve branch instead of short-circuiting.
    metadata: null,
    lastLoadedAt: Date.now(),
    nodeId: 'folder-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(FOLDER_IPNS, state);
  return child;
}

describe('CipherBoxClient.getWriteBodyParams fail-closed on transient resolve miss (SC#2, client.ts)', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });
  });

  it('THROWS when a real writeKey is present and the resolve returns null (transient miss)', async () => {
    seedRenameFixture(client, realWriteKey());
    // Every resolveIpnsRecord call (reconcile pre-check + getWriteBodyParams'
    // own resolve) returns null -- a genuine transient IPNS resolve miss.
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

    await expect(client.renameItem(FOLDER_IPNS, CHILD_IPNS, 'new.txt')).rejects.toThrow();
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('does NOT throw when writeKey is zero/absent (read-only-device fallback, unchanged)', async () => {
    seedRenameFixture(client, zeroWriteKey());
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

    await expect(client.renameItem(FOLDER_IPNS, CHILD_IPNS, 'new.txt')).resolves.toBeUndefined();

    const call = vi.mocked(sdkCore.updateFolderMetadataAndPublish).mock.calls[0]?.[0];
    expect(call?.writeKey).toBeUndefined();
    expect(call?.writeChildren).toBeUndefined();
  });

  it('does NOT throw when a real writeKey resolves to a record without writeSealed (never-write-capable, unchanged)', async () => {
    seedRenameFixture(client, realWriteKey());
    vi.mocked(sdkCore.resolveIpnsRecord)
      // 1st call: reconcileFolderSequence pre-check -- matching sequence, no-op.
      .mockResolvedValueOnce({ cid: 'bafyseq', sequenceNumber: 1n, signatureVerified: true })
      // 2nd call: getWriteBodyParams' own resolvePublishedNode -- resolved,
      // but the on-wire node structurally has no writeSealed field.
      .mockResolvedValueOnce({ cid: 'bafynoseal', sequenceNumber: 1n, signatureVerified: true });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      new TextEncoder().encode(
        JSON.stringify({
          schema: 'node/v3',
          kind: 'folder',
          id: 'folder-node-id',
          generation: 0,
          createdAt: 0,
          modifiedAt: 0,
        })
      )
    );

    await expect(client.renameItem(FOLDER_IPNS, CHILD_IPNS, 'new.txt')).resolves.toBeUndefined();

    const call = vi.mocked(sdkCore.updateFolderMetadataAndPublish).mock.calls[0]?.[0];
    expect(call?.writeKey).toEqual(realWriteKey());
    expect(call?.writeChildren).toEqual([]);
  });

  // The zero-key early return branch is unchanged -- resolveIpnsRecord is
  // never reached a SECOND time for the folder's own write-body resolve
  // (only the reconcile pre-check call happens).
  it('the zero-key early return skips the write-body network resolve entirely', async () => {
    seedRenameFixture(client, zeroWriteKey());
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

    await client.renameItem(FOLDER_IPNS, CHILD_IPNS, 'new.txt');

    // Exactly one resolveIpnsRecord call (reconcile pre-check) -- none for
    // getWriteBodyParams itself, since the zero-key branch returns early.
    expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledTimes(1);
  });
});

describe('bin addToBin getWriteBodyParams twin fail-closed on transient resolve miss (SC#2, bin/index.ts)', () => {
  const binCtx: BinOperationContext = {
    ctx: { apiUrl: 'http://localhost:3000', getAccessToken: async () => 'token' },
    userPrivateKey: new Uint8Array(32).fill(1),
    userPublicKey: new Uint8Array(33).fill(2),
    rootFolderKey: new Uint8Array(32).fill(3),
  };

  const fileRef: SealedChildRef = {
    name: 'doc.txt',
    ipnsName: CHILD_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: 'sealed-base64-placeholder',
  };

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

  function seedBinFixture(writeKey: Uint8Array): { folderTree: FolderTree; binState: BinState } {
    const folderTree = new FolderTree();
    folderTree.set(FOLDER_IPNS, {
      ipnsName: FOLDER_IPNS,
      folderKey: new Uint8Array(32).fill(0x11),
      writeKey,
      ipnsKeypair: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) },
      sequenceNumber: 1n,
      children: [fileRef],
      // No metadata.writeBody mirror -- forces the network resolve branch.
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: 'parent-node-id',
      nodeGeneration: 0,
    });
    const binState: BinState = { entries: [], sequenceNumber: 0, ipnsName: 'k51bin' };
    return { folderTree, binState };
  }

  beforeEach(() => {
    vi.clearAllMocks();
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
  });

  it('THROWS when a real writeKey is present and the folder resolve returns null (transient miss)', async () => {
    const { folderTree, binState } = seedBinFixture(realWriteKey());
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === CHILD_IPNS) {
        return { cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true };
      }
      if (ipnsName === FOLDER_IPNS) return null; // transient miss under test
      return { cid: 'bafybin', sequenceNumber: 1n, signatureVerified: true };
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(childPublishedNode);

    await expect(
      addToBin({
        folderIpnsName: FOLDER_IPNS,
        childId: CHILD_IPNS,
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
      })
    ).rejects.toThrow();

    // Fails BEFORE the durable bin write -- no orphaned bin entry left
    // dangling between the bin save and the (never-reached) folder publish.
    expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('does NOT throw when a real writeKey resolves to a record without writeSealed (never-write-capable, unchanged)', async () => {
    const { folderTree, binState } = seedBinFixture(realWriteKey());
    const folderNoSealNode = new TextEncoder().encode(
      JSON.stringify({
        schema: 'node/v3',
        kind: 'folder',
        id: 'parent-node-id',
        generation: 0,
        createdAt: 0,
        modifiedAt: 0,
      })
    );
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === CHILD_IPNS) {
        return { cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true };
      }
      if (ipnsName === FOLDER_IPNS) {
        return { cid: 'bafyfoldernoseal', sequenceNumber: 1n, signatureVerified: true };
      }
      return { cid: 'bafybin', sequenceNumber: 1n, signatureVerified: true };
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafyfoldernoseal') return folderNoSealNode;
      return childPublishedNode;
    });

    await expect(
      addToBin({
        folderIpnsName: FOLDER_IPNS,
        childId: CHILD_IPNS,
        parentPath: 'My Vault',
        folderTree,
        binState,
        binCtx,
      })
    ).resolves.toBeDefined();

    const call = vi.mocked(sdkCore.updateFolderMetadataAndPublish).mock.calls[0]?.[0];
    expect(call?.writeKey).toEqual(realWriteKey());
    expect(call?.writeChildren).toEqual([]);
  });
});
