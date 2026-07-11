/**
 * enumerateSharedSubtree tests (68.1-27 GAP-7): read/write-chain contract.
 *
 * Rewritten off the deleted `share_keys` fan-out onto the node/v3 read/write
 * chain walked from the loaded `SharedFolderState`. Only the network-touching
 * sdk-core seams (`resolveIpnsRecord`, `fetchFromIpfs`) are mocked -- every
 * `@cipherbox/core` seal/unseal primitive stays real so fixtures are genuine
 * AAD-bound envelopes (mirrors client-write-plane-recovery.test.ts's 68.1-23
 * fixture pattern).
 *
 * Covers:
 * - Nested reachable subtree (root -> subA -> subA1) with correct parentId
 * - writable=true only when a WriteChildRef exists in the PARENT write-body
 *   AND unsealChildWriteKey succeeds under the parent writeKey
 * - A read-only subfolder (no WriteChildRef) is still listed (writable:false)
 *   and its own children are still enumerated (also non-writable)
 * - A file leaf child is excluded from the result (not a move destination)
 * - A structurally-unresolvable child (no IPNS record) is skipped, not thrown
 * - The visited-set guard prevents infinite loops on a cyclic ipnsName
 * - A read-only share root (zero writeKey) lists every child as non-writable
 * - "Shared folder not loaded" throw when the share is not seeded
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { SharedFolderState } from '../types';
import {
  sealNode,
  sealChildReadKey,
  sealChildWriteKey,
  type Node,
  type PublishedNode,
  type SealedChildRef,
  type WriteChildRef,
} from '@cipherbox/core';

// ── sdk-core mock -- override only the network-touching helpers reached
//    through `resolvePublishedNode` (resolveIpnsRecord + fetchFromIpfs).
//    Every other sdk-core export (unused here) stays real via importOriginal.
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

// ── fixture ids ──────────────────────────────────────────────────────────────
const SHARE_ID = 'share-enum-test';
const ROOT_IPNS = 'k51root-shared';
const ROOT_NODE_ID = '11111111-1111-4111-8111-111111111111';

const SUB_A_IPNS = 'k51sub-a';
const SUB_A_NAME = 'FolderA';
const SUB_A_NODE_ID = '22222222-2222-4222-8222-222222222222';

const SUB_B_IPNS = 'k51sub-b';
const SUB_B_NAME = 'FolderB';
const SUB_B_NODE_ID = '33333333-3333-4333-8333-333333333333';

// Structurally unresolvable -- resolveIpnsRecord returns null for this name.
const SUB_C_IPNS = 'k51sub-c';
const SUB_C_NAME = 'FolderC';

const SUB_FILE_IPNS = 'k51sub-file';
const SUB_FILE_NAME = 'notes.txt';
const SUB_FILE_NODE_ID = '99999999-9999-4999-8999-999999999999';

const SUB_A1_IPNS = 'k51sub-a1';
const SUB_A1_NAME = 'FolderA1';
const SUB_A1_NODE_ID = '44444444-4444-4444-8444-444444444444';

const SUB_B1_IPNS = 'k51sub-b1';
const SUB_B1_NAME = 'FolderB1';
const SUB_B1_NODE_ID = '55555555-5555-4555-8555-555555555555';

// ── key material ─────────────────────────────────────────────────────────────
const rootReadKey = new Uint8Array(32).fill(0x01);
const rootWriteKey = new Uint8Array(32).fill(0x02);
const subAReadKey = new Uint8Array(32).fill(0x11);
const subAWriteKey = new Uint8Array(32).fill(0x12);
const subBReadKey = new Uint8Array(32).fill(0x21);
const subA1ReadKey = new Uint8Array(32).fill(0x31);
const subA1WriteKey = new Uint8Array(32).fill(0x32);
const subB1ReadKey = new Uint8Array(32).fill(0x41);
const subFileReadKey = new Uint8Array(32).fill(0x51);

type Fixture = {
  state: SharedFolderState;
  registerNetwork: () => void;
};

/**
 * Builds a genuine node/v3 tree:
 *   root (writable) -> subA (writable), subB (read-only), subC (unresolvable), subFile (file leaf)
 *   subA -> subA1 (writable)
 *   subB -> subB1 (listed, non-writable -- read-only subtree)
 *
 * @param opts.rootWritable - when false, the share root itself has no real
 *   writeKey (SharedFolderState.writeKey is a zero buffer) -- every child
 *   must come back writable:false.
 * @param opts.cyclicSubA1Child - when true, subA1's own children includes a
 *   ref back to SUB_A_IPNS (cycle) instead of being a leaf.
 */
async function buildFixture(
  opts: { rootWritable?: boolean; cyclicSubA1Child?: boolean } = {}
): Promise<Fixture> {
  const rootWritable = opts.rootWritable ?? true;

  const subARef: SealedChildRef = {
    name: SUB_A_NAME,
    ipnsName: SUB_A_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: await sealChildReadKey(subAReadKey, rootReadKey, SUB_A_NODE_ID, 'folder', 0),
  };
  const subBRef: SealedChildRef = {
    name: SUB_B_NAME,
    ipnsName: SUB_B_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: await sealChildReadKey(subBReadKey, rootReadKey, SUB_B_NODE_ID, 'folder', 0),
  };
  const subCRef: SealedChildRef = {
    name: SUB_C_NAME,
    ipnsName: SUB_C_IPNS,
    generation: 0,
    versionFloor: 0n,
    // Never unsealed -- resolvePublishedNode(SUB_C_IPNS) resolves to null first.
    readKeySealed: 'irrelevant',
  };
  const subFileRef: SealedChildRef = {
    name: SUB_FILE_NAME,
    ipnsName: SUB_FILE_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: await sealChildReadKey(subFileReadKey, rootReadKey, SUB_FILE_NODE_ID, 'file', 0),
  };

  const rootWriteChildren: WriteChildRef[] = rootWritable
    ? [
        {
          childId: SUB_A_NODE_ID,
          writeKeySealed: await sealChildWriteKey(
            subAWriteKey,
            rootWriteKey,
            SUB_A_NODE_ID,
            'folder',
            0
          ),
        },
      ]
    : [];

  const rootNode: Node = {
    schema: 'node/v3',
    kind: 'root',
    id: ROOT_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [subARef, subBRef, subCRef, subFileRef],
    writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(0x99), writeChildren: rootWriteChildren },
  };
  const publishedRoot = await sealNode(rootNode, rootReadKey, rootWriteKey);

  // subA (writable): one child, subA1, itself writable via subA's write-body.
  const subA1Ref: SealedChildRef = {
    name: SUB_A1_NAME,
    ipnsName: SUB_A1_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: await sealChildReadKey(subA1ReadKey, subAReadKey, SUB_A1_NODE_ID, 'folder', 0),
  };
  const subANode: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: SUB_A_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [subA1Ref],
    writeBody: {
      ipnsPrivateKey: new Uint8Array(64).fill(0x98),
      writeChildren: [
        {
          childId: SUB_A1_NODE_ID,
          writeKeySealed: await sealChildWriteKey(
            subA1WriteKey,
            subAWriteKey,
            SUB_A1_NODE_ID,
            'folder',
            0
          ),
        },
      ],
    },
  };
  const publishedSubA = await sealNode(subANode, subAReadKey, subAWriteKey);

  // subA1 (writable, leaf -- or cyclic back to subA when requested).
  const subA1Children: SealedChildRef[] = opts.cyclicSubA1Child
    ? [
        {
          name: 'CyclicBackToA',
          ipnsName: SUB_A_IPNS,
          generation: 0,
          versionFloor: 0n,
          readKeySealed: await sealChildReadKey(
            subAReadKey,
            subA1ReadKey,
            SUB_A_NODE_ID,
            'folder',
            0
          ),
        },
      ]
    : [];
  const subA1Node: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: SUB_A1_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: subA1Children,
  };
  const publishedSubA1 = await sealNode(subA1Node, subA1ReadKey, new Uint8Array(32));

  // subB (read-only from this share's root -- no WriteChildRef): one child,
  // subB1, still enumerable via the read chain but never writable.
  const subB1Ref: SealedChildRef = {
    name: SUB_B1_NAME,
    ipnsName: SUB_B1_IPNS,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: await sealChildReadKey(subB1ReadKey, subBReadKey, SUB_B1_NODE_ID, 'folder', 0),
  };
  const subBNode: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: SUB_B_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [subB1Ref],
  };
  const publishedSubB = await sealNode(subBNode, subBReadKey, new Uint8Array(32));

  const subB1Node: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: SUB_B1_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [],
  };
  const publishedSubB1 = await sealNode(subB1Node, subB1ReadKey, new Uint8Array(32));

  const subFileNode: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: SUB_FILE_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    content: {
      cid: 'bafyfilecontent',
      fileIv: 'aXY=',
      size: 0,
      mimeType: 'text/plain',
      encryptionMode: 'GCM',
      fileKey: new Uint8Array(32).fill(0x61),
      versions: [],
    },
  };
  const publishedSubFile = await sealNode(subFileNode, subFileReadKey, new Uint8Array(32));

  const byIpns: Record<string, { cid: string; published: PublishedNode }> = {
    [SUB_A_IPNS]: { cid: 'bafy-sub-a', published: publishedSubA },
    [SUB_A1_IPNS]: { cid: 'bafy-sub-a1', published: publishedSubA1 },
    [SUB_B_IPNS]: { cid: 'bafy-sub-b', published: publishedSubB },
    [SUB_B1_IPNS]: { cid: 'bafy-sub-b1', published: publishedSubB1 },
    [SUB_FILE_IPNS]: { cid: 'bafy-sub-file', published: publishedSubFile },
  };

  const registerNetwork = (): void => {
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      const entry = byIpns[ipnsName];
      if (!entry) return null; // SUB_C_IPNS and anything else: unresolvable
      return { cid: entry.cid, sequenceNumber: 1n, signatureVerified: true };
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
      const entry = Object.values(byIpns).find((e) => e.cid === cid);
      if (!entry) throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
      return new TextEncoder().encode(JSON.stringify(entry.published));
    });
  };

  const state: SharedFolderState = {
    shareId: SHARE_ID,
    ipnsName: ROOT_IPNS,
    folderKey: rootReadKey,
    ipnsPrivateKey: new Uint8Array(64).fill(0x88),
    writeKey: rootWritable ? rootWriteKey : new Uint8Array(32),
    publishedNode: publishedRoot,
    sequenceNumber: 1n,
    children: [subARef, subBRef, subCRef, subFileRef],
    ownerPublicKey: new Uint8Array(33).fill(0x03),
    recipientPublicKey: new Uint8Array(33).fill(0x04),
  };

  return { state, registerNetwork };
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('CipherBoxClient.enumerateSharedSubtree', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('returns a nested reachable subtree with correct writable flags and parentId', async () => {
    const { state, registerNetwork } = await buildFixture();
    registerNetwork();
    client.loadSharedFolder(SHARE_ID, state);

    const result = await client.enumerateSharedSubtree(SHARE_ID);

    const ids = result.map((n) => n.id);
    expect(ids).toContain(SUB_A_IPNS);
    expect(ids).toContain(SUB_B_IPNS);
    expect(ids).toContain(SUB_A1_IPNS);
    expect(ids).toContain(SUB_B1_IPNS);
    // File leaf is never a move destination -- excluded from the result.
    expect(ids).not.toContain(SUB_FILE_IPNS);
    // Structurally unresolvable child -- soft-skipped, not thrown.
    expect(ids).not.toContain(SUB_C_IPNS);

    const subA = result.find((n) => n.id === SUB_A_IPNS);
    const subB = result.find((n) => n.id === SUB_B_IPNS);
    const subA1 = result.find((n) => n.id === SUB_A1_IPNS);
    const subB1 = result.find((n) => n.id === SUB_B1_IPNS);

    expect(subA?.writable).toBe(true);
    expect(subA?.name).toBe(SUB_A_NAME);
    expect(subA?.parentId).toBeNull();

    expect(subB?.writable).toBe(false);
    expect(subB?.parentId).toBeNull();

    expect(subA1?.writable).toBe(true);
    expect(subA1?.name).toBe(SUB_A1_NAME);
    expect(subA1?.parentId).toBe(SUB_A_IPNS);

    // Read-only subfolder's own child is still enumerated, but never writable.
    expect(subB1?.writable).toBe(false);
    expect(subB1?.parentId).toBe(SUB_B_IPNS);
  });

  it('does not loop on a cyclic ipnsName (visited set guard)', async () => {
    const { state, registerNetwork } = await buildFixture({ cyclicSubA1Child: true });
    registerNetwork();
    client.loadSharedFolder(SHARE_ID, state);

    const result = await client.enumerateSharedSubtree(SHARE_ID);

    const subAOccurrences = result.filter((n) => n.ipnsName === SUB_A_IPNS);
    expect(subAOccurrences).toHaveLength(1);
  });

  it('lists every child as non-writable when the share root itself has no real writeKey', async () => {
    const { state, registerNetwork } = await buildFixture({ rootWritable: false });
    registerNetwork();
    client.loadSharedFolder(SHARE_ID, state);

    const result = await client.enumerateSharedSubtree(SHARE_ID);

    expect(result.length).toBeGreaterThan(0);
    for (const node of result) {
      expect(node.writable).toBe(false);
    }
  });

  it('throws "Shared folder not loaded" when share is not seeded', async () => {
    await expect(client.enumerateSharedSubtree('nonexistent-share')).rejects.toThrow(
      'Shared folder not loaded'
    );
  });
});
