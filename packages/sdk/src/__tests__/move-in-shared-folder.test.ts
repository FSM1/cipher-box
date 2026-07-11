/**
 * CipherBoxClient.moveInSharedFolder -- reachable-branch regression test
 * (72-01/72-07, SC#5).
 *
 * `moveInSharedFolder` previously had a second branch keyed off a
 * `getShareKeysFn` callback's result: a LEGACY per-child share_keys fan-out
 * path (`shareKeys.length > 0`), dead in production because every web
 * caller's `fetchShareKeys` always returned `[]` (68.1-20 Task 1 -- no live
 * share_keys endpoint exists). Plan 07 deleted that dead branch and the
 * `getShareKeysFn` parameter entirely. This test covers the single
 * remaining REACHABLE write-chain path: unseals the SOURCE folder's own
 * write-body, walks one hop to the destination's `WriteChildRef` (keyed by
 * the destination's node UUID, NEVER its ipnsName), and derives
 * `destFolderKey`/`destWriteKey`/`destIpnsPrivateKey` from real AES-GCM
 * AAD-bound seals -- exactly as production does.
 *
 * Per 72-RESEARCH.md Critical Finding 3, this file was previously 100%
 * skipped at the describe level (13 tests, all exercising the now-dead
 * legacy branch) and imported retired core types that no longer exist in
 * `@cipherbox/core` today. Those tests are not worth modernizing (they test
 * code Plan 07 deletes); this file replaces them with ONE live test of the
 * reachable branch so Plan 07's dead-branch removal is refactor-under-test,
 * not refactor-blind.
 *
 * Crypto stays fully real: `sealNode`/`unsealNode`/`sealChildReadKey`/
 * `sealChildWriteKey` from `@cipherbox/core` build genuine AAD-bound
 * envelopes (mirrors `update-shared-single-file.test.ts`). No `wrapKey`/
 * `unwrapKey` mock is needed -- the reachable branch never calls ECIES
 * wrap/unwrap (that's legacy-branch-only). Only the network-touching
 * `@cipherbox/sdk-core` seams (`resolveIpnsRecord`/`fetchFromIpfs` for
 * reads, `addToIpfs`/`createAndPublishIpnsRecord` for the publish
 * transport) are mocked.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { SharedFolderState } from '../types';
import { createTestConfig } from './helpers';
import {
  sealNode,
  unsealNode,
  sealChildReadKey,
  sealChildWriteKey,
  type Node,
  type PublishedNode,
  type SealedChildRef,
} from '@cipherbox/core';

// ── sdk-core mock -- override only the network-touching seams reached
//    through resolvePublishedNode (reads) and the publish transport
//    (buildWriteTransportSeams -- addToIpfs + createAndPublishIpnsRecord).
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    addToIpfs: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

// ── fixture ids ──────────────────────────────────────────────────────────────
const SHARE_ID = 'share-move-reachable';
const SRC_IPNS = 'k51src-shared';
const DEST_IPNS = 'k51dest-shared';
const ITEM_IPNS = 'k51item-shared';

const SRC_NODE_ID = '11111111-1111-4111-8111-111111111111';
const DEST_NODE_ID = '22222222-2222-4222-8222-222222222222';
// Deliberately DIFFERENT from ITEM_IPNS (T-72-01-01 mitigation): a
// UUID-vs-ipnsName confusion in the write-chain filter must not silently
// pass this fixture.
const ITEM_NODE_ID = '33333333-3333-4333-8333-333333333333';

const DEST_GENERATION = 0;
const ITEM_GENERATION = 0;

// ── key material (all real 32-byte AES keys -- one-hop unseal must
//    genuinely validate, not just typecheck) ─────────────────────────────────
const srcFolderKey = new Uint8Array(32).fill(0x11); // srcState.folderKey (readKey)
const srcWriteKey = new Uint8Array(32).fill(0x12); // srcState.writeKey
const srcIpnsPrivateKey = new Uint8Array(32).fill(0x13);

const destFolderKey = new Uint8Array(32).fill(0x21); // dest folder's OWN readKey
const destWriteKey = new Uint8Array(32).fill(0x22); // dest folder's OWN writeKey
const destIpnsPrivateKey = new Uint8Array(32).fill(0x23);

const itemReadKey = new Uint8Array(32).fill(0x31); // moved file's OWN readKey
const itemWriteKey = new Uint8Array(32).fill(0x32); // moved file's OWN writeKey

type Fixture = {
  destPublished: PublishedNode;
  itemPublished: PublishedNode;
  srcState: SharedFolderState;
};

/**
 * Builds a genuine node/v3 write-chain fixture: a source shared folder whose
 * write-body links to a destination subfolder (by UUID) and whose read-body
 * lists both the destination subfolder and the item to be moved.
 */
async function buildFixture(): Promise<Fixture> {
  // Destination folder's own node -- sealed under ITS OWN read/write keys,
  // later recovered by the client via the source's one-hop write chain.
  const destNode: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: DEST_NODE_ID,
    generation: DEST_GENERATION,
    createdAt: 1000,
    modifiedAt: 1000,
    children: [],
    writeBody: { ipnsPrivateKey: destIpnsPrivateKey, writeChildren: [] },
  };
  const destPublished = await sealNode(destNode, destFolderKey, destWriteKey);

  // Moved item's own envelope. moveInSharedFolder never unseals the moved
  // item's own body (only its plaintext id/kind off the envelope) -- sealed
  // anyway for a realistic fixture.
  const itemNode: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: ITEM_NODE_ID,
    generation: ITEM_GENERATION,
    createdAt: 1000,
    modifiedAt: 1000,
    content: {
      cid: 'bafyitemcontent',
      fileIv: 'aXY=',
      size: 4,
      mimeType: 'text/plain',
      encryptionMode: 'GCM',
      fileKey: new Uint8Array(32).fill(0x44),
      versions: [],
    },
    writeBody: { ipnsPrivateKey: new Uint8Array(32).fill(0x55), writeChildren: [] },
  };
  const itemPublished = await sealNode(itemNode, itemReadKey, itemWriteKey);

  // Source folder read-body children: the destination subfolder (its own
  // readKey sealed under srcFolderKey) + the item being moved (its own
  // readKey also sealed under srcFolderKey).
  const destReadKeySealed = await sealChildReadKey(
    destFolderKey,
    srcFolderKey,
    DEST_NODE_ID,
    'folder',
    DEST_GENERATION
  );
  const itemReadKeySealed = await sealChildReadKey(
    itemReadKey,
    srcFolderKey,
    ITEM_NODE_ID,
    'file',
    ITEM_GENERATION
  );

  const destReadRef: SealedChildRef = {
    name: 'dest-folder',
    ipnsName: DEST_IPNS,
    generation: DEST_GENERATION,
    versionFloor: 0n,
    readKeySealed: destReadKeySealed,
  };
  const itemReadRef: SealedChildRef = {
    name: 'moved.txt',
    ipnsName: ITEM_IPNS,
    generation: ITEM_GENERATION,
    versionFloor: 0n,
    readKeySealed: itemReadKeySealed,
  };

  // Source folder write-body: WriteChildRef entries keyed by node UUID
  // (childId), NEVER by ipnsName -- for both the destination subfolder and
  // the moved item.
  const destWriteKeySealed = await sealChildWriteKey(
    destWriteKey,
    srcWriteKey,
    DEST_NODE_ID,
    'folder',
    DEST_GENERATION
  );
  const itemWriteKeySealed = await sealChildWriteKey(
    itemWriteKey,
    srcWriteKey,
    ITEM_NODE_ID,
    'file',
    ITEM_GENERATION
  );

  const srcNode: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: SRC_NODE_ID,
    generation: 0,
    createdAt: 1000,
    modifiedAt: 1000,
    children: [itemReadRef, destReadRef],
    writeBody: {
      ipnsPrivateKey: srcIpnsPrivateKey,
      writeChildren: [
        { childId: DEST_NODE_ID, writeKeySealed: destWriteKeySealed },
        { childId: ITEM_NODE_ID, writeKeySealed: itemWriteKeySealed },
      ],
    },
  };
  const srcPublished = await sealNode(srcNode, srcFolderKey, srcWriteKey);

  const srcState: SharedFolderState = {
    shareId: SHARE_ID,
    ipnsName: SRC_IPNS,
    folderKey: new Uint8Array(srcFolderKey),
    ipnsPrivateKey: new Uint8Array(srcIpnsPrivateKey),
    writeKey: new Uint8Array(srcWriteKey),
    publishedNode: srcPublished,
    sequenceNumber: 5n,
    children: [itemReadRef, destReadRef],
    ownerPublicKey: new Uint8Array(33).fill(0x03),
    recipientPublicKey: new Uint8Array(33).fill(0x04),
  };

  return { destPublished, itemPublished, srcState };
}

function mockResolution(destPublished: PublishedNode, itemPublished: PublishedNode): void {
  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === DEST_IPNS) {
      return { cid: 'bafydestenv', sequenceNumber: 9n, signatureVerified: true };
    }
    if (ipnsName === ITEM_IPNS) {
      return { cid: 'bafyitemenv', sequenceNumber: 3n, signatureVerified: true };
    }
    return null;
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafydestenv') return new TextEncoder().encode(JSON.stringify(destPublished));
    if (cid === 'bafyitemenv') return new TextEncoder().encode(JSON.stringify(itemPublished));
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });
}

describe('CipherBoxClient.moveInSharedFolder -- reachable write-chain branch (68.1-20)', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('moves an item into a direct-child destination via the write chain, keying the destination write link by node UUID (childId), never by ipnsName', async () => {
    const { destPublished, itemPublished, srcState } = await buildFixture();
    mockResolution(destPublished, itemPublished);
    client.loadSharedFolder(SHARE_ID, srcState);

    vi.mocked(sdkCore.addToIpfs).mockResolvedValue({
      cid: 'bafynewblob',
      size: 100,
      recorded: true,
    });
    let seq = 100n;
    vi.mocked(sdkCore.createAndPublishIpnsRecord).mockImplementation(async () => {
      seq += 1n;
      return { success: true, sequenceNumber: seq };
    });

    await client.moveInSharedFolder(SHARE_ID, {
      itemId: ITEM_IPNS,
      destFolderId: 'unused-by-the-write-chain-branch',
      destIpnsName: DEST_IPNS,
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    // Publishes DEST before SOURCE (dup-not-orphan, T-68.1-08-04).
    expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledTimes(2);
    const publishCalls = vi.mocked(sdkCore.createAndPublishIpnsRecord).mock.calls;
    expect(publishCalls[0]?.[0]?.ipnsName).toBe(DEST_IPNS);
    expect(publishCalls[1]?.[0]?.ipnsName).toBe(SRC_IPNS);

    // Decode what was actually published for DEST and assert the new write
    // link is keyed by the item's node UUID (childId), never its ipnsName --
    // the two are genuinely different values in this fixture (T-72-01-01).
    const destBytes = vi.mocked(sdkCore.addToIpfs).mock.calls[0]?.[1] as Uint8Array;
    const destEnvelope = JSON.parse(new TextDecoder().decode(destBytes)) as PublishedNode;
    const destNodeAfterMove = await unsealNode(destEnvelope, destFolderKey, destWriteKey);
    expect(destNodeAfterMove.writeBody?.writeChildren).toHaveLength(1);
    expect(destNodeAfterMove.writeBody?.writeChildren[0]?.childId).toBe(ITEM_NODE_ID);
    expect(destNodeAfterMove.writeBody?.writeChildren[0]?.childId).not.toBe(ITEM_IPNS);
    expect(destNodeAfterMove.children).toHaveLength(1);
    expect(destNodeAfterMove.children?.[0]?.ipnsName).toBe(ITEM_IPNS);

    // Decode what was actually published for SOURCE and assert the item's
    // write link and read-body entry are both gone; the destination-folder
    // reference (still a legitimate child of source) remains untouched.
    const srcBytes = vi.mocked(sdkCore.addToIpfs).mock.calls[1]?.[1] as Uint8Array;
    const srcEnvelope = JSON.parse(new TextDecoder().decode(srcBytes)) as PublishedNode;
    const srcNodeAfterMove = await unsealNode(srcEnvelope, srcFolderKey, srcWriteKey);
    expect(
      srcNodeAfterMove.writeBody?.writeChildren.some((wc) => wc.childId === ITEM_NODE_ID)
    ).toBe(false);
    expect(srcNodeAfterMove.writeBody?.writeChildren).toHaveLength(1);
    expect(srcNodeAfterMove.writeBody?.writeChildren[0]?.childId).toBe(DEST_NODE_ID);
    expect(srcNodeAfterMove.children).toHaveLength(1);
    expect(srcNodeAfterMove.children?.[0]?.ipnsName).toBe(DEST_IPNS);
  });
});
