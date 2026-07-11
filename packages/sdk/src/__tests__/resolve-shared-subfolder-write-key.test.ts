/**
 * resolveSharedSubfolderWriteKey tests (68.1-30 WEB-03 deep-shared-write gap):
 * one-hop write-chain resolver for a shared subfolder.
 *
 * Mirrors the fixture pattern of enumerate-shared-subtree.test.ts and
 * client-write-plane-recovery.test.ts: only the network-touching sdk-core
 * seams are mocked, every `@cipherbox/core` seal/unseal primitive stays real
 * so fixtures are genuine AAD-bound envelopes.
 *
 * Covers:
 * - Real (non-zero) parent writeKey -> child writeKey recovered, and it
 *   successfully unseals the child's OWN write-body
 * - Returned buffer is a fresh copy -- zeroing it does not corrupt the
 *   parent's sharedFolderTree writeKey (resolves again unaffected)
 * - Read-only parent (zero writeKey) -> null, no unseal attempted
 * - Parent write-body has no WriteChildRef for the child -> null
 * - shareId not loaded in the tree -> null
 * - Tampered writeKeySealed / wrong parent writeKey -> throws (fail-closed AEAD)
 * - Recovered key that does not unseal the child's own write-body -> null
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { SharedFolderState } from '../types';
import {
  sealNode,
  sealChildWriteKey,
  type Node,
  type PublishedNode,
  type WriteChildRef,
} from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

// ── fixture ids ──────────────────────────────────────────────────────────────
const SHARE_ID = 'share-subfolder-writekey-test';
const ROOT_IPNS = 'k51root-shared-swk';
const ROOT_NODE_ID = '11111111-1111-4111-8111-111111111111';

const SUB_A_NODE_ID = '22222222-2222-4222-8222-222222222222';
const SUB_A_GENERATION = 0;

// ── key material ─────────────────────────────────────────────────────────────
const rootReadKey = new Uint8Array(32).fill(0x01);
const rootWriteKey = new Uint8Array(32).fill(0x02);
const subAReadKey = new Uint8Array(32).fill(0x11);
const subAWriteKey = new Uint8Array(32).fill(0x12);

type Fixture = {
  state: SharedFolderState;
  subAPublished: PublishedNode;
};

/**
 * Builds a genuine node/v3 root -> subA tree.
 *
 * @param opts.rootWritable - when false, the root's own writeKey is a zero
 *   buffer (SharedFolderState.writeKey) so the resolver must return null.
 * @param opts.omitWriteChildRef - when true, the root's write-body carries NO
 *   WriteChildRef for subA (not write-linked).
 * @param opts.tamperSealedKey - when true, corrupt subA's writeKeySealed so
 *   unsealChildWriteKey throws (fail-closed AEAD).
 * @param opts.wrongChildWriteKey - when true, seal subA's WriteChildRef under
 *   a DIFFERENT child writeKey than subA's actual write-body was sealed
 *   under -- the recovered key fails to validate against subA's own
 *   write-body (unsealNode throws under the wrong key), exercising the
 *   validate-before-trust guard.
 */
async function buildFixture(
  opts: {
    rootWritable?: boolean;
    omitWriteChildRef?: boolean;
    tamperSealedKey?: boolean;
    wrongChildWriteKey?: boolean;
  } = {}
): Promise<Fixture> {
  const rootWritable = opts.rootWritable ?? true;

  let sealedSubAWriteKey = await sealChildWriteKey(
    opts.wrongChildWriteKey ? new Uint8Array(32).fill(0xff) : subAWriteKey,
    rootWriteKey,
    SUB_A_NODE_ID,
    'folder',
    SUB_A_GENERATION
  );
  if (opts.tamperSealedKey) {
    // Flip a byte in the base64 ciphertext body (not the first char, to keep
    // valid base64 alphabet) so the AEAD auth tag no longer verifies.
    const chars = sealedSubAWriteKey.split('');
    const idx = Math.floor(chars.length / 2);
    chars[idx] = chars[idx] === 'A' ? 'B' : 'A';
    sealedSubAWriteKey = chars.join('');
  }

  const rootWriteChildren: WriteChildRef[] = opts.omitWriteChildRef
    ? []
    : [{ childId: SUB_A_NODE_ID, writeKeySealed: sealedSubAWriteKey }];

  const rootNode: Node = {
    schema: 'node/v3',
    kind: 'root',
    id: ROOT_NODE_ID,
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [],
    writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(0x99), writeChildren: rootWriteChildren },
  };
  const publishedRoot = await sealNode(rootNode, rootReadKey, rootWriteKey);

  const subANode: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: SUB_A_NODE_ID,
    generation: SUB_A_GENERATION,
    createdAt: 0,
    modifiedAt: 0,
    children: [],
    writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(0x98), writeChildren: [] },
  };
  const publishedSubA = await sealNode(subANode, subAReadKey, subAWriteKey);

  const state: SharedFolderState = {
    shareId: SHARE_ID,
    ipnsName: ROOT_IPNS,
    folderKey: rootReadKey,
    ipnsPrivateKey: new Uint8Array(64).fill(0x88),
    writeKey: rootWritable ? rootWriteKey : new Uint8Array(32),
    publishedNode: publishedRoot,
    sequenceNumber: 1n,
    children: [],
    ownerPublicKey: new Uint8Array(33).fill(0x03),
    recipientPublicKey: new Uint8Array(33).fill(0x04),
  };

  return { state, subAPublished: publishedSubA };
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('CipherBoxClient.resolveSharedSubfolderWriteKey', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('recovers the child writeKey and it unseals the child own write-body', async () => {
    const { state, subAPublished } = await buildFixture();
    client.loadSharedFolder(SHARE_ID, state);

    const result = await client.resolveSharedSubfolderWriteKey(SHARE_ID, {
      published: subAPublished,
      readKey: subAReadKey,
      generation: SUB_A_GENERATION,
    });

    expect(result).not.toBeNull();
    expect(result).toHaveLength(32);
    expect(result).toEqual(subAWriteKey);
  });

  it('returns a fresh copy -- zeroing the result does not corrupt the tree, and resolving again still works', async () => {
    const { state, subAPublished } = await buildFixture();
    client.loadSharedFolder(SHARE_ID, state);

    const first = await client.resolveSharedSubfolderWriteKey(SHARE_ID, {
      published: subAPublished,
      readKey: subAReadKey,
      generation: SUB_A_GENERATION,
    });
    expect(first).not.toBeNull();
    first!.fill(0);

    // The tree's own writeKey (and the fixture's rootWriteKey buffer) must be
    // unaffected by zeroing the returned copy.
    const treeState = client.getSharedFolderState(SHARE_ID);
    expect(treeState?.writeKey.every((b) => b === 0)).toBe(false);

    const second = await client.resolveSharedSubfolderWriteKey(SHARE_ID, {
      published: subAPublished,
      readKey: subAReadKey,
      generation: SUB_A_GENERATION,
    });
    expect(second).not.toBeNull();
    expect(second).toEqual(subAWriteKey);
    // The two returned buffers must be independent instances.
    expect(second).not.toBe(first);
  });

  it('returns null when the parent writeKey is zero (read-only)', async () => {
    const { state, subAPublished } = await buildFixture({ rootWritable: false });
    client.loadSharedFolder(SHARE_ID, state);

    const result = await client.resolveSharedSubfolderWriteKey(SHARE_ID, {
      published: subAPublished,
      readKey: subAReadKey,
      generation: SUB_A_GENERATION,
    });

    expect(result).toBeNull();
  });

  it('returns null when the parent write-body has no WriteChildRef for the child', async () => {
    const { state, subAPublished } = await buildFixture({ omitWriteChildRef: true });
    client.loadSharedFolder(SHARE_ID, state);

    const result = await client.resolveSharedSubfolderWriteKey(SHARE_ID, {
      published: subAPublished,
      readKey: subAReadKey,
      generation: SUB_A_GENERATION,
    });

    expect(result).toBeNull();
  });

  it('returns null when shareId is not loaded in the tree', async () => {
    const { subAPublished } = await buildFixture();

    const result = await client.resolveSharedSubfolderWriteKey('nonexistent-share', {
      published: subAPublished,
      readKey: subAReadKey,
      generation: SUB_A_GENERATION,
    });

    expect(result).toBeNull();
  });

  it('throws on a tampered writeKeySealed (fail-closed AEAD, not swallowed)', async () => {
    const { state, subAPublished } = await buildFixture({ tamperSealedKey: true });
    client.loadSharedFolder(SHARE_ID, state);

    await expect(
      client.resolveSharedSubfolderWriteKey(SHARE_ID, {
        published: subAPublished,
        readKey: subAReadKey,
        generation: SUB_A_GENERATION,
      })
    ).rejects.toThrow();
  });

  it('throws when the recovered writeKey does not unseal the child own write-body (validate-before-trust, fail-closed)', async () => {
    const { state, subAPublished } = await buildFixture({ wrongChildWriteKey: true });
    client.loadSharedFolder(SHARE_ID, state);

    // The wrong-childWriteKey seal recovers cleanly (unsealChildWriteKey only
    // authenticates against the PARENT writeKey + AAD triad, which are both
    // correct here) but the recovered key is not the key subA's own
    // write-body was actually sealed under -- unsealNode's AEAD auth then
    // fails validating it, mirroring dfsFindFolder's T-68.1-01-03 guarantee
    // that a recovered-but-wrong key is never trusted or returned.
    await expect(
      client.resolveSharedSubfolderWriteKey(SHARE_ID, {
        published: subAPublished,
        readKey: subAReadKey,
        generation: SUB_A_GENERATION,
      })
    ).rejects.toThrow();
  });
});
