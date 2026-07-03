/**
 * TDD tests for 68.1-31: moveItem write-link re-homing.
 *
 * Closes the live, reproduced bug where an owned file moved into a subfolder
 * becomes permanently un-editable ("File k51... is not write-capable (no
 * WriteChildRef)"). `CipherBoxClient.moveItem` re-links the read-plane
 * SealedChildRef and re-seals the child readKey for the destination, but
 * historically left the moved child's WriteChildRef orphaned in the SOURCE
 * write-body. This suite proves moveItem now unseals the moved child's
 * WriteChildRef under the source writeKey, removes it from the source
 * write-body, and re-seals it under the destination writeKey into the dest
 * write-body -- keyed strictly by node UUID (never the ipnsName-based
 * `moveItem` `childId` param -- write plane is keyed by UUID, read plane by
 * ipnsName).
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`) and the publish call (`updateFolderMetadataAndPublish`,
 * mocked to CAPTURE its writeChildren argument) are mocked -- every
 * `@cipherbox/core` seal/unseal primitive stays real so fixtures are genuine
 * AAD-bound envelopes (mirrors client-write-descriptor.test.ts /
 * resolve-shared-subfolder-write-key.test.ts's 68.1-18/68.1-30 pattern).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import {
  sealChildReadKey,
  sealChildWriteKey,
  unsealChildWriteKey,
  type SealedChildRef,
  type WriteChildRef,
} from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
  };
});

// Spy on the REAL unsealChildWriteKey (capturing every returned buffer
// reference) so the zeroization test can assert client.ts's terminal-owner
// `finally` actually zeroed the recovered child writeKey in place -- every
// other @cipherbox/core primitive stays real via importOriginal.
const recoveredWriteKeyBuffers: Uint8Array[] = [];
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    unsealChildWriteKey: vi.fn(async (...args: Parameters<typeof actual.unsealChildWriteKey>) => {
      const result = await actual.unsealChildWriteKey(...args);
      recoveredWriteKeyBuffers.push(result);
      return result;
    }),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const SRC_IPNS = 'k51src';
const DEST_IPNS = 'k51dest';
const CHILD_IPNS = 'k51child';
const NODE_UUID = '11111111-1111-4111-8111-111111111111';
const GEN = 0;

interface CapturedPublishArgs {
  ipnsName: string;
  writeKey?: Uint8Array;
  writeChildren?: WriteChildRef[];
  children: SealedChildRef[];
}

/**
 * Installs a fresh `updateFolderMetadataAndPublish` mock that records every
 * call IN ORDER (not by matching a hardcoded IPNS-name constant, which would
 * silently mislabel dest/source on the round-trip leg where the two folders
 * swap roles). moveItem's dest-before-source publish ordering (preserved
 * from the pre-existing FLAG-63-U2 re-seal) means call 0 is always the
 * destination publish and call 1 is always the source publish.
 */
function mockPublishCapture(): {
  dest: () => CapturedPublishArgs | null;
  source: () => CapturedPublishArgs | null;
} {
  const calls: CapturedPublishArgs[] = [];
  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (params) => {
    calls.push(params as unknown as CapturedPublishArgs);
    return {
      cid: 'bafynew',
      newSequenceNumber: BigInt(calls.length + 1),
      publishedChildren: params.children,
    };
  });
  return {
    dest: () => calls[0] ?? null,
    source: () => calls[1] ?? null,
  };
}

/**
 * Seed a SOURCE and DEST FolderState, each with a real non-zero writeKey and
 * a populated `metadata.writeBody` (so `getWriteBodyParams` takes the
 * in-memory fast path). Seeds the moved SealedChildRef into the source
 * read-body, and (by default) a matching WriteChildRef into the source
 * write-body. Mocks the network seams + `updateFolderMetadataAndPublish` to
 * capture the writeChildren threaded into each publish call.
 */
async function seedMove(
  client: CipherBoxClient,
  opts: {
    sourceWriteKey?: Uint8Array;
    destWriteKey?: Uint8Array;
    includeSourceWriteChildRef?: boolean;
    childWriteKey?: Uint8Array;
  } = {}
): Promise<{
  sourceWriteKey: Uint8Array;
  destWriteKey: Uint8Array;
  childWriteKey: Uint8Array;
  captured: ReturnType<typeof mockPublishCapture>;
}> {
  const srcFolderKey = new Uint8Array(32).fill(0x11);
  const destFolderKey = new Uint8Array(32).fill(0x22);
  const sourceWriteKey = opts.sourceWriteKey ?? new Uint8Array(32).fill(0x33);
  const destWriteKey = opts.destWriteKey ?? new Uint8Array(32).fill(0x44);
  const childWriteKey = opts.childWriteKey ?? new Uint8Array(32).fill(0x77);
  const includeSourceWriteChildRef = opts.includeSourceWriteChildRef ?? true;

  const readKeySealed = await sealChildReadKey(
    new Uint8Array(32).fill(0x55),
    srcFolderKey,
    NODE_UUID,
    'file',
    GEN
  );
  const movedEntry: SealedChildRef = {
    name: 'file.txt',
    ipnsName: CHILD_IPNS,
    generation: GEN,
    versionFloor: 1n,
    readKeySealed,
  };

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

  const srcState: FolderState = {
    ipnsName: SRC_IPNS,
    folderKey: srcFolderKey,
    writeKey: sourceWriteKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [movedEntry],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'src-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [movedEntry],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(3), writeChildren: sourceWriteChildren },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'src-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(SRC_IPNS, srcState);

  const destState: FolderState = {
    ipnsName: DEST_IPNS,
    folderKey: destFolderKey,
    writeKey: destWriteKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(4),
      privateKey: new Uint8Array(64).fill(5),
    },
    sequenceNumber: 1n,
    children: [],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'dest-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: { ipnsPrivateKey: new Uint8Array(64).fill(5), writeChildren: [] },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'dest-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(DEST_IPNS, destState);

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === CHILD_IPNS) {
      return { cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true };
    }
    // src/dest reconcile calls -- null short-circuits reconcileFolderSequence.
    return null;
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
    if (cid === 'bafychild') {
      return new TextEncoder().encode(
        JSON.stringify({
          schema: 'node/v3',
          kind: 'file',
          id: NODE_UUID,
          generation: GEN,
          createdAt: 0,
          modifiedAt: 0,
        })
      );
    }
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });

  const captured = mockPublishCapture();

  return { sourceWriteKey, destWriteKey, childWriteKey, captured };
}

describe('CipherBoxClient.moveItem write-link re-homing (68.1-31)', () => {
  let client: CipherBoxClient;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    recoveredWriteKeyBuffers.length = 0;
    client = new CipherBoxClient(createTestConfig());
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it('re-homes the WriteChildRef into the DEST write-body, unsealable under the dest writeKey', async () => {
    const { destWriteKey, childWriteKey, captured } = await seedMove(client);

    await client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS);

    const destWriteChildRef = captured
      .dest()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(destWriteChildRef).toBeDefined();
    const recovered = await unsealChildWriteKey(
      destWriteChildRef!.writeKeySealed,
      destWriteKey,
      NODE_UUID,
      'file',
      GEN
    );
    expect(recovered).toEqual(childWriteKey);
  });

  it('removes the WriteChildRef from the SOURCE write-body', async () => {
    const { captured } = await seedMove(client);

    await client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS);

    const sourceWriteChildRef = captured
      .source()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(sourceWriteChildRef).toBeUndefined();
  });

  it('round-trip: moving back dest->source re-homes the WriteChildRef symmetrically', async () => {
    const { sourceWriteKey, childWriteKey } = await seedMove(client);

    // First move: source -> dest.
    await client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS);

    // Intermediate assertion (guards against a false pass where the entry was
    // simply never removed from SRC_IPNS in the first place -- proves move 1
    // ACTUALLY re-homed the entry into DEST_IPNS's in-memory write-body
    // mirror, not merely that it survives untouched in SRC_IPNS).
    const midSrc = client.getFolderTree().get(SRC_IPNS)!;
    const midDest = client.getFolderTree().get(DEST_IPNS)!;
    expect(
      midSrc.metadata?.writeBody?.writeChildren?.find((wc) => wc.childId === NODE_UUID)
    ).toBeUndefined();
    expect(
      midDest.metadata?.writeBody?.writeChildren?.find((wc) => wc.childId === NODE_UUID)
    ).toBeDefined();

    // Second move: dest -> source (swap direction). Re-install the ordered
    // publish capture for the second leg (dest publish is always call 0).
    const captured2 = mockPublishCapture();

    await client.moveItem(DEST_IPNS, SRC_IPNS, CHILD_IPNS);

    // In this second call, SRC_IPNS plays the DEST role -- call 0.
    const rehomedSourceRef = captured2
      .dest()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(rehomedSourceRef).toBeDefined();
    const recovered = await unsealChildWriteKey(
      rehomedSourceRef!.writeKeySealed,
      sourceWriteKey,
      NODE_UUID,
      'file',
      GEN
    );
    expect(recovered).toEqual(childWriteKey);

    // DEST_IPNS now plays the SOURCE role -- call 1 -- and must have lost the entry.
    const rehomedDestRef = captured2
      .source()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(rehomedDestRef).toBeUndefined();
  });

  it('edge: no source WriteChildRef -- resolves without throwing, both lists unchanged', async () => {
    const { captured } = await seedMove(client, { includeSourceWriteChildRef: false });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS)).resolves.toBeUndefined();

    expect(captured.dest()?.writeChildren ?? []).toEqual([]);
    expect(captured.source()?.writeChildren ?? []).toEqual([]);
  });

  it('edge: read-only dest (zero writeKey) -- resolves without throwing, warns, both write-bodies verbatim', async () => {
    const zeroWriteKey = new Uint8Array(32);
    const { captured } = await seedMove(client, { destWriteKey: zeroWriteKey });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS)).resolves.toBeUndefined();

    // Dest is read-only -- getWriteBodyParams returns {} (no writeKey/writeChildren).
    expect(captured.dest()?.writeKey).toBeUndefined();
    expect(captured.dest()?.writeChildren).toBeUndefined();
    // Source write-body preserved verbatim (still has the entry -- nothing re-homed).
    const sourceWriteChildRef = captured
      .source()
      ?.writeChildren?.find((wc) => wc.childId === NODE_UUID);
    expect(sourceWriteChildRef).toBeDefined();
    expect(warnSpy).toHaveBeenCalled();
  });

  it('zeroization: the recovered child writeKey buffer is zeroed after the operation', async () => {
    const { childWriteKey } = await seedMove(client);

    await client.moveItem(SRC_IPNS, DEST_IPNS, CHILD_IPNS);

    // moveItem's write-link re-homing calls unsealChildWriteKey exactly once
    // to recover the moved child's writeKey under the source writeKey. That
    // returned buffer must be zeroed in a terminal-owner `finally` (D-09).
    expect(recoveredWriteKeyBuffers.length).toBe(1);
    const recoveredBuffer = recoveredWriteKeyBuffers[0];
    // Sanity: the buffer originally held the real child writeKey bytes
    // (proves this is the right buffer, not a decoy) -- checked BEFORE
    // asserting zeroization by comparing lengths only (content is now zeroed).
    expect(recoveredBuffer.length).toBe(childWriteKey.length);
    expect(recoveredBuffer.every((b) => b === 0)).toBe(true);

    // Folder-owned source/dest writeKeys are NEVER zeroed (caller/tree-owned).
    const src = client.getFolderTree().get(SRC_IPNS)!;
    const dest = client.getFolderTree().get(DEST_IPNS)!;
    expect(src.writeKey.every((b) => b === 0)).toBe(false);
    expect(dest.writeKey.every((b) => b === 0)).toBe(false);
  });
});
