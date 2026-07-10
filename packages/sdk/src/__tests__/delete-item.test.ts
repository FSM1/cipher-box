/**
 * TDD tests for SC#1: `deleteItem` drops the removed child's WriteChildRef
 * (72-03 Task 2).
 *
 * `deleteItem`'s `childId` param is an ipnsName (matched against
 * `SealedChildRef.ipnsName` by `sdkCore.deleteFromFolder`); `WriteChildRef.childId`
 * is the child's node UUID -- a DIFFERENT value (72-RESEARCH.md Pitfall 1). This
 * suite proves `deleteItem` resolves the removed item's UUID and filters it out
 * of `writeChildren` in the SAME publish that removes the read-plane
 * `SealedChildRef`, threads a `baseWriteChildren` snapshot so Task 1's
 * base-aware merge can prune it under a 409, and fails OPEN (never aborts the
 * already-succeeded read-plane delete) when the UUID resolve itself fails.
 *
 * Fixture uses genuinely DIFFERENT values for the deleted child's ipnsName
 * (CHILD_IPNS) and its WriteChildRef.childId (NODE_UUID) -- a naive filter on
 * the read-plane `childId` param would silently no-op and pass a broken
 * implementation (Pitfall 1's warning sign).
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`) and the publish call (`updateFolderMetadataAndPublish`,
 * mocked to CAPTURE its writeChildren/baseWriteChildren arguments) are mocked --
 * every `@cipherbox/core` seal primitive stays real (mirrors
 * move-write-link-rehoming.test.ts's 68.1-31 pattern).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import {
  sealChildReadKey,
  sealChildWriteKey,
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

import * as sdkCore from '@cipherbox/sdk-core';

const FOLDER_IPNS = 'k51folder';
// Deliberately DIFFERENT from NODE_UUID -- SealedChildRef.ipnsName is never a UUID.
const CHILD_IPNS = 'k51child';
const NODE_UUID = '11111111-1111-4111-8111-111111111111';
const OTHER_UUID = '22222222-2222-4222-8222-222222222222';
const GEN = 0;

interface CapturedPublishArgs {
  writeKey?: Uint8Array;
  writeChildren?: WriteChildRef[];
  baseWriteChildren?: WriteChildRef[];
  children: SealedChildRef[];
}

/**
 * Seed a FolderState whose write-body has TWO WriteChildRefs: one keyed by the
 * deleted child's UUID (NODE_UUID) and one for an unrelated sibling (OTHER_UUID)
 * that must survive the delete untouched. Mocks the network seams so
 * `resolvePublishedNode(CHILD_IPNS)` resolves to a PublishedNode with
 * `id: NODE_UUID` (the UUID `deleteItem` must recover before it can filter
 * `writeChildren`).
 */
async function seedDelete(
  client: CipherBoxClient,
  opts: { childResolveFails?: boolean } = {}
): Promise<{ writeKey: Uint8Array; captured: () => CapturedPublishArgs | null }> {
  const folderKey = new Uint8Array(32).fill(0x11);
  const writeKey = new Uint8Array(32).fill(0x33);

  const readKeySealed = await sealChildReadKey(
    new Uint8Array(32).fill(0x55),
    folderKey,
    NODE_UUID,
    'file',
    GEN
  );
  const childEntry: SealedChildRef = {
    name: 'file.txt',
    ipnsName: CHILD_IPNS,
    generation: GEN,
    versionFloor: 1n,
    readKeySealed,
  };

  const nodeWriteChildRef: WriteChildRef = {
    childId: NODE_UUID,
    writeKeySealed: await sealChildWriteKey(
      new Uint8Array(32).fill(0x77),
      writeKey,
      NODE_UUID,
      'file',
      GEN
    ),
  };
  const otherWriteChildRef: WriteChildRef = {
    childId: OTHER_UUID,
    writeKeySealed: await sealChildWriteKey(
      new Uint8Array(32).fill(0x88),
      writeKey,
      OTHER_UUID,
      'file',
      GEN
    ),
  };

  const state: FolderState = {
    ipnsName: FOLDER_IPNS,
    folderKey,
    writeKey,
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [childEntry],
    metadata: {
      schema: 'node/v3',
      kind: 'folder',
      id: 'folder-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [childEntry],
      writeBody: {
        ipnsPrivateKey: new Uint8Array(64).fill(3),
        writeChildren: [nodeWriteChildRef, otherWriteChildRef],
      },
    },
    lastLoadedAt: Date.now(),
    nodeId: 'folder-node-id',
    nodeGeneration: 0,
  };
  client.getFolderTree().set(FOLDER_IPNS, state);

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === CHILD_IPNS) {
      if (opts.childResolveFails) {
        throw new Error('simulated transient resolve failure');
      }
      return { cid: 'bafychild', sequenceNumber: 1n, signatureVerified: true };
    }
    // Folder's own reconcile call -- null short-circuits reconcileFolderSequence.
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

  const calls: CapturedPublishArgs[] = [];
  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockImplementation(async (params) => {
    calls.push(params as unknown as CapturedPublishArgs);
    return {
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: params.children,
    };
  });

  return { writeKey, captured: () => calls[0] ?? null };
}

describe('CipherBoxClient.deleteItem write-chain trim (SC#1)', () => {
  let client: CipherBoxClient;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  it('drops the removed child WriteChildRef (write-chain length shrinks by exactly 1)', async () => {
    const { captured } = await seedDelete(client);

    await client.deleteItem(FOLDER_IPNS, CHILD_IPNS);

    const published = captured();
    expect(published?.writeChildren).toHaveLength(1);
    expect(published?.writeChildren?.find((wc) => wc.childId === NODE_UUID)).toBeUndefined();
    expect(published?.writeChildren?.find((wc) => wc.childId === OTHER_UUID)).toBeDefined();
  });

  it('threads the pre-trim write-body as baseWriteChildren so a 409 merge cannot resurrect the dropped ref', async () => {
    const { captured } = await seedDelete(client);

    await client.deleteItem(FOLDER_IPNS, CHILD_IPNS);

    const published = captured();
    expect(published?.baseWriteChildren).toHaveLength(2);
    expect(published?.baseWriteChildren?.some((wc) => wc.childId === NODE_UUID)).toBe(true);
  });

  it('fails OPEN on a UUID resolve failure: delete still succeeds and write-body is left unchanged', async () => {
    const { captured } = await seedDelete(client, { childResolveFails: true });

    const result = await client.deleteItem(FOLDER_IPNS, CHILD_IPNS);

    expect(result.removedItem.ipnsName).toBe(CHILD_IPNS);
    const published = captured();
    // Write-chain trim skipped -- both entries survive verbatim.
    expect(published?.writeChildren).toHaveLength(2);
    expect(published?.writeChildren?.find((wc) => wc.childId === NODE_UUID)).toBeDefined();
    expect(warnSpy).toHaveBeenCalled();
  });
});
