/**
 * TDD tests for SC#4 (reframed): `maybeRepublishFolderForFileMigration`
 * invalidates the parent's `listingCache` entry on a file-only publish, gated
 * on a real size/cid change (72-06 Task 1).
 *
 * `replaceFile`/`restoreFileVersion`/`deleteFileVersion` publish only the
 * FILE's own IPNS record — the parent folder's sequence number (and hence
 * `listingCache`'s cache key) is unchanged, so the cache entry survives the
 * edit and the next `folder:updated` emission would otherwise serve the
 * PRE-edit size for the just-updated file (72-RESEARCH.md Critical Finding
 * 1). The fix mirrors the shipped `updateSharedFile` (68.2-02 Rule 1)
 * one-liner: `this.listingCache.delete(folderIpnsName)`, gated behind a
 * caller-computed "did size/cid actually change" signal so a genuine no-op
 * edit (e.g. `deleteFileVersion`, whose live content descriptor is
 * unchanged) does not needlessly bust an otherwise-valid cache.
 *
 * This suite drives the private `maybeRepublishFolderForFileMigration` seam
 * directly (per the plan's "driving replaceFile (or the seam directly)"
 * option) — isolating the cache-invalidation behavior from the write-chain
 * key recovery `replaceFile` itself requires, mirroring
 * `delete-item.test.ts`'s network-mock-only boundary (only
 * `resolveIpnsRecord`/`fetchFromIpfs` and the folder publish are mocked;
 * every `@cipherbox/core` seal primitive stays real).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import type { SdkEvent } from '../events';
import {
  sealChildReadKey,
  sealNode,
  type Node,
  type PublishedNode,
  type SealedChildRef,
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

const FOLDER_IPNS = 'k51folder-listing-cache';
const FILE_IPNS = 'k51file-listing-cache';
const FILE_NODE_ID = '44444444-4444-4444-8444-444444444444';
const GEN = 0;
const folderKey = new Uint8Array(32).fill(0x41);
const fileReadKey = new Uint8Array(32).fill(0x66);

async function buildChildRef(): Promise<SealedChildRef> {
  const readKeySealed = await sealChildReadKey(fileReadKey, folderKey, FILE_NODE_ID, 'file', GEN);
  return {
    name: 'edited.txt',
    ipnsName: FILE_IPNS,
    generation: GEN,
    versionFloor: 0n,
    readKeySealed,
  };
}

async function buildFilePublished(size: number): Promise<PublishedNode> {
  const node: Node = {
    schema: 'node/v3',
    kind: 'file',
    id: FILE_NODE_ID,
    generation: GEN,
    createdAt: 1000,
    modifiedAt: 1000 + size,
    content: {
      cid: `bafy-${size}`,
      fileIv: 'aXY=',
      size,
      mimeType: 'text/plain',
      encryptionMode: 'GCM',
      fileKey: new Uint8Array(32).fill(0x77),
      versions: [],
    },
  };
  // No write-body on this fixture — writeKey arg is unused (writeSealed omitted).
  return sealNode(node, fileReadKey, new Uint8Array(32));
}

function buildFolder(childRef: SealedChildRef): FolderState {
  return {
    ipnsName: FOLDER_IPNS,
    folderKey,
    // Zero writeKey = legacy registered-folder path: getWriteBodyParams
    // returns {} (no write-body, no network round-trip) — matches
    // helpers.ts's setupFolder pattern.
    writeKey: new Uint8Array(32),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: 1n,
    children: [childRef],
    metadata: null,
    lastLoadedAt: Date.now(),
    nodeId: 'folder-node-id',
    nodeGeneration: 0,
  };
}

/** Access to the private seam + private `listingCache` field under test. */
type ClientInternals = {
  listingCache: Map<string, { sequenceNumber: bigint; children: unknown[] }>;
  maybeRepublishFolderForFileMigration: (
    folderIpnsName: string,
    folder: FolderState,
    fileContentChanged: boolean,
    migratedIpnsPrivateKeyEncrypted?: string
  ) => Promise<void>;
};

describe('CipherBoxClient.maybeRepublishFolderForFileMigration listingCache invalidation (SC#4)', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('busts the parent listingCache and emits the fresh size when the file content actually changed', async () => {
    const childRef = await buildChildRef();
    const folder = buildFolder(childRef);
    client.getFolderTree().set(FOLDER_IPNS, folder);

    const events: SdkEvent[] = [];
    client.on((e) => events.push(e));

    // Pre-populate listingCache with a STALE entry (same sequenceNumber the
    // folder still carries — a file-only publish never bumps it) simulating a
    // listing resolved BEFORE this edit.
    (client as unknown as ClientInternals).listingCache.set(FOLDER_IPNS, {
      sequenceNumber: folder.sequenceNumber,
      children: [
        {
          ipnsName: FILE_IPNS,
          name: 'edited.txt',
          kind: 'file',
          size: 100,
          modifiedAt: 1000,
          sequence: 4,
        },
      ],
    });

    const newPublished = await buildFilePublished(250);
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === FILE_IPNS)
        return { cid: 'bafy-new', sequenceNumber: 9n, signatureVerified: true };
      return null;
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-new') return new TextEncoder().encode(JSON.stringify(newPublished));
      throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
    });

    await (client as unknown as ClientInternals).maybeRepublishFolderForFileMigration(
      FOLDER_IPNS,
      folder,
      true,
      undefined
    );

    expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledWith(FILE_IPNS, expect.anything());

    const updated = events.find(
      (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
    );
    expect(updated).toBeDefined();
    expect(updated?.children).toEqual([
      expect.objectContaining({ ipnsName: FILE_IPNS, size: 250 }),
    ]);
  });

  it('preserves the listingCache (no re-resolve) when the file content did not change', async () => {
    const childRef = await buildChildRef();
    const folder = buildFolder(childRef);
    client.getFolderTree().set(FOLDER_IPNS, folder);

    const events: SdkEvent[] = [];
    client.on((e) => events.push(e));

    const cachedChildren = [
      {
        ipnsName: FILE_IPNS,
        name: 'edited.txt',
        kind: 'file' as const,
        size: 100,
        modifiedAt: 1000,
        sequence: 4,
      },
    ];
    (client as unknown as ClientInternals).listingCache.set(FOLDER_IPNS, {
      sequenceNumber: folder.sequenceNumber,
      children: cachedChildren,
    });

    // Wired to resolve a DIFFERENT size if the cache were bypassed — proves a
    // genuine cache hit, not a coincidental resolve-returns-same-value case.
    const wouldBeNewPublished = await buildFilePublished(999);
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === FILE_IPNS)
        return { cid: 'bafy-wouldbe', sequenceNumber: 9n, signatureVerified: true };
      return null;
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx: unknown, cid: string) => {
      if (cid === 'bafy-wouldbe')
        return new TextEncoder().encode(JSON.stringify(wouldBeNewPublished));
      throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
    });

    await (client as unknown as ClientInternals).maybeRepublishFolderForFileMigration(
      FOLDER_IPNS,
      folder,
      false,
      undefined
    );

    expect(sdkCore.resolveIpnsRecord).not.toHaveBeenCalled();

    const updated = events.find(
      (e): e is Extract<SdkEvent, { type: 'folder:updated' }> => e.type === 'folder:updated'
    );
    expect(updated).toBeDefined();
    expect(updated?.children).toEqual(cachedChildren);
  });
});
