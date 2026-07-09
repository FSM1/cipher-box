/**
 * TDD tests for 70.1-07: `reconcileFolderSequence` must gate on the
 * FRESHLY-RESOLVED generation, not the cached `folderTree.nodeGeneration`
 * (SC#5/D-09).
 *
 * `reconcileFolderSequence` (`client.ts:1789-1834`) currently sources
 * `nodeGeneration = this.folderTree.get(ipnsName)?.nodeGeneration ?? 0` --
 * a value the client itself minted at the LAST successful load/publish, not
 * the actual generation of the record it just resolved from the network.
 * Since `resolveIpnsRecord` returns no generation field at all (generation
 * lives inside the sealed node body), closing this gap requires fetching the
 * resolved CID and unsealing it with the folder's read key INSIDE the
 * reconcile path, then feeding THAT generation into
 * `RotationHighWater.enforceResolved` -- fail closed if the unseal fails,
 * never silently falling back to the cached value.
 *
 * Only the network-touching sdk-core seams (`resolveIpnsRecord`,
 * `fetchFromIpfs`) are mocked -- `sealNode`/`unsealNode` stay real
 * (`@cipherbox/core` is NOT mocked) so fixtures are genuine AAD-bound
 * envelopes, mirroring move-write-link-rehoming.test.ts's pattern.
 *
 * `reconcileFolderSequence` is private; these tests invoke it directly via a
 * narrow cast (Task 1's plan-sanctioned "narrow harness") to isolate the gate
 * from the unrelated publish/rotation machinery every public write-path
 * caller also triggers.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderState } from '../types';
import { sealNode } from '@cipherbox/core';
import {
  createRotationHighWater,
  GenerationRegressionError,
  type RotationHighWater,
  type EnforceResolvedParams,
  type HighWaterStore,
  type CombinedFloorRecord,
} from '../state/rotation-high-water';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

const TEST_NODE_UUID = '11111111-1111-4111-8111-111111111111';

/**
 * Narrow structural type exposing the private method under test. Deliberately
 * NOT intersected with `CipherBoxClient` -- intersecting a private class
 * member with a public structural re-declaration collapses to `never`
 * (TS2339), so this type stands alone and the cast goes through `unknown`.
 */
type ClientWithReconcile = {
  reconcileFolderSequence(
    ipnsName: string,
    expectedSequence: bigint,
    folderReadKey: Uint8Array
  ): Promise<void>;
};

function asReconcilable(client: CipherBoxClient): ClientWithReconcile {
  return client as unknown as ClientWithReconcile;
}

/** Fake HighWaterStore -- a plain in-memory Map, used to back a REAL createRotationHighWater. */
function createInMemoryStore(): HighWaterStore {
  const map = new Map<string, CombinedFloorRecord>();
  return {
    async get(nodeId) {
      return map.get(nodeId);
    },
    async put(nodeId, record) {
      map.set(nodeId, record);
    },
  };
}

/** Fake RotationHighWater whose enforceResolved just captures every call's params. */
function createCapturingRotationHighWater(): {
  rotationHighWater: RotationHighWater;
  calls: EnforceResolvedParams[];
} {
  const calls: EnforceResolvedParams[] = [];
  const rotationHighWater: RotationHighWater = {
    getGenerationFloor: vi.fn(),
    bumpGeneration: vi.fn(),
    seedFromGrant: vi.fn(),
    getSeqFloor: vi.fn(),
    bumpSeq: vi.fn(),
    enforceResolved: vi.fn(async (params: EnforceResolvedParams) => {
      calls.push(params);
    }),
  };
  return { rotationHighWater, calls };
}

/** Seeds a minimal loaded FolderState directly into folderTree, mirroring helpers.ts's setupFolder. */
function seedFolder(
  client: CipherBoxClient,
  opts: {
    ipnsName: string;
    folderKey: Uint8Array;
    cachedGeneration: number;
    sequenceNumber: bigint;
  }
): void {
  const state: FolderState = {
    ipnsName: opts.ipnsName,
    folderKey: opts.folderKey,
    writeKey: new Uint8Array(32),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(2),
      privateKey: new Uint8Array(64).fill(3),
    },
    sequenceNumber: opts.sequenceNumber,
    children: [],
    metadata: null,
    lastLoadedAt: Date.now(),
    nodeId: TEST_NODE_UUID,
    nodeGeneration: opts.cachedGeneration,
  };
  client.getFolderTree().set(opts.ipnsName, state);
}

/** Builds a real, AAD-bound PublishedNode sealed under `sealUnderKey` at `generation`. */
async function buildPublishedNodeAtGeneration(
  generation: number,
  sealUnderKey: Uint8Array
): Promise<Uint8Array> {
  const published = await sealNode(
    {
      schema: 'node/v3',
      kind: 'folder',
      id: TEST_NODE_UUID,
      generation,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
    },
    sealUnderKey,
    new Uint8Array(32) // dummy writeKey -- no writeBody present, so unused
  );
  return new TextEncoder().encode(JSON.stringify(published));
}

describe('CipherBoxClient.reconcileFolderSequence freshly-resolved generation gate (70.1-07 SC#5)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('feeds enforceResolved the freshly-resolved (fetched+unsealed) generation, not the stale cached folderTree value', async () => {
    const ipnsName = 'k51folder-stale-cache';
    const folderKey = new Uint8Array(32).fill(0x11);
    const cachedGeneration = 1; // stale -- lower than the actual published generation
    const actualGeneration = 5; // the record's real, freshly-resolved generation
    const expectedSequence = 1n;

    const { rotationHighWater, calls } = createCapturingRotationHighWater();
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedFolder(client, {
      ipnsName,
      folderKey,
      cachedGeneration,
      sequenceNumber: expectedSequence,
    });

    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafyfolder',
      sequenceNumber: expectedSequence,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      await buildPublishedNodeAtGeneration(actualGeneration, folderKey)
    );

    await asReconcilable(client).reconcileFolderSequence(ipnsName, expectedSequence, folderKey);

    expect(calls).toHaveLength(1);
    expect(calls[0].generation).toBe(actualGeneration);
    expect(calls[0].generation).not.toBe(cachedGeneration);
  });

  it('rejects a self-inflicted lower-generation body at a higher sequence, fail-closed, using the ACTUAL resolved generation', async () => {
    const ipnsName = 'k51folder-self-equivocation';
    const folderKey = new Uint8Array(32).fill(0x22);
    const durableFloorGeneration = 5;
    // Cached folderTree value matches the durable floor -- if the gate were
    // (buggily) fed this cached value instead of the fresh one, no
    // regression would ever be detected here.
    const cachedGeneration = durableFloorGeneration;
    const selfInflictedLowerGeneration = 2;

    const store = createInMemoryStore();
    const rotationHighWater = createRotationHighWater(store);
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedFolder(client, {
      ipnsName,
      folderKey,
      cachedGeneration,
      sequenceNumber: 1n,
    });

    // Seed the durable floor to durableFloorGeneration via a prior legitimate commit.
    await rotationHighWater.enforceResolved({
      nodeId: ipnsName,
      seq: 1,
      generation: durableFloorGeneration,
      versionFloor: 0,
    });

    // A later resolve returns a body whose ACTUAL generation regressed below
    // the durable floor, at a higher sequence number (self-inflicted bug).
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafyfolder2',
      sequenceNumber: 2n,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      await buildPublishedNodeAtGeneration(selfInflictedLowerGeneration, folderKey)
    );

    await expect(
      asReconcilable(client).reconcileFolderSequence(ipnsName, 2n, folderKey)
    ).rejects.toThrow(GenerationRegressionError);
  });

  it('fails closed when the folder read key cannot unseal the freshly-resolved node (never falls back to the cached generation)', async () => {
    const ipnsName = 'k51folder-wrong-key';
    const correctFolderKey = new Uint8Array(32).fill(0x33);
    const keyActuallyUsedToSeal = new Uint8Array(32).fill(0x99); // simulates tamper/corruption
    const cachedGeneration = 7;
    const expectedSequence = 1n;

    const { rotationHighWater, calls } = createCapturingRotationHighWater();
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedFolder(client, {
      ipnsName,
      folderKey: correctFolderKey,
      cachedGeneration,
      sequenceNumber: expectedSequence,
    });

    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
      cid: 'bafyfolder3',
      sequenceNumber: expectedSequence,
      signatureVerified: true,
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
      await buildPublishedNodeAtGeneration(4, keyActuallyUsedToSeal)
    );

    await expect(
      asReconcilable(client).reconcileFolderSequence(ipnsName, expectedSequence, correctFolderKey)
    ).rejects.toThrow();

    // Fail-closed: the gate must never have been invoked with a value derived
    // from silently swallowing the unseal failure and falling back to the
    // stale cached generation.
    expect(calls).toHaveLength(0);
  });
});
