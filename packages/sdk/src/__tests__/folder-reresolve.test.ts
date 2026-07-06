/**
 * Phase 68.2 Plan 13 (TDD, gap-closure): failing-first proof that an
 * ALREADY-LOADED folder re-resolves its own IPNS record from the network on
 * `{ forceResolve: true }`, gated through the ROT-07 durable anti-rollback
 * floor, closing the self-referential cache-clock bug (SDK-READ-03 / SC#5).
 *
 * Today `ensureFolderLoaded` (client.ts ~L1549) short-circuits on any
 * already-loaded `folderTree` entry and returns it verbatim -- it never
 * re-resolves from the network. `resolveListingChildren` then compares the
 * incoming sequenceNumber against the SAME stale `folder.sequenceNumber` the
 * short-circuit just returned, a no-op comparison against itself. An owner
 * who loaded a shared-out folder once never sees a grantee's later upload
 * without writing first.
 *
 * Covers:
 *  - Test 1: `{ forceResolve: true }` re-resolves the folder's OWN IPNS
 *    record, advances the stored sequenceNumber/children in place, and the
 *    new child surfaces through `listFolder`'s resolved listing too.
 *  - Test 2: the re-resolve is GATED -- a below-floor resolve still rejects
 *    with SequenceRegressionError, the gate is invoked (not bypassed), and
 *    the stored folderTree entry is left unchanged.
 *  - Test 3: WITHOUT forceResolve, the cached fast path is preserved (no
 *    second `resolveIpnsRecord` call) so write chokepoints stay cheap.
 *  - Test 4: concurrent forceResolve calls for the same ipnsName dedupe to a
 *    single network resolve.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { SequenceRegressionError } from '../state/rotation-high-water';
import type { RotationHighWater } from '../state/rotation-high-water';
import type { Node, SealedChildRef } from '@cipherbox/core';

// ── sdk-core mock (network-touching seams only) ─────────────────────────
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

// ── @cipherbox/core mock (crypto stubbed so fixtures don't need real AEAD) ──
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    unsealChildReadKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0x42)),
    unsealChildWriteKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0x43)),
    unsealNode: vi.fn(),
  };
});

// ── @cipherbox/crypto mock (deriveEd25519PublicKey lives here, not core) ────
vi.mock('@cipherbox/crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/crypto')>();
  return {
    ...actual,
    deriveEd25519PublicKey: vi.fn().mockReturnValue(new Uint8Array(32).fill(0x45)),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';
import { unsealNode } from '@cipherbox/core';

const FOLDER_IPNS = 'k51folder-reresolve';
const FOLDER_NODE_ID = 'folder-reresolve-node-id';
const NEW_CHILD_IPNS = 'k51newchild-reresolve';
const NEW_CHILD_NODE_ID = 'new-child-reresolve-node-id';

const NEW_CHILD_REF: SealedChildRef = {
  name: 'new-file.txt',
  ipnsName: NEW_CHILD_IPNS,
  generation: 0,
  versionFloor: 0n,
  readKeySealed: 'sealed-new-child-key-hex',
};

/** A fake RotationHighWater whose enforceResolved is a controllable vi.fn(). */
function fakeRotationHighWater(enforceResolved: RotationHighWater['enforceResolved']) {
  return {
    getGenerationFloor: vi.fn(),
    bumpGeneration: vi.fn(),
    seedFromGrant: vi.fn(),
    getSeqFloor: vi.fn(),
    bumpSeq: vi.fn(),
    enforceResolved: vi.fn(enforceResolved),
  } satisfies RotationHighWater;
}

/**
 * Seeds an ALREADY-LOADED folder (real folderKey + writeKey + nodeGeneration)
 * directly into `folderTree`, mirroring `loadFolder`'s FolderState shape.
 * Children start empty -- the new child only appears after a successful
 * forceResolve re-resolve.
 */
function seedLoadedFolder(
  client: CipherBoxClient,
  opts?: { sequenceNumber?: bigint; generation?: number }
) {
  const sequenceNumber = opts?.sequenceNumber ?? 3n;
  const generation = opts?.generation ?? 2;
  const metadata: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: FOLDER_NODE_ID,
    generation,
    createdAt: 0,
    modifiedAt: 0,
    children: [],
    writeBody: {
      ipnsPrivateKey: new Uint8Array(64).fill(0x23),
      writeChildren: [],
    },
  };
  client.getFolderTree().set(FOLDER_IPNS, {
    ipnsName: FOLDER_IPNS,
    folderKey: new Uint8Array(32).fill(0x20),
    writeKey: new Uint8Array(32).fill(0x21),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0x22),
      privateKey: new Uint8Array(64).fill(0x23),
    },
    sequenceNumber,
    children: [],
    metadata,
    lastLoadedAt: Date.now(),
    nodeId: FOLDER_NODE_ID,
    nodeGeneration: generation,
  });
}

/**
 * Mocks the FOLDER's own IPNS resolve + IPFS fetch + unseal round trip
 * (returning a fresh node whose children include NEW_CHILD_REF), plus the
 * per-child resolve round trip for NEW_CHILD_IPNS (so `listFolder`'s
 * resolved-listing step can surface it too).
 */
function mockFolderReresolve(opts?: {
  folderSequence?: bigint;
  folderSignatureVerified?: boolean;
  folderResultGeneration?: number;
}) {
  const folderSeq = opts?.folderSequence ?? 4n;
  const folderVerified = opts?.folderSignatureVerified ?? true;
  const resultGeneration = opts?.folderResultGeneration ?? 3;

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
    if (ipnsName === FOLDER_IPNS) {
      return {
        cid: 'bafyfolder-new',
        sequenceNumber: folderSeq,
        signatureVerified: folderVerified,
      };
    }
    if (ipnsName === NEW_CHILD_IPNS) {
      return { cid: 'bafychild-new', sequenceNumber: 1n, signatureVerified: true };
    }
    return null;
  });

  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx, cid: string) => {
    if (cid === 'bafyfolder-new') {
      return new TextEncoder().encode(
        JSON.stringify({
          schema: 'node/v3',
          kind: 'folder',
          id: FOLDER_NODE_ID,
          // Deliberately divergent from existing.nodeGeneration -- proves the
          // gate must never source `generation` from this envelope value
          // (Pitfall 3 / D-04).
          generation: 999,
          aeadVersion: 1,
          readSealed: 'x',
          writeSealed: 'y',
        })
      );
    }
    if (cid === 'bafychild-new') {
      return new TextEncoder().encode(
        JSON.stringify({
          schema: 'node/v3',
          kind: 'file',
          id: NEW_CHILD_NODE_ID,
          generation: 0,
          aeadVersion: 1,
          readSealed: 'x',
        })
      );
    }
    throw new Error(`unexpected fetchFromIpfs cid: ${cid}`);
  });

  vi.mocked(unsealNode).mockImplementation(async (published: { id: string }) => {
    if (published.id === FOLDER_NODE_ID) {
      return {
        schema: 'node/v3',
        kind: 'folder',
        id: FOLDER_NODE_ID,
        generation: resultGeneration,
        createdAt: 0,
        modifiedAt: 0,
        children: [NEW_CHILD_REF],
        writeBody: {
          ipnsPrivateKey: new Uint8Array(64).fill(0x23),
          writeChildren: [],
        },
      } as unknown as Node;
    }
    if (published.id === NEW_CHILD_NODE_ID) {
      return {
        schema: 'node/v3',
        kind: 'file',
        id: NEW_CHILD_NODE_ID,
        generation: 0,
        createdAt: 0,
        modifiedAt: 1234,
        content: { size: 42 },
      } as unknown as Node;
    }
    throw new Error(`unexpected unsealNode call for id ${published.id}`);
  });
}

describe('CipherBoxClient — gated live-resolve-on-navigation (folder-reresolve)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('ensureFolderLoaded({forceResolve:true}) re-resolves an already-loaded folder and surfaces a new child (also via listFolder)', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedLoadedFolder(client, { sequenceNumber: 3n, generation: 2 });
    mockFolderReresolve({ folderSequence: 4n });

    const result = await client.ensureFolderLoaded(FOLDER_IPNS, { forceResolve: true });

    expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledWith(FOLDER_IPNS, expect.anything());
    expect(result).not.toBeNull();
    expect(result!.sequenceNumber).toBe(4n);
    expect(result!.children).toEqual([NEW_CHILD_REF]);
    expect(client.getFolderTree().get(FOLDER_IPNS)!.sequenceNumber).toBe(4n);

    const listed = await client.listFolder(FOLDER_IPNS, { forceResolve: true });
    expect(listed.map((c) => c.ipnsName)).toContain(NEW_CHILD_IPNS);
  });

  it('rejects with SequenceRegressionError when the gate rejects a below-floor re-resolve, and leaves the folderTree entry unchanged', async () => {
    const rotationHighWater = fakeRotationHighWater(async ({ nodeId, seq }) => {
      throw new SequenceRegressionError(nodeId, 999, seq);
    });
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedLoadedFolder(client, { sequenceNumber: 3n, generation: 2 });
    mockFolderReresolve({ folderSequence: 4n });

    await expect(client.ensureFolderLoaded(FOLDER_IPNS, { forceResolve: true })).rejects.toThrow(
      SequenceRegressionError
    );

    expect(rotationHighWater.enforceResolved).toHaveBeenCalledTimes(1);
    const stored = client.getFolderTree().get(FOLDER_IPNS)!;
    expect(stored.sequenceNumber).toBe(3n);
    expect(stored.children).toEqual([]);
  });

  it('does NOT re-resolve an already-loaded folder without forceResolve (cached fast path preserved)', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedLoadedFolder(client, { sequenceNumber: 3n, generation: 2 });
    mockFolderReresolve({ folderSequence: 4n });

    const result = await client.ensureFolderLoaded(FOLDER_IPNS);

    expect(sdkCore.resolveIpnsRecord).not.toHaveBeenCalled();
    expect(result).not.toBeNull();
    expect(result!.sequenceNumber).toBe(3n);
    expect(result!.children).toEqual([]);
  });

  it('dedupes concurrent forceResolve calls for the same ipnsName to a single network resolve', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(createTestConfig({ rotationHighWater }));
    seedLoadedFolder(client, { sequenceNumber: 3n, generation: 2 });
    mockFolderReresolve({ folderSequence: 4n });

    const [r1, r2] = await Promise.all([
      client.ensureFolderLoaded(FOLDER_IPNS, { forceResolve: true }),
      client.ensureFolderLoaded(FOLDER_IPNS, { forceResolve: true }),
    ]);

    const folderResolveCalls = vi
      .mocked(sdkCore.resolveIpnsRecord)
      .mock.calls.filter(([ipnsName]) => ipnsName === FOLDER_IPNS);
    expect(folderResolveCalls).toHaveLength(1);
    expect(r1).toBe(r2);
  });
});
