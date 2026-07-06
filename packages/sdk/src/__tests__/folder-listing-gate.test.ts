/**
 * Phase 68.2 Plan 01 (TDD): failing-first proof that the SDK's own internal
 * read path (ensureFolderLoaded -> dfsFindFolder -> resolvePublishedNode) is
 * gated by RotationHighWater.enforceResolved (ROT-07).
 *
 * Today the SDK's internal navigate path resolves children with ZERO ROT-07
 * gating -- the only production read-side gate lives in
 * apps/web/src/services/ipns.service.ts, which this phase eventually deletes
 * (RESEARCH.md Pitfall 2). This test proves the SDK-internal equivalent
 * BEFORE that deletion happens.
 *
 * Covers:
 *  - Test 1: a below-floor child resolve rejects with SequenceRegressionError
 *    and never yields a FolderState past the throw.
 *  - Test 2: enforceResolved is invoked exactly once per read-path resolve,
 *    sourcing `generation` from the PARENT's SealedChildRef mirror (never the
 *    child's own envelope generation -- Pitfall 3 / D-04).
 *  - Test 3: an unverified-signature resolve throws BEFORE enforceResolved is
 *    ever called (fail-closed; no floor mutation on an unverified record).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { SequenceRegressionError } from '../state/rotation-high-water';
import type { RotationHighWater } from '../state/rotation-high-water';
import type { Node } from '@cipherbox/core';

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
    unsealNode: vi.fn().mockResolvedValue({
      schema: 'node/v3',
      kind: 'folder',
      id: 'child-node-id',
      // Deliberately divergent from childRef.generation (7) below -- proves the
      // gate must never source `generation` from the child's own envelope
      // (Pitfall 3 / D-04).
      generation: 999,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: {
        ipnsPrivateKey: new Uint8Array(64).fill(0x44),
        writeChildren: [],
      },
    } satisfies Node),
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

const ROOT_IPNS = 'k51root-folder-listing-gate';
const CHILD_IPNS = 'k51child-folder-listing-gate';
const CHILD_NODE_ID = 'child-node-id';

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
 * Seeds a root FolderState (matching config.rootIpnsName) carrying one
 * SealedChildRef (readKeySealed side) + matching WriteChildRef (write chain
 * side) so `dfsFindFolder` takes the network-resolve path for the child.
 */
function seedRootWithChild(client: CipherBoxClient) {
  const childRef = {
    name: 'child-folder',
    ipnsName: CHILD_IPNS,
    // PARENT mirror -- the gate must source `generation` from THIS value,
    // never the child's own envelope generation (999, mocked above).
    generation: 7,
    versionFloor: 42n,
    readKeySealed: 'sealed-read-key-hex',
  };
  const rootMetadata: Node = {
    schema: 'node/v3',
    kind: 'root',
    id: 'root-node-id',
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [childRef],
    writeBody: {
      ipnsPrivateKey: new Uint8Array(64).fill(0x01),
      writeChildren: [{ childId: CHILD_NODE_ID, writeKeySealed: 'sealed-write-key-hex' }],
    },
  };
  client.getFolderTree().set(ROOT_IPNS, {
    ipnsName: ROOT_IPNS,
    folderKey: new Uint8Array(32).fill(0x10),
    writeKey: new Uint8Array(32).fill(0x11),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0x12),
      privateKey: new Uint8Array(64).fill(0x13),
    },
    sequenceNumber: 1n,
    children: [childRef],
    metadata: rootMetadata,
    lastLoadedAt: Date.now(),
    nodeId: 'root-node-id',
    nodeGeneration: 0,
  });
  return childRef;
}

/** Mocks the child's IPNS resolve + IPFS fetch round trip. */
function mockChildResolve(overrides?: { sequenceNumber?: bigint; signatureVerified?: boolean }) {
  vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
    cid: 'bafychild',
    sequenceNumber: overrides?.sequenceNumber ?? 5n,
    signatureVerified: overrides?.signatureVerified ?? true,
  });
  vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(
    new TextEncoder().encode(
      JSON.stringify({
        schema: 'node/v3',
        kind: 'folder',
        id: CHILD_NODE_ID,
        // Child's OWN envelope generation -- must never be threaded into
        // enforceResolved (Pitfall 3 / D-04).
        generation: 999,
        aeadVersion: 1,
        readSealed: 'x',
        writeSealed: 'y',
      })
    )
  );
}

describe('CipherBoxClient — internal read-path ROT-07 gate (folder-listing-gate)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('ensureFolderLoaded rejects with SequenceRegressionError when enforceResolved throws on a below-floor child resolve, and never returns a FolderState past the throw', async () => {
    const rotationHighWater = fakeRotationHighWater(async ({ nodeId, seq }) => {
      throw new SequenceRegressionError(nodeId, 999, seq);
    });
    const client = new CipherBoxClient(
      createTestConfig({ rotationHighWater, rootIpnsName: ROOT_IPNS })
    );
    seedRootWithChild(client);
    mockChildResolve();

    await expect(client.ensureFolderLoaded(CHILD_IPNS)).rejects.toThrow(SequenceRegressionError);
    expect(client.getFolderTree().get(CHILD_IPNS)).toBeUndefined();
  });

  it('enforceResolved is invoked exactly once per read-path resolve during ensureFolderLoaded, sourcing generation from the PARENT mirror', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(
      createTestConfig({ rotationHighWater, rootIpnsName: ROOT_IPNS })
    );
    const childRef = seedRootWithChild(client);
    mockChildResolve({ sequenceNumber: 5n });

    const result = await client.ensureFolderLoaded(CHILD_IPNS);

    expect(result).not.toBeNull();
    expect(rotationHighWater.enforceResolved).toHaveBeenCalledTimes(1);
    expect(rotationHighWater.enforceResolved).toHaveBeenCalledWith(
      expect.objectContaining({
        nodeId: CHILD_IPNS,
        seq: 5,
        generation: childRef.generation, // 7 -- PARENT mirror, NOT the child's own 999
        versionFloor: Number(childRef.versionFloor),
      })
    );
  });

  it('throws BEFORE calling enforceResolved when the resolved record has signatureVerified=false (fail-closed, no floor mutation)', async () => {
    const rotationHighWater = fakeRotationHighWater(async () => undefined);
    const client = new CipherBoxClient(
      createTestConfig({ rotationHighWater, rootIpnsName: ROOT_IPNS })
    );
    seedRootWithChild(client);
    mockChildResolve({ signatureVerified: false });

    await expect(client.ensureFolderLoaded(CHILD_IPNS)).rejects.toThrow();
    expect(rotationHighWater.enforceResolved).not.toHaveBeenCalled();
  });
});
