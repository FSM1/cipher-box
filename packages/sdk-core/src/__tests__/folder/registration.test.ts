/**
 * TDD tests for folder/registration.ts — nodeId/nodeGeneration required fields (D-06).
 *
 * Phase 64 Plan 01 Task 1.
 *
 * RED phase: tests written before implementation.
 * - "throws when nodeId is not provided": FAILS in RED (function falls back to
 *   crypto.randomUUID() instead of throwing) → PASSES in GREEN after guard added.
 * - "sealed Node preserves the supplied nodeId and nodeGeneration": tests the
 *   round-trip using REAL sealNode/unsealNode from @cipherbox/core (no codec mock).
 *
 * Mock boundary: only the network I/O layers (ipfs + ipns) are mocked; the
 * publishWithCas CAS helper and @cipherbox/core codec run with real implementations
 * so that the sealed envelope genuinely reflects what updateFolderMetadataAndPublish
 * builds.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { updateFolderMetadataAndPublish } from '../../folder/registration';
import type { PublishedNode, WriteChildRef } from '@cipherbox/core';
import { unsealNode, sealNode } from '@cipherbox/core';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — only I/O layers; @cipherbox/core runs real
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
}));

vi.mock('../../ipfs', () => ({
  addToIpfs: mockFns.addToIpfs,
  fetchFromIpfs: mockFns.fetchFromIpfs,
}));

vi.mock('../../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  batchPublishIpnsRecords: mockFns.batchPublishIpnsRecords,
}));

// mergeChildren is a Phase-64-02 stub; stub it out here so the retry
// test can exercise the CAS path without depending on Plan 64-02.
vi.mock('../../folder/merge', () => ({
  mergeChildren: (_base: unknown[], local: unknown[], _remote: unknown[]) => local,
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NODE_ID = '550e8400-e29b-41d4-a716-446655440000';
const READ_KEY = new Uint8Array(32).fill(0xab);
const WRITE_KEY = new Uint8Array(32).fill(0xcd);
const IPNS_PRIVATE_KEY = new Uint8Array(64).fill(0x01);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('updateFolderMetadataAndPublish — nodeId/nodeGeneration required (D-06)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default happy-path mocks
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmTestCid', size: 100, recorded: true });
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });
  });

  // -------------------------------------------------------------------------
  // RED test: will FAIL before the D-06 fix because the function currently
  // falls back to crypto.randomUUID() instead of throwing.
  // -------------------------------------------------------------------------
  it('throws when nodeId is not provided (D-06 required field)', async () => {
    const ctx = createMockContext();

    await expect(
      // @ts-expect-error — nodeId is required (D-06); omitting it must be a type error
      updateFolderMetadataAndPublish({
        children: [],
        readKey: READ_KEY,
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        ipnsName: 'k51-test',
        sequenceNumber: 1n,
        ctx,
        // nodeId INTENTIONALLY OMITTED — tests the missing-guard (D-06 bug)
      })
    ).rejects.toThrow('nodeId is required');
  });

  it('throws when nodeGeneration is not provided (D-06 required field)', async () => {
    const ctx = createMockContext();

    await expect(
      // @ts-expect-error — nodeGeneration is required (D-06); omitting it must be a type error
      updateFolderMetadataAndPublish({
        children: [],
        readKey: READ_KEY,
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        ipnsName: 'k51-test',
        sequenceNumber: 1n,
        ctx,
        nodeId: NODE_ID,
        // nodeGeneration INTENTIONALLY OMITTED
      })
    ).rejects.toThrow('nodeGeneration is required');
  });

  // -------------------------------------------------------------------------
  // Behavioral test: round-trip the nodeId and nodeGeneration through the
  // real sealNode/unsealNode codec (no @cipherbox/core mock in this file).
  // -------------------------------------------------------------------------
  it('sealed Node envelope contains the supplied nodeId (plaintext, tamper-evident)', async () => {
    const ctx = createMockContext();
    let capturedBytes: Uint8Array | null = null;

    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedBytes = data;
      return { cid: 'QmCapture', size: data.length, recorded: true };
    });

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-round-trip',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    expect(capturedBytes).not.toBeNull();
    const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;

    // id and generation are plaintext on the PublishedNode envelope (per types.ts L181-192)
    expect(publishedNode.id).toBe(NODE_ID);
    expect(publishedNode.generation).toBe(0);
  });

  it('unsealNode round-trip: sealed body preserves nodeId and nodeGeneration', async () => {
    const ctx = createMockContext();
    const nodeGeneration = 7;
    let capturedBytes: Uint8Array | null = null;

    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedBytes = data;
      return { cid: 'QmRoundTrip', size: data.length, recorded: true };
    });

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-unseal-trip',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration,
    });

    expect(capturedBytes).not.toBeNull();
    const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;

    // Full round-trip: unseal and verify the decrypted node carries the supplied identity
    const unsealed = await unsealNode(publishedNode, READ_KEY);
    expect(unsealed.id).toBe(NODE_ID);
    expect(unsealed.generation).toBe(nodeGeneration);
  });

  it('two CAS encode attempts (on retry) use the same nodeId — no UUID drift', async () => {
    const ctx = createMockContext();
    const capturedIds: string[] = [];

    // First attempt: simulate 409 (CAS conflict), second attempt succeeds
    let callCount = 0;
    let firstCid = '';
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      const node = JSON.parse(new TextDecoder().decode(data)) as PublishedNode;
      capturedIds.push(node.id);
      callCount++;
      const cid = `QmAttempt${callCount}`;
      if (callCount === 1) firstCid = cid;
      return { cid, size: data.length, recorded: true };
    });

    // First IPNS publish: 409 conflict
    const axios409 = Object.assign(new Error('Conflict'), { response: { status: 409 } });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(axios409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 3n });

    // On 409, publishWithCas re-resolves for the latest seq
    // The "remote" fetch uses the CID from the FIRST encode attempt so decryption
    // succeeds (same key, same node contents). This simulates a concurrent writer
    // that published the same data at the same time.
    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 2n,
      cid: 'QmRemoteFromConcurrentWrite',
    });
    // Provide a properly sealed remote node so decodeRemote (unsealNode) succeeds.
    // We use the same key and content, so the merge returns the local data unchanged.
    const remoteNode = JSON.parse(
      new TextDecoder().decode(
        await (async () => {
          const { sealNode: realSeal } = await import('@cipherbox/core');
          const n = {
            schema: 'node/v3' as const,
            kind: 'folder' as const,
            id: NODE_ID,
            generation: 0,
            createdAt: Date.now(),
            modifiedAt: Date.now(),
            children: [],
          };
          const sealed = await realSeal(n, READ_KEY, new Uint8Array(32));
          return new TextEncoder().encode(JSON.stringify(sealed));
        })()
      )
    );
    mockFns.fetchFromIpfs.mockResolvedValue(new TextEncoder().encode(JSON.stringify(remoteNode)));

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-retry',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    // Both encode attempts must use the same nodeId (no UUID drift across retries)
    expect(capturedIds).toHaveLength(2);
    expect(capturedIds[0]).toBe(NODE_ID);
    expect(capturedIds[1]).toBe(NODE_ID);
    // Suppress unused variable warning
    void firstCid;
  });
});

// ---------------------------------------------------------------------------
// SC#1 Critical Finding 2 — base-aware write-body CAS-merge (72-03 Task 1)
// ---------------------------------------------------------------------------

/**
 * Build a real sealed remote PublishedNode carrying the given writeChildren,
 * used to simulate a racing writer's published state fetched via decodeRemote
 * during a CAS-409 retry.
 */
async function buildSealedRemote(writeChildren: WriteChildRef[]): Promise<Uint8Array> {
  const node = {
    schema: 'node/v3' as const,
    kind: 'folder' as const,
    id: NODE_ID,
    generation: 0,
    createdAt: Date.now(),
    modifiedAt: Date.now(),
    children: [],
    writeBody: {
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      writeChildren,
    },
  };
  const sealed = await sealNode(node, READ_KEY, WRITE_KEY);
  return new TextEncoder().encode(JSON.stringify(sealed));
}

describe('updateFolderMetadataAndPublish — base-aware write-body CAS-merge (SC#1 Critical Finding 2)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => ({
      cid: 'QmTestCid',
      size: data.length,
      recorded: true,
    }));
  });

  it('Test A — no concurrent change: a clean publish with a dropped childId omits it from the sealed write-body', async () => {
    const ctx = createMockContext();
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });

    const baseWriteChildren: WriteChildRef[] = [
      { childId: 'X', writeKeySealed: 'seal-x' },
      { childId: 'Z', writeKeySealed: 'seal-z' },
    ];
    // Local already dropped X (e.g. deleteItem's write-chain trim).
    const localWriteChildren: WriteChildRef[] = [{ childId: 'Z', writeKeySealed: 'seal-z' }];

    const { publishedWriteChildren } = await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: localWriteChildren,
      recipientPins: [],
      baseWriteChildren,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-write-merge-a',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    expect(publishedWriteChildren).toEqual([{ childId: 'Z', writeKeySealed: 'seal-z' }]);
  });

  it('Test B — concurrent add: a local delete is honored AND a remote-only concurrent add is kept', async () => {
    const ctx = createMockContext();
    const capturedIds: string[] = [];
    let callCount = 0;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      const node = JSON.parse(new TextDecoder().decode(data)) as PublishedNode;
      capturedIds.push(node.id);
      callCount++;
      return { cid: `QmAttempt${callCount}`, size: data.length, recorded: true };
    });

    const axios409 = Object.assign(new Error('Conflict'), { response: { status: 409 } });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(axios409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 3n });
    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 2n,
      cid: 'QmRemoteFromConcurrentWrite',
    });

    const baseWriteChildren: WriteChildRef[] = [{ childId: 'X', writeKeySealed: 'seal-x' }];
    // Local already dropped X, has nothing else.
    const localWriteChildren: WriteChildRef[] = [];
    // Remote (racing writer, unaware of the delete) still has X, plus a
    // brand-new concurrently-added Y absent from base.
    const remoteWriteChildren: WriteChildRef[] = [
      { childId: 'X', writeKeySealed: 'seal-x' },
      { childId: 'Y', writeKeySealed: 'seal-y' },
    ];
    mockFns.fetchFromIpfs.mockResolvedValue(await buildSealedRemote(remoteWriteChildren));

    const { publishedWriteChildren } = await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: localWriteChildren,
      recipientPins: [],
      baseWriteChildren,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-write-merge-b',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    expect(publishedWriteChildren).toEqual([{ childId: 'Y', writeKeySealed: 'seal-y' }]);
    expect(capturedIds).toHaveLength(2);
  });

  it("Test C — resurrection guard: a concurrent 409 with the racing writer's pre-delete snapshot must NOT resurrect the dropped childId", async () => {
    const ctx = createMockContext();
    let callCount = 0;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      callCount++;
      return { cid: `QmAttempt${callCount}`, size: data.length, recorded: true };
    });

    const axios409 = Object.assign(new Error('Conflict'), { response: { status: 409 } });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(axios409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 3n });
    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 2n,
      cid: 'QmRemoteFromConcurrentWrite',
    });

    // Base has {X, Z}; local dropped X (has {Z}); the racing writer's remote
    // snapshot predates the delete and still carries {X, Z} unchanged.
    const baseWriteChildren: WriteChildRef[] = [
      { childId: 'X', writeKeySealed: 'seal-x' },
      { childId: 'Z', writeKeySealed: 'seal-z' },
    ];
    const localWriteChildren: WriteChildRef[] = [{ childId: 'Z', writeKeySealed: 'seal-z' }];
    const remoteWriteChildren: WriteChildRef[] = [
      { childId: 'X', writeKeySealed: 'seal-x' },
      { childId: 'Z', writeKeySealed: 'seal-z' },
    ];
    mockFns.fetchFromIpfs.mockResolvedValue(await buildSealedRemote(remoteWriteChildren));

    const { publishedWriteChildren } = await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: localWriteChildren,
      recipientPins: [],
      baseWriteChildren,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-write-merge-c',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    // X must NOT be resurrected — merged write-body is exactly {Z}.
    expect(publishedWriteChildren).toEqual([{ childId: 'Z', writeKeySealed: 'seal-z' }]);
  });

  it('Test D — concurrent REMOTE deletion: local never touched X, but a concurrent remote writer deleted it — merge must NOT resurrect X (F5)', async () => {
    const ctx = createMockContext();
    let callCount = 0;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      callCount++;
      return { cid: `QmAttempt${callCount}`, size: data.length, recorded: true };
    });

    const axios409 = Object.assign(new Error('Conflict'), { response: { status: 409 } });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(axios409)
      .mockResolvedValueOnce({ success: true, sequenceNumber: 3n });
    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 2n,
      cid: 'QmRemoteFromConcurrentWrite',
    });

    // Base has {X, Z}; local's own transaction never touched X (it is still
    // present, unchanged from base, in local's write-body); the racing
    // writer concurrently DELETED X for real (its remote snapshot only has
    // {Z}) — this is a genuine concurrent delete, not a stale pre-delete
    // snapshot (contrast with Test C).
    const baseWriteChildren: WriteChildRef[] = [
      { childId: 'X', writeKeySealed: 'seal-x' },
      { childId: 'Z', writeKeySealed: 'seal-z' },
    ];
    const localWriteChildren: WriteChildRef[] = [
      { childId: 'X', writeKeySealed: 'seal-x' },
      { childId: 'Z', writeKeySealed: 'seal-z' },
    ];
    const remoteWriteChildren: WriteChildRef[] = [{ childId: 'Z', writeKeySealed: 'seal-z' }];
    mockFns.fetchFromIpfs.mockResolvedValue(await buildSealedRemote(remoteWriteChildren));

    const { publishedWriteChildren } = await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: localWriteChildren,
      recipientPins: [],
      baseWriteChildren,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-write-merge-d',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    // The concurrent remote deletion of X must be honored — merged
    // write-body is exactly {Z}, X is NOT resurrected by local's untouched
    // (now-stale) copy.
    expect(publishedWriteChildren).toEqual([{ childId: 'Z', writeKeySealed: 'seal-z' }]);
  });
});

describe('updateFolderMetadataAndPublish — recipient-pin snapshot fail-closed (thread-80-4)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => ({
      cid: 'QmPinCid',
      size: data.length,
      recorded: true,
    }));
  });

  it('rejects an OMITTED recipientPins snapshot when a write-body is sealed (writeKey present)', async () => {
    const ctx = createMockContext();
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });

    await expect(
      updateFolderMetadataAndPublish({
        children: [],
        readKey: READ_KEY,
        writeKey: WRITE_KEY,
        writeChildren: [],
        // recipientPins deliberately OMITTED — must fail closed, not silently
        // seal [] and erase existing owner-sealed pins on a clean publish.
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        ipnsName: 'k51-pin-omitted',
        sequenceNumber: 1n,
        ctx,
        nodeId: NODE_ID,
        nodeGeneration: 0,
      })
    ).rejects.toThrow(/recipientPins snapshot is required/);

    // Fail-closed BEFORE any upload/publish I/O.
    expect(mockFns.addToIpfs).not.toHaveBeenCalled();
    expect(mockFns.createAndPublishIpnsRecord).not.toHaveBeenCalled();
  });

  it('preserves an explicit recipientPins snapshot into the sealed write-body on a clean (no-409) publish', async () => {
    const ctx = createMockContext();
    let capturedNode: PublishedNode | undefined;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedNode = JSON.parse(new TextDecoder().decode(data)) as PublishedNode;
      return { cid: 'QmPinCid', size: data.length, recorded: true };
    });
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });

    const pins = ['cGluLWE=', 'cGluLWI=']; // two base64 pins

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: [],
      recipientPins: pins,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-pin-preserve',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    expect(capturedNode).toBeDefined();
    // Unseal the write-body under the write key and assert the pins survived the
    // clean publish (no CAS-409 union ran — this is the routine happy path).
    const unsealed = await unsealNode(capturedNode!, READ_KEY, WRITE_KEY);
    expect(unsealed.writeBody?.recipientPins).toEqual(pins);
  });

  it('allows an explicit empty [] snapshot for a genuinely unpinned node', async () => {
    const ctx = createMockContext();
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });

    await expect(
      updateFolderMetadataAndPublish({
        children: [],
        readKey: READ_KEY,
        writeKey: WRITE_KEY,
        writeChildren: [],
        recipientPins: [],
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        ipnsName: 'k51-pin-empty-ok',
        sequenceNumber: 1n,
        ctx,
        nodeId: NODE_ID,
        nodeGeneration: 0,
      })
    ).resolves.toBeDefined();
  });
});
