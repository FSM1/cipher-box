/**
 * TDD tests for the recipient-pubkey pin machinery (Phase 80 Plan 04, D-03a/c/e).
 *
 * RED phase: written before implementation.
 *
 * Covers:
 *  - Pure helpers `assertRecipientPinned` / `appendRecipientPin` / `extractRecipientPins`
 *    (share/recipient-pins.ts), including the D-03e empty/absent hard-fail and
 *    cross-encoding (raw-bytes / hex / base64) normalization.
 *  - `updateFolderMetadataAndPublish` threading `recipientPins` into the sealed
 *    write-body (preservation across a writeChildren-only update) and unioning
 *    local ∪ remote pins across a CAS-409 merge (T-80-11 durability).
 *  - A write→read round-trip at the sdk-core seal boundary: seal a node with a
 *    pin, unseal it, and read the pin back (the substantive round-trip the thin
 *    `client.addRecipientPubkeyPin` / `client.getRecipientPubkeyPins` wrappers
 *    delegate to — the wrappers themselves are covered by `@cipherbox/sdk`
 *    typecheck, since sdk-core cannot import sdk).
 *
 * Mock boundary: only network I/O (ipfs + ipns) is mocked; the @cipherbox/core
 * codec (sealNode/unsealNode) runs for real so round-trip assertions reflect the
 * actual sealed envelope, matching write-body.test.ts / registration.test.ts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  assertRecipientPinned,
  appendRecipientPin,
  extractRecipientPins,
} from '../../share/recipient-pins';
import { updateFolderMetadataAndPublish } from '../../folder/registration';
import { sealNode, unsealNode } from '@cipherbox/core';
import type { NodeWriteBody, PublishedNode, WriteChildRef } from '@cipherbox/core';
import { bytesToBase64, base64ToBytes, bytesToHex } from '@cipherbox/crypto';
import { createMockContext } from '../helpers';

// ---------------------------------------------------------------------------
// Module mocks — only I/O layers; @cipherbox/core runs real
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
}));

vi.mock('../../ipfs', () => ({
  addToIpfs: mockFns.addToIpfs,
  fetchFromIpfs: mockFns.fetchFromIpfs,
}));

vi.mock('../../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
}));

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NODE_ID = '550e8400-e29b-41d4-a716-446655440000';
const READ_KEY = new Uint8Array(32).fill(0xab);
const WRITE_KEY = new Uint8Array(32).fill(0xcd);
const IPNS_PRIVATE_KEY = new Uint8Array(64).fill(0x01);

// Two distinct 65-byte uncompressed-secp256k1-shaped recipient pubkeys.
const RECIPIENT_A = ((): Uint8Array => {
  const k = new Uint8Array(65);
  k[0] = 0x04;
  for (let i = 1; i < 65; i++) k[i] = (i * 7) & 0xff;
  return k;
})();
const RECIPIENT_B = ((): Uint8Array => {
  const k = new Uint8Array(65);
  k[0] = 0x04;
  for (let i = 1; i < 65; i++) k[i] = (i * 13 + 1) & 0xff;
  return k;
})();

const RECIPIENT_A_B64 = bytesToBase64(RECIPIENT_A);
const RECIPIENT_B_B64 = bytesToBase64(RECIPIENT_B);

/**
 * Build a real sealed remote PublishedNode carrying the given write-body fields,
 * used to simulate a racing writer's published state fetched via decodeRemote
 * during a CAS-409 retry.
 */
async function buildSealedRemote(writeBody: {
  writeChildren: WriteChildRef[];
  recipientPins?: string[];
}): Promise<Uint8Array> {
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
      writeChildren: writeBody.writeChildren,
      ...(writeBody.recipientPins ? { recipientPins: writeBody.recipientPins } : {}),
    },
  };
  const sealed = await sealNode(node, READ_KEY, WRITE_KEY);
  return new TextEncoder().encode(JSON.stringify(sealed));
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

describe('recipient-pins pure helpers', () => {
  describe('extractRecipientPins', () => {
    it('returns the recipientPins list from a decoded write-body', () => {
      const wb: NodeWriteBody = {
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        writeChildren: [],
        recipientPins: [RECIPIENT_A_B64],
      };
      expect(extractRecipientPins(wb)).toEqual([RECIPIENT_A_B64]);
    });

    it('defaults to [] when recipientPins is absent', () => {
      const wb: NodeWriteBody = { ipnsPrivateKey: IPNS_PRIVATE_KEY, writeChildren: [] };
      expect(extractRecipientPins(wb)).toEqual([]);
    });

    it('defaults to [] when the write-body itself is undefined', () => {
      expect(extractRecipientPins(undefined)).toEqual([]);
    });
  });

  describe('appendRecipientPin', () => {
    it('appends a recipient (as raw bytes) to an empty list', () => {
      expect(appendRecipientPin([], RECIPIENT_A)).toEqual([RECIPIENT_A_B64]);
    });

    it('appends a recipient when pins is undefined', () => {
      expect(appendRecipientPin(undefined, RECIPIENT_A)).toEqual([RECIPIENT_A_B64]);
    });

    it('is idempotent — appending the same recipient twice yields a single entry (dedup by raw bytes)', () => {
      const once = appendRecipientPin([], RECIPIENT_A);
      const twice = appendRecipientPin(once, RECIPIENT_A);
      expect(twice).toEqual([RECIPIENT_A_B64]);
    });

    it('dedups across encodings — a hex-encoded recipient equal to an existing base64 pin is not duplicated', () => {
      const hexA = '0x' + bytesToHex(RECIPIENT_A);
      expect(appendRecipientPin([RECIPIENT_A_B64], hexA)).toEqual([RECIPIENT_A_B64]);
    });

    it('keeps existing distinct pins and appends the new one', () => {
      expect(appendRecipientPin([RECIPIENT_A_B64], RECIPIENT_B)).toEqual([
        RECIPIENT_A_B64,
        RECIPIENT_B_B64,
      ]);
    });
  });

  describe('assertRecipientPinned', () => {
    it('throws when the pin list is empty (D-03e no-legacy hard fail)', () => {
      expect(() => assertRecipientPinned(RECIPIENT_A, [])).toThrow();
    });

    it('throws when the pin list is absent/undefined (D-03e)', () => {
      expect(() => assertRecipientPinned(RECIPIENT_A, undefined)).toThrow();
    });

    it('throws when the recipient is not a member of a non-empty list', () => {
      expect(() => assertRecipientPinned(RECIPIENT_B, [RECIPIENT_A_B64])).toThrow();
    });

    it('returns normally (void) when the recipient is pinned (raw-byte match)', () => {
      expect(assertRecipientPinned(RECIPIENT_A, [RECIPIENT_A_B64])).toBeUndefined();
    });

    it('normalizes both sides — a hex-encoded recipient matches its base64 pin', () => {
      const hexA = '0x' + bytesToHex(RECIPIENT_A);
      expect(assertRecipientPinned(hexA, [RECIPIENT_B_B64, RECIPIENT_A_B64])).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// updateFolderMetadataAndPublish — recipientPins preservation + CAS-409 union
// ---------------------------------------------------------------------------

describe('updateFolderMetadataAndPublish — recipientPins durability (T-80-11)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => ({
      cid: 'QmTestCid',
      size: data.length,
      recorded: true,
    }));
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });
  });

  it('seals recipientPins into the write-body and preserves them across a writeChildren-only update (clean publish)', async () => {
    const ctx = createMockContext();
    let capturedBytes: Uint8Array | null = null;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedBytes = data;
      return { cid: 'QmWithPins', size: data.length, recorded: true };
    });

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: [{ childId: 'child-a', writeKeySealed: 'seal-a' }],
      recipientPins: [RECIPIENT_A_B64],
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-pins-clean',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    expect(capturedBytes).not.toBeNull();
    const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;
    const unsealed = await unsealNode(publishedNode, READ_KEY, WRITE_KEY);
    // The writeChildren mutation must NOT drop the recipient pin.
    expect(extractRecipientPins(unsealed.writeBody)).toEqual([RECIPIENT_A_B64]);
    expect(unsealed.writeBody!.writeChildren).toEqual([
      { childId: 'child-a', writeKeySealed: 'seal-a' },
    ]);
  });

  it('unions local ∪ remote recipientPins across a CAS-409 merge (a concurrent writer’s pin is never dropped)', async () => {
    const ctx = createMockContext();
    let lastBytes: Uint8Array | null = null;
    let callCount = 0;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      lastBytes = data;
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
    // Remote (racing writer) already pinned RECIPIENT_B; local is adding RECIPIENT_A.
    mockFns.fetchFromIpfs.mockResolvedValue(
      await buildSealedRemote({ writeChildren: [], recipientPins: [RECIPIENT_B_B64] })
    );

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: [],
      recipientPins: [RECIPIENT_A_B64],
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-pins-cas',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    expect(callCount).toBe(2);
    const publishedNode = JSON.parse(new TextDecoder().decode(lastBytes!)) as PublishedNode;
    const unsealed = await unsealNode(publishedNode, READ_KEY, WRITE_KEY);
    const pins = extractRecipientPins(unsealed.writeBody);
    // Union — both the local and the concurrently-added remote pin survive.
    expect(pins).toHaveLength(2);
    expect(pins).toContain(RECIPIENT_A_B64);
    expect(pins).toContain(RECIPIENT_B_B64);
  });

  it('preserves the remote pin on a CAS-409 even when this update adds no pin of its own', async () => {
    const ctx = createMockContext();
    let lastBytes: Uint8Array | null = null;
    let callCount = 0;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      lastBytes = data;
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
    mockFns.fetchFromIpfs.mockResolvedValue(
      await buildSealedRemote({ writeChildren: [], recipientPins: [RECIPIENT_B_B64] })
    );

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: [],
      // No recipientPins param on this routine update — the remote pin must still survive.
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-pins-cas-noninvasive',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    const publishedNode = JSON.parse(new TextDecoder().decode(lastBytes!)) as PublishedNode;
    const unsealed = await unsealNode(publishedNode, READ_KEY, WRITE_KEY);
    expect(extractRecipientPins(unsealed.writeBody)).toEqual([RECIPIENT_B_B64]);
  });
});

// ---------------------------------------------------------------------------
// Write → read round-trip at the sdk-core seal boundary (client-wrapper proxy)
// ---------------------------------------------------------------------------

describe('recipient-pin write→read round-trip (sdk-core seal boundary)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });
  });

  it('appendRecipientPin → seal via updateFolderMetadataAndPublish → unseal → extract includes the pin', async () => {
    const ctx = createMockContext();
    let capturedBytes: Uint8Array | null = null;
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
      capturedBytes = data;
      return { cid: 'QmRoundTrip', size: data.length, recorded: true };
    });

    // Emulate client.addRecipientPubkeyPin: start from the node's current pins
    // ([] here), append the recipient, then publish the unioned list.
    const nextPins = appendRecipientPin([], RECIPIENT_A);

    await updateFolderMetadataAndPublish({
      children: [],
      readKey: READ_KEY,
      writeKey: WRITE_KEY,
      writeChildren: [],
      recipientPins: nextPins,
      ipnsPrivateKey: IPNS_PRIVATE_KEY,
      ipnsName: 'k51-roundtrip',
      sequenceNumber: 1n,
      ctx,
      nodeId: NODE_ID,
      nodeGeneration: 0,
    });

    const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;
    const unsealed = await unsealNode(publishedNode, READ_KEY, WRITE_KEY);
    // Emulate client.getRecipientPubkeyPins: read the pin list back as raw bytes.
    const pinsB64 = extractRecipientPins(unsealed.writeBody);
    const pinsBytes = pinsB64.map((p) => base64ToBytes(p));
    expect(
      pinsBytes.some(
        (b) => b.length === RECIPIENT_A.length && b.every((v, i) => v === RECIPIENT_A[i])
      )
    ).toBe(true);
  });
});
