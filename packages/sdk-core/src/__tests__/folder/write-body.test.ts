/**
 * TDD tests for the owned write-body model (D-03, Phase 68.1 Plan 01).
 *
 * RED phase: written before implementation.
 * - `updateFolderMetadataAndPublish` gains `writeKey?` / `writeChildren?` params and
 *   seals a real write-body (ipnsPrivateKey + writeChildren) when writeKey is supplied.
 * - `publishEmptyRootNode` (packages/sdk-core/src/vault/index.ts) publishes a new
 *   user's empty root Node at IPNS sequence 1n with a write-body carrying the root
 *   ipnsPrivateKey.
 *
 * Mock boundary: only network I/O (ipfs + ipns) is mocked; the @cipherbox/core codec
 * (sealNode/unsealNode) runs for real so round-trip assertions reflect the actual
 * sealed envelope, matching the pattern in registration.test.ts.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { updateFolderMetadataAndPublish } from '../../folder/registration';
import { publishEmptyRootNode } from '../../vault';
import { unsealNode } from '@cipherbox/core';
import type { PublishedNode, WriteChildRef } from '@cipherbox/core';
import { generateEd25519Keypair } from '@cipherbox/crypto';
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

describe('owned write-body model (D-03)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => ({
      cid: 'QmTestCid',
      size: data.length,
      recorded: true,
    }));
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 2n });
  });

  describe('updateFolderMetadataAndPublish write-body seal', () => {
    it('seals a real write-body carrying the supplied ipnsPrivateKey and writeChildren (order-stable) when writeKey is supplied', async () => {
      const ctx = createMockContext();
      const writeChildren: WriteChildRef[] = [
        { childId: 'child-a', writeKeySealed: 'seal-a' },
        { childId: 'child-b', writeKeySealed: 'seal-b' },
      ];
      let capturedBytes: Uint8Array | null = null;
      mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
        capturedBytes = data;
        return { cid: 'QmWriteBody', size: data.length, recorded: true };
      });

      await updateFolderMetadataAndPublish({
        children: [],
        readKey: READ_KEY,
        writeKey: WRITE_KEY,
        writeChildren,
        recipientPins: [],
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        ipnsName: 'k51-write-body',
        sequenceNumber: 1n,
        ctx,
        nodeId: NODE_ID,
        nodeGeneration: 0,
      });

      expect(capturedBytes).not.toBeNull();
      const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;
      expect(publishedNode.writeSealed).toBeDefined();

      // Round-trip under BOTH readKey and writeKey — assert write-body contents.
      const unsealed = await unsealNode(publishedNode, READ_KEY, WRITE_KEY);
      expect(unsealed.writeBody).toBeDefined();
      expect(unsealed.writeBody!.ipnsPrivateKey).toEqual(IPNS_PRIVATE_KEY);
      expect(unsealed.writeBody!.writeChildren).toEqual(writeChildren);
    });

    it('omits the write-body when writeKey is not supplied (legacy compatibility)', async () => {
      const ctx = createMockContext();
      let capturedBytes: Uint8Array | null = null;
      mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
        capturedBytes = data;
        return { cid: 'QmNoWriteBody', size: data.length, recorded: true };
      });

      await updateFolderMetadataAndPublish({
        children: [],
        readKey: READ_KEY,
        ipnsPrivateKey: IPNS_PRIVATE_KEY,
        ipnsName: 'k51-no-write-body',
        sequenceNumber: 1n,
        ctx,
        nodeId: NODE_ID,
        nodeGeneration: 0,
      });

      expect(capturedBytes).not.toBeNull();
      const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;
      expect(publishedNode.writeSealed).toBeUndefined();
    });
  });

  describe('publishEmptyRootNode', () => {
    it('publishes an empty kind:root Node at seq 1n with a write-body carrying the root ipnsPrivateKey', async () => {
      const ctx = createMockContext();
      const rootIpnsKeypair = await generateEd25519Keypair();
      const rootReadKey = new Uint8Array(32).fill(0xef);
      const rootWriteKey = new Uint8Array(32).fill(0x12);
      let capturedBytes: Uint8Array | null = null;
      mockFns.addToIpfs.mockImplementation(async (_ctx: unknown, data: Uint8Array) => {
        capturedBytes = data;
        return { cid: 'QmRoot', size: data.length, recorded: true };
      });

      const result = await publishEmptyRootNode({
        rootIpnsKeypair,
        rootReadKey,
        rootWriteKey,
        ctx,
      });

      expect(result.sequenceNumber).toBe(1n);
      expect(typeof result.ipnsName).toBe('string');
      expect(result.ipnsName.length).toBeGreaterThan(0);
      expect(typeof result.nodeId).toBe('string');

      // First publish MUST embed sequenceNumber 1n (strict gate).
      expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledWith(
        expect.objectContaining({ sequenceNumber: 1n })
      );

      expect(capturedBytes).not.toBeNull();
      const publishedNode = JSON.parse(new TextDecoder().decode(capturedBytes!)) as PublishedNode;
      expect(publishedNode.kind).toBe('root');
      expect(publishedNode.id).toBe(result.nodeId);

      const unsealed = await unsealNode(publishedNode, rootReadKey, rootWriteKey);
      expect(unsealed.kind).toBe('root');
      expect(unsealed.children).toEqual([]);
      expect(unsealed.writeBody).toBeDefined();
      expect(unsealed.writeBody!.ipnsPrivateKey).toEqual(rootIpnsKeypair.privateKey);
      expect(unsealed.writeBody!.writeChildren).toEqual([]);
    });
  });
});
