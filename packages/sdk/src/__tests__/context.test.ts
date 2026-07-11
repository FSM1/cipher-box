import { describe, it, expect, vi } from 'vitest';
import { buildSharedWriteContext, type SharedWriteContextParams } from '../share/context';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { SealedChildRef, PublishedNode } from '@cipherbox/core';

const makeSdkContext = (): SdkContext => ({
  apiUrl: 'http://localhost:3000',
  getAccessToken: async () => 'test-token',
});

const makeFolderEntry = (id: string, name: string): SealedChildRef => ({
  name,
  ipnsName: `k51-${id}`,
  generation: 0,
  versionFloor: 0n,
  readKeySealed: 'encrypted-folder-key',
});

const stubPublishedNode: PublishedNode = {
  schema: 'node/v3',
  kind: 'folder',
  id: 'stub-node-id',
  generation: 0,
  aeadVersion: 1,
  readSealed: 'dGVzdA==',
};

const makeParams = (overrides?: Partial<SharedWriteContextParams>): SharedWriteContextParams => ({
  ctx: makeSdkContext(),
  readKey: new Uint8Array(32).fill(1),
  writeKey: new Uint8Array(32).fill(2),
  publishedNode: stubPublishedNode,
  ipnsName: 'k51-test-folder',
  sequenceNumber: 42n,
  children: [makeFolderEntry('child-1', 'Documents')],
  ownerPublicKey: new Uint8Array(33).fill(3),
  recipientPublicKey: new Uint8Array(33).fill(4),
  shareId: 'share-abc-123',
  publishNodeFn: vi.fn().mockResolvedValue({ tombstoned: false, newSequenceNumber: 2n }),
  addToIpfsFn: vi.fn().mockResolvedValue({ cid: 'QmMock' }),
  ...overrides,
});

describe('buildSharedWriteContext', () => {
  it('maps all params to SharedWriteContext fields', () => {
    const params = makeParams();
    const ctx = buildSharedWriteContext(params);

    expect(ctx.ctx).toBe(params.ctx);
    expect(ctx.readKey).toBe(params.readKey);
    expect(ctx.writeKey).toBe(params.writeKey);
    expect(ctx.publishedNode).toBe(params.publishedNode);
    expect(ctx.ipnsName).toBe(params.ipnsName);
    expect(ctx.sequenceNumber).toBe(42n);
    expect(ctx.children).toBe(params.children);
    expect(ctx.ownerPublicKey).toBe(params.ownerPublicKey);
    expect(ctx.recipientPublicKey).toBe(params.recipientPublicKey);
    expect(ctx.shareId).toBe('share-abc-123');
    expect(ctx.publishNodeFn).toBe(params.publishNodeFn);
    expect(ctx.addToIpfsFn).toBe(params.addToIpfsFn);
  });

  it('preserves reference identity (no deep clone)', () => {
    const params = makeParams();
    const ctx = buildSharedWriteContext(params);

    // Should be the same references, not copies
    expect(ctx.readKey).toBe(params.readKey);
    expect(ctx.writeKey).toBe(params.writeKey);
    expect(ctx.publishedNode).toBe(params.publishedNode);
    expect(ctx.children).toBe(params.children);
  });

  it('handles empty children array', () => {
    const params = makeParams({ children: [] });
    const ctx = buildSharedWriteContext(params);
    expect(ctx.children).toEqual([]);
  });

  it('handles zero sequence number', () => {
    const params = makeParams({ sequenceNumber: 0n });
    const ctx = buildSharedWriteContext(params);
    expect(ctx.sequenceNumber).toBe(0n);
  });

  it('handles large sequence numbers', () => {
    const bigNum = 9007199254740993n; // > Number.MAX_SAFE_INTEGER
    const params = makeParams({ sequenceNumber: bigNum });
    const ctx = buildSharedWriteContext(params);
    expect(ctx.sequenceNumber).toBe(bigNum);
  });

  it('preserves publishNodeFn and addToIpfsFn as callable', async () => {
    const publishFn = vi.fn().mockResolvedValue({ tombstoned: false, newSequenceNumber: 5n });
    const ipfsFn = vi.fn().mockResolvedValue({ cid: 'QmTest' });
    const params = makeParams({ publishNodeFn: publishFn, addToIpfsFn: ipfsFn });
    const ctx = buildSharedWriteContext(params);

    const publishResult = await ctx.publishNodeFn({
      published: stubPublishedNode,
      ipnsName: 'k51-test',
      ipnsPrivateKey: new Uint8Array(32),
      sequenceNumber: 4n,
    });
    expect(publishResult).toEqual({ tombstoned: false, newSequenceNumber: 5n });

    const ipfsResult = await ctx.addToIpfsFn(new Uint8Array([1, 2, 3]));
    expect(ipfsResult).toEqual({ cid: 'QmTest' });
  });
});
