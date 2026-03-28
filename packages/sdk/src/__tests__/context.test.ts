import { describe, it, expect, vi } from 'vitest';
import { buildSharedWriteContext, type SharedWriteContextParams } from '../share/context';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { FolderChild, FolderEntry } from '@cipherbox/core';

const makeSdkContext = (): SdkContext => ({
  apiUrl: 'http://localhost:3000',
  getAccessToken: async () => 'test-token',
});

const makeFolderEntry = (id: string, name: string): FolderEntry => ({
  type: 'folder',
  id,
  name,
  ipnsName: `k51-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  folderKeyEncrypted: 'encrypted-folder-key',
  createdAt: 1000,
  modifiedAt: 1000,
});

const makeParams = (overrides?: Partial<SharedWriteContextParams>): SharedWriteContextParams => ({
  ctx: makeSdkContext(),
  folderKey: new Uint8Array(32).fill(1),
  ipnsPrivateKey: new Uint8Array(64).fill(2),
  ipnsName: 'k51-test-folder',
  sequenceNumber: 42n,
  children: [makeFolderEntry('child-1', 'Documents')] as FolderChild[],
  ownerPublicKey: new Uint8Array(33).fill(3),
  recipientPublicKey: new Uint8Array(33).fill(4),
  shareId: 'share-abc-123',
  addShareKeysFn: vi.fn().mockResolvedValue(undefined),
  ...overrides,
});

describe('buildSharedWriteContext', () => {
  it('maps all params to SharedWriteContext fields', () => {
    const params = makeParams();
    const ctx = buildSharedWriteContext(params);

    expect(ctx.ctx).toBe(params.ctx);
    expect(ctx.folderKey).toBe(params.folderKey);
    expect(ctx.ipnsPrivateKey).toBe(params.ipnsPrivateKey);
    expect(ctx.ipnsName).toBe(params.ipnsName);
    expect(ctx.sequenceNumber).toBe(42n);
    expect(ctx.children).toBe(params.children);
    expect(ctx.ownerPublicKey).toBe(params.ownerPublicKey);
    expect(ctx.recipientPublicKey).toBe(params.recipientPublicKey);
    expect(ctx.shareId).toBe('share-abc-123');
    expect(ctx.addShareKeysFn).toBe(params.addShareKeysFn);
  });

  it('preserves reference identity (no deep clone)', () => {
    const params = makeParams();
    const ctx = buildSharedWriteContext(params);

    // Should be the same references, not copies
    expect(ctx.folderKey).toBe(params.folderKey);
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

  it('preserves addShareKeysFn as callable', async () => {
    const addFn = vi.fn().mockResolvedValue(undefined);
    const params = makeParams({ addShareKeysFn: addFn });
    const ctx = buildSharedWriteContext(params);

    await ctx.addShareKeysFn('share-1', [{ keyType: 'file', itemId: 'f1', encryptedKey: 'abc' }]);

    expect(addFn).toHaveBeenCalledWith('share-1', [
      { keyType: 'file', itemId: 'f1', encryptedKey: 'abc' },
    ]);
  });
});
