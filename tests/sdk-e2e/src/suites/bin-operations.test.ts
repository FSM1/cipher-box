/**
 * Bin Operations Tests
 *
 * Tests the full recycle bin lifecycle: loadBin, deleteToBin, restore,
 * permanentDelete, emptyBin, and IPNS persistence of bin state.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { BinEntry } from '@cipherbox/core';
import { BinNotLoadedError } from '@cipherbox/sdk';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { expectChildNamed, expectNoChildNamed, getChild } from '../helpers/assertions';
import { generateTextContent } from '../helpers/data-generators';

/** Internal bin state shape exposed via `(client as unknown as HasBinState).binState` */
interface HasBinState {
  binState: { entries: BinEntry[]; sequenceNumber: number; ipnsName: string };
}

describe('Bin Operations', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('bin-ops');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should loadBin on fresh account and return empty state', async () => {
    const binState = await ctx.client.loadBin();

    expect(binState).toBeTruthy();
    expect(binState.entries).toEqual([]);
    // loadBin NEVER publishes on a null resolve (publishing an empty record is
    // destructive — it would clobber a real record's CID). On a fresh account
    // it returns an in-memory empty state at sequenceNumber 0; the first
    // addToBin then publishes the real record at 0 + 1 = 1.
    expect(binState.sequenceNumber).toBe(0);
  });

  it('should deleteToBin a file', async () => {
    // Upload a file first
    const content = generateTextContent('bin-test-file ' + Date.now());
    await ctx.client.uploadFile(ctx.rootIpnsName, content, 'bin-file.txt', 'text/plain');
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'bin-file.txt');

    const fileChild = getChild(ctx.client, ctx.rootIpnsName, 'bin-file.txt');

    // Delete to bin — read-plane handle is the child's ipnsName (NODE-03)
    await ctx.client.deleteToBin(ctx.rootIpnsName, fileChild.ipnsName, 'My Vault');

    // Verify removed from folder
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'bin-file.txt');

    // Verify in bin state
    const binState = (ctx.client as unknown as HasBinState).binState;
    expect(binState.entries.length).toBe(1);
    expect(binState.entries[0].name).toBe('bin-file.txt');
    expect(binState.entries[0].itemType).toBe('file');
  });

  it('should persist bin state to IPNS (reload)', async () => {
    const reloaded = await ctx.client.loadBin();
    expect(reloaded.entries.length).toBe(1);
    expect(reloaded.entries[0].name).toBe('bin-file.txt');
  });

  it('should deleteToBin a folder', async () => {
    const folder = await ctx.client.createFolder(ctx.rootIpnsName, 'BinFolder');
    expect(folder.id).toBeTruthy();

    await ctx.client.deleteToBin(ctx.rootIpnsName, folder.ipnsName, 'My Vault');
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'BinFolder');

    const binState = (ctx.client as unknown as HasBinState).binState;
    const folderEntry = binState.entries.find((e: BinEntry) => e.name === 'BinFolder');
    expect(folderEntry).toBeTruthy();
    expect(folderEntry!.itemType).toBe('folder');
  });

  it('should restore a file from bin', async () => {
    const binState = (ctx.client as unknown as HasBinState).binState;
    const fileEntry = binState.entries.find((e: BinEntry) => e.name === 'bin-file.txt');
    expect(fileEntry).toBeTruthy();

    await ctx.client.restoreFromBin(fileEntry!.id, ctx.rootIpnsName);

    // Verify restored to folder
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'bin-file.txt');

    // Verify removed from bin
    const updatedBin = (ctx.client as unknown as HasBinState).binState;
    const stillInBin = updatedBin.entries.find((e: BinEntry) => e.name === 'bin-file.txt');
    expect(stillInBin).toBeUndefined();
  });

  it('should permanently delete a bin entry', async () => {
    const binState = (ctx.client as unknown as HasBinState).binState;
    const folderEntry = binState.entries.find((e: BinEntry) => e.name === 'BinFolder');
    expect(folderEntry).toBeTruthy();

    await ctx.client.permanentDelete(folderEntry!.id);

    const updatedBin = (ctx.client as unknown as HasBinState).binState;
    const stillInBin = updatedBin.entries.find((e: BinEntry) => e.name === 'BinFolder');
    expect(stillInBin).toBeUndefined();
  });

  it('should emptyBin', async () => {
    // Add two items to bin
    const content1 = generateTextContent('empty-test-1');
    const content2 = generateTextContent('empty-test-2');
    await ctx.client.uploadFile(ctx.rootIpnsName, content1, 'empty-1.txt', 'text/plain');
    await ctx.client.uploadFile(ctx.rootIpnsName, content2, 'empty-2.txt', 'text/plain');

    const child1 = getChild(ctx.client, ctx.rootIpnsName, 'empty-1.txt');
    const child2 = getChild(ctx.client, ctx.rootIpnsName, 'empty-2.txt');

    await ctx.client.deleteToBin(ctx.rootIpnsName, child1.ipnsName, 'My Vault');
    await ctx.client.deleteToBin(ctx.rootIpnsName, child2.ipnsName, 'My Vault');

    const binBefore = (ctx.client as unknown as HasBinState).binState;
    expect(binBefore.entries.length).toBeGreaterThanOrEqual(2);

    await ctx.client.emptyBin();

    const binAfter = (ctx.client as unknown as HasBinState).binState;
    expect(binAfter.entries.length).toBe(0);
  });

  it('should self-heal the bin (no BinNotLoadedError) when bin not loaded', async () => {
    // Create a fresh client that hasn't called loadBin(). deleteToBin now
    // lazily loads the bin instead of throwing BinNotLoadedError (bin init is
    // fire-and-forget on login, so a delete soon after login/reload must still
    // soft-delete rather than hard-delete). The bin self-heals to an empty
    // state and the root folder self-bootstraps; the call then fails only
    // because the target child does not exist. v3 resolves the child's IPNS
    // record before the folder lookup, so a nonexistent handle surfaces a
    // resolve error — the self-healing contract under test is that it is NOT a
    // BinNotLoadedError.
    const freshCtx = await createTestContext('bin-not-loaded');
    try {
      const err = await freshCtx.client
        .deleteToBin(freshCtx.rootIpnsName, 'some-id', 'My Vault')
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(BinNotLoadedError);
      expect((err as Error).message).not.toMatch(/bin not loaded/i);
    } finally {
      freshCtx.cleanup();
      await deleteTestAccount(freshCtx);
    }
  });
});
