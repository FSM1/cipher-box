/**
 * Folder CRUD Tests
 *
 * Tests create, nested create, rename, move, delete operations
 * through the CipherBoxClient API. Includes a 20-folder stress test.
 *
 * v3 contract notes (NODE-03):
 *  - Read-plane children are SealedChildRefs keyed by ipnsName (no `id` field);
 *    renameItem/moveItem/deleteItem take the child's ipnsName as the handle.
 *  - createFolder registers the new subfolder in the client's folderTree with
 *    its real writeKey — callers must NOT re-registerFolder it (that would
 *    clobber the write-capable entry with a zero writeKey).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { expectChildNamed, expectNoChildNamed, getChild, getChildren } from '../helpers/assertions';

describe('Folder CRUD', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('folder-crud');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should create a folder in root', async () => {
    const result = await ctx.client.createFolder(ctx.rootIpnsName, 'Documents');

    expect(result.id).toBeTruthy();
    expect(result.ipnsName).toMatch(/^(k51|bafz)/);
    expect(result.folderKey.length).toBe(32);
    expect(result.ipnsPrivateKey.length).toBeGreaterThan(0);

    expectChildNamed(ctx.client, ctx.rootIpnsName, 'Documents');
  });

  it('should create a subfolder inside a newly created folder', async () => {
    const subResult = await ctx.client.createFolder(ctx.rootIpnsName, 'Projects');
    expect(subResult.id).toBeTruthy();

    // createFolder already registered 'Projects' in the folderTree with its
    // real writeKey — nested creation works without any manual registerFolder.
    const nested = await ctx.client.createFolder(subResult.ipnsName, 'SubProject');
    expect(nested.id).toBeTruthy();
    expectChildNamed(ctx.client, subResult.ipnsName, 'SubProject');
  });

  it('should reject duplicate folder names', async () => {
    await expect(ctx.client.createFolder(ctx.rootIpnsName, 'Documents')).rejects.toThrow(
      'An item with this name already exists'
    );
  });

  it('should rename a folder', async () => {
    const child = getChild(ctx.client, ctx.rootIpnsName, 'Documents');
    await ctx.client.renameItem(ctx.rootIpnsName, child.ipnsName, 'Docs');

    expectChildNamed(ctx.client, ctx.rootIpnsName, 'Docs');
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Documents');
  });

  it('should move a folder between parents', async () => {
    // Create a destination folder (registered write-capable by createFolder)
    const dest = await ctx.client.createFolder(ctx.rootIpnsName, 'Archive');

    // Move 'Docs' into 'Archive' — child handle is the ipnsName (NODE-03)
    const docs = getChild(ctx.client, ctx.rootIpnsName, 'Docs');
    await ctx.client.moveItem(ctx.rootIpnsName, dest.ipnsName, docs.ipnsName);

    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Docs');
    expectChildNamed(ctx.client, dest.ipnsName, 'Docs');
  });

  it('should delete a folder', async () => {
    const result = await ctx.client.deleteItem(
      ctx.rootIpnsName,
      getChild(ctx.client, ctx.rootIpnsName, 'Archive').ipnsName
    );
    expect(result.removedItem.ipnsName).toBeTruthy();
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Archive');
  });

  it('should handle deleting the last folder', async () => {
    // Delete remaining 'Projects' folder
    const projects = getChild(ctx.client, ctx.rootIpnsName, 'Projects');
    await ctx.client.deleteItem(ctx.rootIpnsName, projects.ipnsName);
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Projects');
  });

  it('should throw when operating on unloaded folder', async () => {
    await expect(ctx.client.createFolder('k51nonexistent', 'Test')).rejects.toThrow(
      'Parent folder not loaded'
    );
  });

  it('should throw when deleting non-existent child', async () => {
    await expect(ctx.client.deleteItem(ctx.rootIpnsName, 'non-existent-id')).rejects.toThrow();
  });

  it('should handle 20-folder stress test', { timeout: 600_000 }, async () => {
    const baseCount = getChildren(ctx.client, ctx.rootIpnsName).length;
    const folderIpnsNames: string[] = [];

    // Create 20 folders
    for (let i = 0; i < 20; i++) {
      const result = await ctx.client.createFolder(ctx.rootIpnsName, `Stress-${i}`);
      expect(result.id).toBeTruthy();
      folderIpnsNames.push(result.ipnsName);
    }

    expect(getChildren(ctx.client, ctx.rootIpnsName).length).toBe(baseCount + 20);

    // Delete all 20
    for (const ipnsName of folderIpnsNames) {
      await ctx.client.deleteItem(ctx.rootIpnsName, ipnsName);
    }

    expect(getChildren(ctx.client, ctx.rootIpnsName).length).toBe(baseCount);
  });
});
