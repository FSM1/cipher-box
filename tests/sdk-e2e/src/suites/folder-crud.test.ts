/**
 * Folder CRUD Tests
 *
 * Tests create, nested create, rename, move, delete operations
 * through the CipherBoxClient API. Includes a 20-folder stress test.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import {
  expectChildNamed,
  expectNoChildNamed,
  expectChildCount,
  getChild,
} from '../helpers/assertions';

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
    expect(result.ipnsName).toMatch(/^k51|^bafz/);
    expect(result.folderKey.length).toBe(32);
    expect(result.ipnsPrivateKey.length).toBeGreaterThan(0);

    expectChildNamed(ctx.client, ctx.rootIpnsName, 'Documents');
  });

  it('should create a nested folder', async () => {
    const parent = getChild(ctx.client, ctx.rootIpnsName, 'Documents');

    // Register the parent folder so we can create children
    ctx.client.registerFolder(
      parent.ipnsName,
      parent.folderKey ?? new Uint8Array(32), // folderKey might not be on the child
      { publicKey: new Uint8Array(0), privateKey: new Uint8Array(0) },
      [],
      0n
    );

    // For nested creation we need the actual folder key.
    // The createFolder result contains the actual key.
    // Re-create with proper keys from the original createFolder return.
    // Actually, let's create a fresh subfolder in root and then nest inside it.
    const subResult = await ctx.client.createFolder(ctx.rootIpnsName, 'Projects');
    expect(subResult.id).toBeTruthy();

    // Register the subfolder with its real keys
    ctx.client.registerFolder(
      subResult.ipnsName,
      subResult.folderKey,
      {
        publicKey: new Uint8Array(0), // We don't have the public key from createFolder
        privateKey: subResult.ipnsPrivateKey,
      },
      [],
      1n // After the empty metadata publish
    );

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
    await ctx.client.renameItem(ctx.rootIpnsName, child.id, 'Docs');

    expectChildNamed(ctx.client, ctx.rootIpnsName, 'Docs');
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Documents');
  });

  it('should move a folder between parents', async () => {
    // Create a destination folder
    const dest = await ctx.client.createFolder(ctx.rootIpnsName, 'Archive');
    ctx.client.registerFolder(
      dest.ipnsName,
      dest.folderKey,
      { publicKey: new Uint8Array(0), privateKey: dest.ipnsPrivateKey },
      [],
      1n
    );

    // Move 'Docs' into 'Archive'
    const docs = getChild(ctx.client, ctx.rootIpnsName, 'Docs');
    await ctx.client.moveItem(ctx.rootIpnsName, dest.ipnsName, docs.id);

    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Docs');
    expectChildNamed(ctx.client, dest.ipnsName, 'Docs');
  });

  it('should delete a folder', async () => {
    const result = await ctx.client.deleteItem(
      ctx.rootIpnsName,
      getChild(ctx.client, ctx.rootIpnsName, 'Archive').id
    );
    expect(result.removedItem.id).toBeTruthy();
    expectNoChildNamed(ctx.client, ctx.rootIpnsName, 'Archive');
  });

  it('should handle deleting the last folder', async () => {
    // Delete remaining 'Projects' folder
    const projects = getChild(ctx.client, ctx.rootIpnsName, 'Projects');
    await ctx.client.deleteItem(ctx.rootIpnsName, projects.id);
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

  it('should handle 20-folder stress test', async () => {
    const folderIds: string[] = [];

    // Create 20 folders
    for (let i = 0; i < 20; i++) {
      const result = await ctx.client.createFolder(ctx.rootIpnsName, `Stress-${i}`);
      expect(result.id).toBeTruthy();
      folderIds.push(result.id);
    }

    expectChildCount(ctx.client, ctx.rootIpnsName, 20);

    // Delete all 20
    for (const id of folderIds) {
      await ctx.client.deleteItem(ctx.rootIpnsName, id);
    }

    expectChildCount(ctx.client, ctx.rootIpnsName, 0);
  });
});
