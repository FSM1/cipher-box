/**
 * Rapid Sequential Operations Tests
 *
 * Tests back-to-back SDK operations on a single client to verify
 * state consistency under rapid serial mutations:
 * - Rapid folder creation (10 back-to-back)
 * - Interleaved file uploads
 * - Upload followed by immediate rename
 * - Create-folder then upload-into-folder sequence
 * - Rapid create-and-move cycle
 *
 * Note: True concurrent (parallel) operations on the same folder are
 * intentionally not supported by the SDK — mutations are serialized
 * via IPNS sequence numbers. These tests verify rapid serial behavior.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { expectChildNamed, getChild, getChildren } from '../helpers/assertions';
import { generateBytes, generateTextContent } from '../helpers/data-generators';

describe('Concurrent Operations', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('concurrent-ops');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should handle rapid sequential folder creation', async () => {
    // Create 10 folders as fast as possible (serial, but back-to-back)
    const results = [];
    for (let i = 0; i < 10; i++) {
      results.push(await ctx.client.createFolder(ctx.rootIpnsName, `Rapid-${i}`));
    }

    // All should succeed with unique IDs and IPNS names
    const ids = new Set(results.map((r) => r.id));
    const ipnsNames = new Set(results.map((r) => r.ipnsName));
    expect(ids.size).toBe(10);
    expect(ipnsNames.size).toBe(10);

    // Verify all present in folder tree
    for (let i = 0; i < 10; i++) {
      expectChildNamed(ctx.client, ctx.rootIpnsName, `Rapid-${i}`);
    }

    // Cleanup
    for (const r of results) {
      await ctx.client.deleteItem(ctx.rootIpnsName, r.id);
    }
  });

  it('should handle interleaved file uploads', async () => {
    // Upload 5 files back-to-back (serial, but rapid)
    const fileNames = Array.from({ length: 5 }, (_, i) => `concurrent-${i}.bin`);
    const contents = fileNames.map((_, i) => generateBytes(1024, i));

    for (let i = 0; i < 5; i++) {
      await ctx.client.uploadFile(
        ctx.rootIpnsName,
        contents[i],
        fileNames[i],
        'application/octet-stream'
      );
    }

    // Verify all are present
    for (const name of fileNames) {
      expectChildNamed(ctx.client, ctx.rootIpnsName, name);
    }

    // Cleanup
    for (const name of fileNames) {
      const child = getChild(ctx.client, ctx.rootIpnsName, name);
      await ctx.client.deleteItem(ctx.rootIpnsName, child.id);
    }
  });

  it('should handle upload followed by immediate rename', async () => {
    const content = generateTextContent('rename-after-upload');
    await ctx.client.uploadFile(ctx.rootIpnsName, content, 'before-rename.txt', 'text/plain');

    const child = getChild(ctx.client, ctx.rootIpnsName, 'before-rename.txt');
    await ctx.client.renameItem(ctx.rootIpnsName, child.id, 'after-rename.txt');

    expectChildNamed(ctx.client, ctx.rootIpnsName, 'after-rename.txt');

    // Cleanup
    const renamed = getChild(ctx.client, ctx.rootIpnsName, 'after-rename.txt');
    await ctx.client.deleteItem(ctx.rootIpnsName, renamed.id);
  });

  it('should handle create-folder then upload-into-folder sequence', async () => {
    const folder = await ctx.client.createFolder(ctx.rootIpnsName, 'SeqFolder');

    ctx.client.registerFolder(
      folder.ipnsName,
      folder.folderKey,
      { publicKey: new Uint8Array(0), privateKey: folder.ipnsPrivateKey },
      [],
      1n
    );

    // Upload into the just-created folder
    const content = generateTextContent('sequential file');
    await ctx.client.uploadFile(folder.ipnsName, content, 'seq-file.txt', 'text/plain');

    expectChildNamed(ctx.client, folder.ipnsName, 'seq-file.txt');

    // Cleanup
    await ctx.client.deleteItem(ctx.rootIpnsName, folder.id);
  });

  it('should handle rapid create-and-move cycle', async () => {
    // Create source and dest folders
    const src = await ctx.client.createFolder(ctx.rootIpnsName, 'MoveSource');
    const dst = await ctx.client.createFolder(ctx.rootIpnsName, 'MoveDest');

    ctx.client.registerFolder(
      src.ipnsName,
      src.folderKey,
      { publicKey: new Uint8Array(0), privateKey: src.ipnsPrivateKey },
      [],
      1n
    );
    ctx.client.registerFolder(
      dst.ipnsName,
      dst.folderKey,
      { publicKey: new Uint8Array(0), privateKey: dst.ipnsPrivateKey },
      [],
      1n
    );

    // Upload files to source
    for (let i = 0; i < 3; i++) {
      await ctx.client.uploadFile(
        src.ipnsName,
        generateTextContent(`move-file-${i}`),
        `move-${i}.txt`,
        'text/plain'
      );
    }

    // Move each file one at a time
    for (let i = 0; i < 3; i++) {
      const child = getChild(ctx.client, src.ipnsName, `move-${i}.txt`);
      await ctx.client.moveItem(src.ipnsName, dst.ipnsName, child.id);
    }

    // Verify source is empty, dest has all 3
    expect(getChildren(ctx.client, src.ipnsName).length).toBe(0);
    expect(getChildren(ctx.client, dst.ipnsName).length).toBe(3);

    // Cleanup
    await ctx.client.deleteItem(ctx.rootIpnsName, src.id);
    await ctx.client.deleteItem(ctx.rootIpnsName, dst.id);
  });
});
