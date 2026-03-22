/**
 * File Operations Tests
 *
 * Tests file upload (various sizes), download, and content round-trip
 * verification through the CipherBoxClient API.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { expectChildNamed, getChild, expectBytesEqual } from '../helpers/assertions';
import {
  generateBytes,
  generateTextContent,
  decodeText,
  FILE_SIZES,
} from '../helpers/data-generators';

describe('File Operations', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('file-ops');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should upload a small text file (100 bytes)', async () => {
    const content = generateTextContent('Hello SDK E2E! ' + Date.now());
    const result = await ctx.client.uploadFile(
      ctx.rootIpnsName,
      content,
      'hello.txt',
      'text/plain'
    );

    expect(result.cid).toBeTruthy();
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'hello.txt');
  });

  it('should upload a 50KB binary file', async () => {
    const content = generateBytes(FILE_SIZES.medium, 100);
    const result = await ctx.client.uploadFile(
      ctx.rootIpnsName,
      content,
      'medium.bin',
      'application/octet-stream'
    );

    expect(result.cid).toBeTruthy();
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'medium.bin');
  });

  it('should upload a 500KB binary file', async () => {
    const content = generateBytes(FILE_SIZES.large, 200);
    const result = await ctx.client.uploadFile(
      ctx.rootIpnsName,
      content,
      'large.bin',
      'application/octet-stream'
    );

    expect(result.cid).toBeTruthy();
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'large.bin');
  });

  it('should download a text file and verify content', async () => {
    const originalText = 'Round-trip verification content ' + Date.now();
    const originalBytes = generateTextContent(originalText);

    await ctx.client.uploadFile(ctx.rootIpnsName, originalBytes, 'roundtrip.txt', 'text/plain');

    const fileChild = getChild(ctx.client, ctx.rootIpnsName, 'roundtrip.txt');
    expect(fileChild.fileMetaIpnsName).toBeTruthy();

    const downloaded = await ctx.client.downloadFromIpns(
      fileChild.fileMetaIpnsName,
      ctx.rootFolderKey
    );

    const downloadedText = decodeText(downloaded);
    expect(downloadedText).toBe(originalText);
  });

  it('should round-trip a binary file with byte-for-byte verification', async () => {
    const original = generateBytes(FILE_SIZES.small, 42);

    await ctx.client.uploadFile(
      ctx.rootIpnsName,
      original,
      'binary-roundtrip.bin',
      'application/octet-stream'
    );

    const fileChild = getChild(ctx.client, ctx.rootIpnsName, 'binary-roundtrip.bin');
    const downloaded = await ctx.client.downloadFromIpns(
      fileChild.fileMetaIpnsName,
      ctx.rootFolderKey
    );

    expectBytesEqual(downloaded, original);
  });

  it('should reject duplicate file names in same folder', async () => {
    await expect(
      ctx.client.uploadFile(
        ctx.rootIpnsName,
        generateTextContent('duplicate'),
        'hello.txt',
        'text/plain'
      )
    ).rejects.toThrow('An item with this name already exists');
  });

  it('should upload files to a subfolder', async () => {
    const folder = await ctx.client.createFolder(ctx.rootIpnsName, 'FileTestFolder');
    ctx.client.registerFolder(
      folder.ipnsName,
      folder.folderKey,
      { publicKey: new Uint8Array(0), privateKey: folder.ipnsPrivateKey },
      [],
      1n
    );

    const content = generateTextContent('subfolder file');
    const result = await ctx.client.uploadFile(
      folder.ipnsName,
      content,
      'sub-file.txt',
      'text/plain'
    );

    expect(result.cid).toBeTruthy();
    expectChildNamed(ctx.client, folder.ipnsName, 'sub-file.txt');
  });

  it('should rename a file', async () => {
    const child = getChild(ctx.client, ctx.rootIpnsName, 'hello.txt');
    await ctx.client.renameItem(ctx.rootIpnsName, child.id, 'renamed-hello.txt');
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'renamed-hello.txt');
  });

  it('should delete a file', async () => {
    const child = getChild(ctx.client, ctx.rootIpnsName, 'renamed-hello.txt');
    const result = await ctx.client.deleteItem(ctx.rootIpnsName, child.id);
    expect(result.removedItem.id).toBe(child.id);
  });
});
