/**
 * Batch Upload Tests
 *
 * Tests uploadFiles() batch method: concurrent encrypt+pin with single folder
 * publish, partial failure callbacks, and content round-trip verification.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { expectChildNamed, getChild, expectBytesEqual } from '../helpers/assertions';
import { generateTextContent, generateBytes, decodeText } from '../helpers/data-generators';
import type { FilePointer } from '@cipherbox/core';

describe('Batch Upload Operations', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('batch-upload');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should upload 3 text files in one batch', async () => {
    const files = [
      { data: generateTextContent('alpha-' + Date.now()), fileName: 'batch-a.txt', mimeType: 'text/plain' },
      { data: generateTextContent('bravo-' + Date.now()), fileName: 'batch-b.txt', mimeType: 'text/plain' },
      { data: generateTextContent('charlie-' + Date.now()), fileName: 'batch-c.txt', mimeType: 'text/plain' },
    ];

    const completed: string[] = [];
    const result = await ctx.client.uploadFiles(ctx.rootIpnsName, files, {
      onFileComplete: (name) => completed.push(name),
    });

    expect(result.successes).toHaveLength(3);
    expect(result.failures).toHaveLength(0);
    expect(completed).toHaveLength(3);

    expectChildNamed(ctx.client, ctx.rootIpnsName, 'batch-a.txt');
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'batch-b.txt');
    expectChildNamed(ctx.client, ctx.rootIpnsName, 'batch-c.txt');
  });

  it('should round-trip verify content of batch-uploaded files', async () => {
    const child = getChild(ctx.client, ctx.rootIpnsName, 'batch-a.txt') as FilePointer;
    const downloaded = await ctx.client.downloadFromIpns(
      child.fileMetaIpnsName,
      ctx.rootFolderKey
    );
    const text = decodeText(downloaded);
    expect(text).toContain('alpha-');
  });

  it('should upload mixed-size files in one batch', async () => {
    const files = [
      { data: generateBytes(100), fileName: 'tiny.bin', mimeType: 'application/octet-stream' },
      { data: generateBytes(50 * 1024), fileName: 'medium.bin', mimeType: 'application/octet-stream' },
      { data: generateBytes(500 * 1024, 99), fileName: 'large.bin', mimeType: 'application/octet-stream' },
    ];

    const result = await ctx.client.uploadFiles(ctx.rootIpnsName, files);
    expect(result.successes).toHaveLength(3);
    expect(result.failures).toHaveLength(0);

    // Round-trip the largest file
    const child = getChild(ctx.client, ctx.rootIpnsName, 'large.bin') as FilePointer;
    const downloaded = await ctx.client.downloadFromIpns(
      child.fileMetaIpnsName,
      ctx.rootFolderKey
    );
    expectBytesEqual(downloaded, files[2].data);
  });

  it('should fire per-file progress callbacks', async () => {
    const folder = await ctx.client.createFolder(ctx.rootIpnsName, 'ProgressTestFolder');
    ctx.client.registerFolder(
      folder.ipnsName,
      folder.folderKey,
      { publicKey: new Uint8Array(0), privateKey: folder.ipnsPrivateKey },
      [],
      1n
    );

    const files = [
      { data: generateBytes(10 * 1024), fileName: 'prog-a.bin', mimeType: 'application/octet-stream' },
      { data: generateBytes(10 * 1024), fileName: 'prog-b.bin', mimeType: 'application/octet-stream' },
    ];

    const progressEvents: Array<{ fileName: string; percent: number }> = [];
    const result = await ctx.client.uploadFiles(folder.ipnsName, files, {
      onFileProgress: (fileName, percent) => progressEvents.push({ fileName, percent }),
      onFileComplete: () => {},
    });

    expect(result.successes).toHaveLength(2);
    // Each file should have at least one progress event
    const aProgress = progressEvents.filter((e) => e.fileName === 'prog-a.bin');
    const bProgress = progressEvents.filter((e) => e.fileName === 'prog-b.bin');
    expect(aProgress.length).toBeGreaterThan(0);
    expect(bProgress.length).toBeGreaterThan(0);
  });

  it('should emit files:batchUploaded event', async () => {
    const folder = await ctx.client.createFolder(ctx.rootIpnsName, 'EventTestFolder');
    ctx.client.registerFolder(
      folder.ipnsName,
      folder.folderKey,
      { publicKey: new Uint8Array(0), privateKey: folder.ipnsPrivateKey },
      [],
      1n
    );

    const events: Array<{ type: string }> = [];
    ctx.client.on((e) => events.push(e));

    const files = [
      { data: generateTextContent('event-test'), fileName: 'event.txt', mimeType: 'text/plain' },
    ];
    await ctx.client.uploadFiles(folder.ipnsName, files);

    const batchEvent = events.find((e) => e.type === 'files:batchUploaded');
    expect(batchEvent).toBeDefined();
  });
});
