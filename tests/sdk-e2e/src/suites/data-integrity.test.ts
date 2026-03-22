/**
 * Data Integrity Tests
 *
 * Comprehensive round-trip verification: upload files of varying sizes,
 * download via IPNS, decrypt, and compare byte-for-byte.
 * Tests the full encrypt → IPFS → IPNS → resolve → decrypt pipeline.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { getChild, expectBytesEqual } from '../helpers/assertions';
import { generateBytes, generateTextContent, decodeText } from '../helpers/data-generators';

describe('Data Integrity', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('data-integrity');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  const testSizes = [
    { name: '100B', size: 100 },
    { name: '1KB', size: 1_024 },
    { name: '5KB', size: 5 * 1_024 },
    { name: '10KB', size: 10 * 1_024 },
    { name: '50KB', size: 50 * 1_024 },
    { name: '100KB', size: 100 * 1_024 },
    { name: '250KB', size: 250 * 1_024 },
    { name: '500KB', size: 500 * 1_024 },
  ];

  for (const { name, size } of testSizes) {
    it(`should round-trip ${name} binary file`, async () => {
      const original = generateBytes(size, size % 256);
      const fileName = `integrity-${name}.bin`;

      await ctx.client.uploadFile(ctx.rootIpnsName, original, fileName, 'application/octet-stream');

      const fileChild = getChild(ctx.client, ctx.rootIpnsName, fileName);
      const downloaded = await ctx.client.downloadFromIpns(
        fileChild.fileMetaIpnsName,
        ctx.rootFolderKey
      );

      expectBytesEqual(downloaded, original);
    });
  }

  it('should round-trip text files with unicode content', async () => {
    const unicodeContent =
      'Unicode: \u00e9\u00e0\u00fc\u00f1 \u4f60\u597d \u0410\u043b\u043b\u043e \ud83d\ude80\ud83c\udf1f\ud83c\udf08 \u2603\u2764\u2602 \u00c6\u00d8\u00c5';
    const original = generateTextContent(unicodeContent);

    await ctx.client.uploadFile(ctx.rootIpnsName, original, 'unicode-test.txt', 'text/plain');

    const fileChild = getChild(ctx.client, ctx.rootIpnsName, 'unicode-test.txt');
    const downloaded = await ctx.client.downloadFromIpns(
      fileChild.fileMetaIpnsName,
      ctx.rootFolderKey
    );

    expect(decodeText(downloaded)).toBe(unicodeContent);
  });

  it('should round-trip a file in a nested folder', async () => {
    const folder = await ctx.client.createFolder(ctx.rootIpnsName, 'DeepTest');
    ctx.client.registerFolder(
      folder.ipnsName,
      folder.folderKey,
      { publicKey: new Uint8Array(0), privateKey: folder.ipnsPrivateKey },
      [],
      1n
    );

    const original = generateBytes(10_000, 77);
    await ctx.client.uploadFile(
      folder.ipnsName,
      original,
      'nested-file.bin',
      'application/octet-stream'
    );

    const fileChild = getChild(ctx.client, folder.ipnsName, 'nested-file.bin');
    const downloaded = await ctx.client.downloadFromIpns(
      fileChild.fileMetaIpnsName,
      folder.folderKey
    );

    expectBytesEqual(downloaded, original);
  });
});
