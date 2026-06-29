/**
 * IPNS Consistency Tests
 *
 * Tests IPNS publish, resolve, sequence number increment,
 * and folder metadata persistence through the IPNS layer.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';
import { getChild } from '../helpers/assertions';
import { generateTextContent } from '../helpers/data-generators';
import { ipnsControllerUnenrollBatch, createAxiosInstance } from '@cipherbox/api-client';
import type { FilePointer } from '@cipherbox/core';

describe.skip('IPNS Consistency [quarantined D-01: SDK runtime stubbed mid-milestone, re-enable at phase 63-65 consumer re-wire]', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('ipns-consistency');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  it('should increment sequence number on each folder mutation', async () => {
    const seq0 = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName);
    expect(seq0).toBe(0n);

    await ctx.client.createFolder(ctx.rootIpnsName, 'SeqTest1');
    const seq1 = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName);
    expect(seq1).toBeGreaterThan(seq0!);

    await ctx.client.createFolder(ctx.rootIpnsName, 'SeqTest2');
    const seq2 = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName);
    expect(seq2).toBeGreaterThan(seq1!);

    await ctx.client.createFolder(ctx.rootIpnsName, 'SeqTest3');
    const seq3 = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName);
    expect(seq3).toBeGreaterThan(seq2!);
  });

  it('should persist folder children through IPNS publish/resolve', async () => {
    // Verify that loadFolder resolves the metadata we just published
    const loaded = await ctx.client.loadFolder(
      ctx.rootIpnsName,
      ctx.rootFolderKey,
      ctx.rootIpnsKeypair
    );

    expect(loaded).toBeTruthy();
    expect(loaded!.children.length).toBe(3); // SeqTest1, SeqTest2, SeqTest3

    const names = loaded!.children.map((c) => c.name).sort();
    expect(names).toEqual(['SeqTest1', 'SeqTest2', 'SeqTest3']);
  });

  it('should persist file upload through IPNS', async () => {
    const content = generateTextContent('IPNS persistence test');
    await ctx.client.uploadFile(ctx.rootIpnsName, content, 'ipns-test.txt', 'text/plain');

    // Reload from IPNS to verify persistence
    const loaded = await ctx.client.loadFolder(
      ctx.rootIpnsName,
      ctx.rootFolderKey,
      ctx.rootIpnsKeypair
    );

    expect(loaded).toBeTruthy();
    const file = loaded!.children.find((c) => c.name === 'ipns-test.txt');
    expect(file).toBeTruthy();
    expect(file!.type).toBe('file');
  });

  it('should persist rename through IPNS', async () => {
    const child = getChild(ctx.client, ctx.rootIpnsName, 'SeqTest1');
    await ctx.client.renameItem(ctx.rootIpnsName, child.id, 'RenamedSeq');

    // Reload and verify
    const loaded = await ctx.client.loadFolder(
      ctx.rootIpnsName,
      ctx.rootFolderKey,
      ctx.rootIpnsKeypair
    );

    expect(loaded).toBeTruthy();
    const renamed = loaded!.children.find((c) => c.name === 'RenamedSeq');
    expect(renamed).toBeTruthy();
    const original = loaded!.children.find((c) => c.name === 'SeqTest1');
    expect(original).toBeUndefined();
  });

  it('should persist delete through IPNS', async () => {
    const before = await ctx.client.loadFolder(
      ctx.rootIpnsName,
      ctx.rootFolderKey,
      ctx.rootIpnsKeypair
    );
    const countBefore = before!.children.length;

    const child = getChild(ctx.client, ctx.rootIpnsName, 'RenamedSeq');
    await ctx.client.deleteItem(ctx.rootIpnsName, child.id);

    const after = await ctx.client.loadFolder(
      ctx.rootIpnsName,
      ctx.rootFolderKey,
      ctx.rootIpnsKeypair
    );
    expect(after!.children.length).toBe(countBefore - 1);
  });

  it('should fire IPNS unenrollment on deleteItem (integration)', async () => {
    // Upload a file — this creates per-file IPNS metadata
    const content = generateTextContent('unenroll-test ' + Date.now());
    await ctx.client.uploadFile(ctx.rootIpnsName, content, 'unenroll-test.txt', 'text/plain');

    const fileChild = getChild(ctx.client, ctx.rootIpnsName, 'unenroll-test.txt');
    const fileIpnsName = (fileChild as FilePointer).fileMetaIpnsName;
    expect(fileIpnsName).toBeTruthy();

    // Delete the file — triggers fireAndForgetUnenroll internally
    await ctx.client.deleteItem(ctx.rootIpnsName, fileChild.id);

    // Wait for the fire-and-forget unenroll to complete
    await new Promise((r) => setTimeout(r, 1000));

    // Create a dedicated axios instance from the test context's access token
    const axiosInstance = createAxiosInstance({
      baseUrl: process.env.API_URL ?? 'http://localhost:3000',
      getAccessToken: async () => ctx.accessToken,
    });

    // Calling unenroll again should return 0 — deleteItem already unenrolled it
    const result = await ipnsControllerUnenrollBatch(
      { ipnsNames: [fileIpnsName] },
      { _axiosInstance: axiosInstance }
    );
    expect(result.totalRequested).toBe(1);
    expect(result.totalUnenrolled).toBe(0);
  });

  it('should maintain sequence number monotonicity after many operations', async () => {
    let prevSeq = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName)!;

    // Rapid folder create-delete cycles
    for (let i = 0; i < 5; i++) {
      const folder = await ctx.client.createFolder(ctx.rootIpnsName, `Rapid-${i}`);
      const newSeq = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName)!;
      expect(newSeq).toBeGreaterThan(prevSeq);
      prevSeq = newSeq;

      await ctx.client.deleteItem(ctx.rootIpnsName, folder.id);
      const afterDelete = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName)!;
      expect(afterDelete).toBeGreaterThan(prevSeq);
      prevSeq = afterDelete;
    }
  });
});
