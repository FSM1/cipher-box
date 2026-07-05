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

describe('IPNS Consistency', () => {
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
    // v3 eagerly publishes the empty root Node at bootstrap, and the first IPNS
    // publish embeds sequence 1 (not 0) — so the root starts at 1n here.
    const seq0 = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName);
    expect(seq0).toBe(1n);

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
    // v3 read-plane children are SealedChildRefs keyed by ipnsName (NODE-03);
    // kind is not carried in the read body, so persistence is witnessed by the
    // child's presence + resolvable ipnsName rather than a `type` field.
    expect(file!.ipnsName).toBeTruthy();
  });

  it('should persist rename through IPNS', async () => {
    const child = getChild(ctx.client, ctx.rootIpnsName, 'SeqTest1');
    await ctx.client.renameItem(ctx.rootIpnsName, child.ipnsName, 'RenamedSeq');

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
    await ctx.client.deleteItem(ctx.rootIpnsName, child.ipnsName);

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
    // v3: the file's own ipnsName IS its per-file IPNS metadata name (NODE-03).
    const fileIpnsName = fileChild.ipnsName;
    expect(fileIpnsName).toBeTruthy();

    // Delete the file — triggers fireAndForgetUnenroll internally
    await ctx.client.deleteItem(ctx.rootIpnsName, fileChild.ipnsName);

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

      await ctx.client.deleteItem(ctx.rootIpnsName, folder.ipnsName);
      const afterDelete = ctx.client.getFolderSequenceNumber(ctx.rootIpnsName)!;
      expect(afterDelete).toBeGreaterThan(prevSeq);
      prevSeq = afterDelete;
    }
  });
});
