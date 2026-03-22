/**
 * Error Cases Tests
 *
 * Tests negative paths: expired tokens, unloaded folders,
 * BinNotLoadedError, and various edge cases.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { BinNotLoadedError } from '@cipherbox/sdk';
import { createTestContext, deleteTestAccount, type TestContext } from '../fixtures/test-harness';

describe('Error Cases', () => {
  let ctx: TestContext;

  beforeAll(async () => {
    ctx = await createTestContext('error-cases');
  });

  afterAll(async () => {
    if (ctx) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
  });

  describe('Unloaded folder operations', () => {
    const fakeIpnsName = 'k51qzi5uqu5fake000000000000000000000000000000000000';

    it('should throw on createFolder with unloaded parent', async () => {
      await expect(ctx.client.createFolder(fakeIpnsName, 'Test')).rejects.toThrow(
        'Parent folder not loaded'
      );
    });

    it('should throw on renameItem with unloaded folder', async () => {
      await expect(ctx.client.renameItem(fakeIpnsName, 'child-id', 'new-name')).rejects.toThrow(
        'Folder not loaded'
      );
    });

    it('should throw on deleteItem with unloaded folder', async () => {
      await expect(ctx.client.deleteItem(fakeIpnsName, 'child-id')).rejects.toThrow(
        'Folder not loaded'
      );
    });

    it('should throw on uploadFile with unloaded folder', async () => {
      await expect(
        ctx.client.uploadFile(fakeIpnsName, new Uint8Array(10), 'test.txt', 'text/plain')
      ).rejects.toThrow('Folder not loaded');
    });

    it('should throw on moveItem with unloaded source', async () => {
      await expect(ctx.client.moveItem(fakeIpnsName, ctx.rootIpnsName, 'child-id')).rejects.toThrow(
        'Source folder not loaded'
      );
    });

    it('should throw on moveItem with unloaded destination', async () => {
      await expect(ctx.client.moveItem(ctx.rootIpnsName, fakeIpnsName, 'child-id')).rejects.toThrow(
        'Destination folder not loaded'
      );
    });
  });

  describe('Bin operations without loadBin', () => {
    let freshCtx: TestContext;

    beforeAll(async () => {
      freshCtx = await createTestContext('bin-err');
    });

    afterAll(async () => {
      freshCtx.cleanup();
      await deleteTestAccount(freshCtx);
    });

    it('should throw BinNotLoadedError on deleteToBin', async () => {
      const err = await freshCtx.client
        .deleteToBin(freshCtx.rootIpnsName, 'id', 'path')
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(BinNotLoadedError);
      expect((err as Error).message).toBe('Bin not loaded');
    });

    it('should throw BinNotLoadedError on restoreFromBin', async () => {
      await expect(
        freshCtx.client.restoreFromBin('entry-id', freshCtx.rootIpnsName)
      ).rejects.toThrow('Bin not loaded');
    });

    it('should throw BinNotLoadedError on permanentDelete', async () => {
      await expect(freshCtx.client.permanentDelete('entry-id')).rejects.toThrow('Bin not loaded');
    });

    it('should throw BinNotLoadedError on emptyBin', async () => {
      await expect(freshCtx.client.emptyBin()).rejects.toThrow('Bin not loaded');
    });
  });

  describe('Event emission', () => {
    it('should emit operation:start and operation:end events', async () => {
      const events: any[] = [];
      const unsub = ctx.client.on((event) => events.push(event));

      await ctx.client.createFolder(ctx.rootIpnsName, 'EventTest');

      unsub();

      const starts = events.filter((e) => e.type === 'operation:start');
      const ends = events.filter((e) => e.type === 'operation:end');

      expect(starts.length).toBeGreaterThan(0);
      expect(ends.length).toBeGreaterThan(0);
      expect(starts[0].operation).toBe('createFolder');
      expect(ends[0].operation).toBe('createFolder');
      expect(ends[0].durationMs).toBeTypeOf('number');
    });

    it('should emit error events on failure', async () => {
      const events: any[] = [];
      const unsub = ctx.client.on((event) => events.push(event));

      try {
        await ctx.client.createFolder('k51nonexistent', 'WillFail');
      } catch {
        // Expected
      }

      unsub();

      const errors = events.filter((e) => e.type === 'error');
      expect(errors.length).toBe(1);
      expect(errors[0].operation).toBe('createFolder');
      expect(errors[0].error).toBeInstanceOf(Error);
    });
  });

  describe('Client lifecycle', () => {
    it('should not work after destroy()', async () => {
      const tempCtx = await createTestContext('destroy-test');

      // Should work before destroy
      const folder = await tempCtx.client.createFolder(tempCtx.rootIpnsName, 'PreDestroy');
      expect(folder.id).toBeTruthy();

      // Destroy
      tempCtx.client.destroy();

      // Operations should fail after destroy (keys are zeroed)
      await expect(
        tempCtx.client.createFolder(tempCtx.rootIpnsName, 'PostDestroy')
      ).rejects.toThrow();

      await deleteTestAccount(tempCtx);
    });
  });
});
