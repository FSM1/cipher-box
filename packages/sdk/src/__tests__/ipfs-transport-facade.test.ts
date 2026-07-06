import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';

// Mock sdk-core to avoid real IPFS/IPNS calls; only the IPFS transport fns
// are relevant to this facade — everything else is left as `actual` since
// these tests never touch folder/file orchestration paths.
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    addToIpfs: vi.fn(),
    fetchFromIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

describe('CipherBoxClient IPFS-transport facade', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('uploadBytes', () => {
    it('forwards the onProgress callback to sdkCore.addToIpfs', async () => {
      vi.mocked(sdkCore.addToIpfs).mockImplementation(async (_ctx, _data, onProgress) => {
        // Simulate the underlying transport reporting progress events.
        onProgress?.(50);
        onProgress?.(100);
        return { cid: 'bafyUploaded', size: 42, recorded: true };
      });

      const onProgress = vi.fn();
      const data = new Uint8Array([1, 2, 3]);

      const result = await client.uploadBytes(data, onProgress);

      expect(sdkCore.addToIpfs).toHaveBeenCalledWith(expect.anything(), data, expect.any(Function));
      expect(onProgress).toHaveBeenCalledTimes(2);
      expect(onProgress).toHaveBeenNthCalledWith(1, 50);
      expect(onProgress).toHaveBeenNthCalledWith(2, 100);
      expect(result).toEqual({ cid: 'bafyUploaded', size: 42 });
    });

    it('works without an onProgress callback', async () => {
      vi.mocked(sdkCore.addToIpfs).mockResolvedValue({
        cid: 'bafyNoProgress',
        size: 10,
        recorded: true,
      });

      const result = await client.uploadBytes(new Uint8Array([9]));

      expect(result).toEqual({ cid: 'bafyNoProgress', size: 10 });
    });
  });

  describe('downloadBytes', () => {
    it('returns the fetched bytes for a given CID and forwards onProgress', async () => {
      const expected = new Uint8Array([4, 5, 6]);
      vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx, _cid, onProgress) => {
        onProgress?.(3, 6);
        return expected;
      });

      const onProgress = vi.fn();
      const result = await client.downloadBytes('bafyDownload', onProgress);

      expect(sdkCore.fetchFromIpfs).toHaveBeenCalledWith(
        expect.anything(),
        'bafyDownload',
        expect.any(Function)
      );
      expect(onProgress).toHaveBeenCalledWith(3, 6);
      expect(result).toBe(expected);
    });
  });

  describe('unpin', () => {
    it('delegates to sdkCore.unpinFromIpfs', async () => {
      vi.mocked(sdkCore.unpinFromIpfs).mockResolvedValue(undefined);

      await client.unpin('bafyUnpin');

      expect(sdkCore.unpinFromIpfs).toHaveBeenCalledWith(expect.anything(), 'bafyUnpin');
    });
  });
});
