/**
 * TDD tests for 68.2-04 Task 2: BYO-pinning config-blob facade passthrough
 * on CipherBoxClient (D-07 full boundary).
 *
 * These give ConnectionTest.tsx/StorageTab.tsx a facade entrypoint for the
 * BYO-config-blob operations they perform today via `@cipherbox/sdk-core`'s
 * `testConnection` and the web-local `ipns.service.ts`'s
 * `resolveIpnsRecord`/`createAndPublishIpnsRecord` (slated for deletion --
 * 68.2-PATTERNS.md). The BYO config blob is user-configured, NOT part of the
 * ROT-07 durable anti-rollback floor, so none of these methods route through
 * `rotationHighWater.enforceResolved` (68.2-PATTERNS "No Analog Found").
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    testConnection: vi.fn(),
    resolveIpnsRecord: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

describe('CipherBoxClient BYO-pinning facade', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('testConnection', () => {
    it('delegates to sdkCore.testConnection with the endpoint and authToken', async () => {
      vi.mocked(sdkCore.testConnection).mockResolvedValue({
        success: true,
        protocol: 'kubo',
        version: '0.34.0',
        latencyMs: 42,
      });

      const result = await client.testConnection('https://ipfs.example.com', 'token123');

      expect(sdkCore.testConnection).toHaveBeenCalledWith('https://ipfs.example.com', 'token123');
      expect(result).toEqual({
        success: true,
        protocol: 'kubo',
        version: '0.34.0',
        latencyMs: 42,
      });
    });

    it('works without an authToken', async () => {
      vi.mocked(sdkCore.testConnection).mockResolvedValue({
        success: false,
        latencyMs: 0,
        error: 'could not detect ipfs protocol at this endpoint.',
      });

      await client.testConnection('https://ipfs.example.com');

      expect(sdkCore.testConnection).toHaveBeenCalledWith('https://ipfs.example.com', undefined);
    });
  });

  describe('resolveConfigBlob', () => {
    it('delegates to sdkCore.resolveIpnsRecord with this.ctx injected -- NOT gated', async () => {
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
        cid: 'bafyConfig',
        sequenceNumber: 3n,
        signatureVerified: true,
      });

      const result = await client.resolveConfigBlob('k51byoConfig');

      expect(sdkCore.resolveIpnsRecord).toHaveBeenCalledWith('k51byoConfig', expect.anything());
      expect(result).toEqual({ cid: 'bafyConfig', sequenceNumber: 3n, signatureVerified: true });
    });

    it('returns null when the config blob has never been published', async () => {
      vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);

      const result = await client.resolveConfigBlob('k51byoConfig');

      expect(result).toBeNull();
    });
  });

  describe('publishConfigBlob', () => {
    it('delegates to sdkCore.createAndPublishIpnsRecord with this.ctx injected -- NOT gated', async () => {
      vi.mocked(sdkCore.createAndPublishIpnsRecord).mockResolvedValue({
        success: true,
        sequenceNumber: 1n,
      });

      const ipnsPrivateKey = new Uint8Array(32).fill(5);

      const result = await client.publishConfigBlob({
        ipnsPrivateKey,
        ipnsName: 'k51byoConfig',
        metadataCid: 'bafyConfigBlob',
        sequenceNumber: 1n,
      });

      expect(sdkCore.createAndPublishIpnsRecord).toHaveBeenCalledWith({
        ipnsPrivateKey,
        ipnsName: 'k51byoConfig',
        metadataCid: 'bafyConfigBlob',
        sequenceNumber: 1n,
        ctx: expect.anything(),
      });
      expect(result).toEqual({ success: true, sequenceNumber: 1n });
    });
  });
});
