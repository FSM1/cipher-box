import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
// Types used implicitly via createTestConfig overrides
import type { SdkEvent } from '../events';
import { createTestConfig, setupFolder } from './helpers';

// Track pinFn calls from uploadFile
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let capturedPinFn: ((...args: any[]) => any) | undefined;

// Mock sdk-core
vi.mock('@cipherbox/sdk-core', async () => {
  const actual = await vi.importActual<typeof import('@cipherbox/sdk-core')>('@cipherbox/sdk-core');
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    createSubfolder: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    renameInFolder: vi.fn(),
    deleteFromFolder: vi.fn(),
    moveItem: vi.fn(),
    addFilePointerToFolder: vi.fn(),
    // uploadFile mock: captures pinFn and calls it if present
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    uploadFile: vi.fn().mockImplementation(async (params: { pinFn?: (...args: any[]) => any }) => {
      capturedPinFn = params.pinFn;
      // If a pinFn is provided, call it with test data to exercise the BYO path
      if (params.pinFn) {
        const pinResult = await params.pinFn(
          { apiUrl: 'http://localhost:3000', getAccessToken: async () => 'token' },
          new Uint8Array([1, 2, 3])
        );
        return {
          cid: pinResult.cid,
          encryptedSize: pinResult.size,
          fileMetaIpnsName: 'k51fileMeta',
          ipnsRecord: { ipnsName: 'k51fileMeta', data: 'mock-record' },
          encryptedIpnsPrivateKey: 'encrypted-key-hex',
          fileKey: new Uint8Array(32),
        };
      }
      return {
        cid: 'bafyDefault',
        encryptedSize: 100,
        fileMetaIpnsName: 'k51fileMeta',
        ipnsRecord: { ipnsName: 'k51fileMeta', data: 'mock-record' },
        encryptedIpnsPrivateKey: 'encrypted-key-hex',
        fileKey: new Uint8Array(32),
      };
    }),
    downloadAndDecrypt: vi.fn(),
    batchPublishIpnsRecords: vi.fn().mockResolvedValue({ totalSucceeded: 1, totalFailed: 0 }),
    resolveFileMetadata: vi.fn(),
    // IPFS ops (called by pinWithMode)
    addToIpfs: vi.fn().mockResolvedValue({ cid: 'bafyCipherbox', size: 200, recorded: true }),
    unpinFromIpfs: vi.fn().mockResolvedValue(undefined),
    registerCid: vi.fn().mockResolvedValue(undefined),
    fetchFromIpfs: vi.fn(),
    // Pinning provider classes -- use actual implementations
    KuboProvider: actual.KuboProvider,
    PsaProvider: actual.PsaProvider,
    DualPinProvider: actual.DualPinProvider,
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

describe('CipherBoxClient pinning', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedPinFn = undefined;
  });

  describe('cipherbox mode (default)', () => {
    it('passes no pinFn to sdkCore.uploadFile', async () => {
      const config = createTestConfig();
      const client = new CipherBoxClient(config);
      setupFolder(client, 'folder-ipns');

      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'test.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      await client.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain');

      expect(sdkCore.uploadFile).toHaveBeenCalledWith(
        expect.objectContaining({
          pinFn: undefined,
        })
      );
    });
  });

  describe('external mode + kubo', () => {
    it('passes pinFn to sdkCore.uploadFile and KuboProvider.pin is called directly', async () => {
      // Stub global fetch for KuboProvider
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ Hash: 'bafyKubo', Size: '300' })),
      });
      vi.stubGlobal('fetch', mockFetch);

      const config = createTestConfig({
        pinningConfig: {
          mode: 'external',
          externalProvider: {
            endpoint: 'http://my-kubo:5001',
            authToken: 'kubo-secret',
            protocol: 'kubo',
            providerName: 'My Kubo Node',
          },
        },
      });
      const client = new CipherBoxClient(config);
      setupFolder(client, 'folder-ipns');

      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'new.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      await client.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain');

      // pinFn should have been provided
      expect(capturedPinFn).toBeDefined();
      // KuboProvider.pin was called via fetch (addToIpfs NOT called)
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('http://my-kubo:5001/api/v0/add'),
        expect.anything()
      );
      expect(sdkCore.addToIpfs).not.toHaveBeenCalled();
      // registerCid was called for advisory tracking
      expect(sdkCore.registerCid).toHaveBeenCalledWith(expect.anything(), 'bafyKubo', 300);

      vi.unstubAllGlobals();
    });

    it('fails hard when Kubo is unreachable (no CipherBox fallback)', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Connection refused'));
      vi.stubGlobal('fetch', mockFetch);

      const config = createTestConfig({
        pinningConfig: {
          mode: 'external',
          externalProvider: {
            endpoint: 'http://unreachable:5001',
            authToken: '',
            protocol: 'kubo',
          },
        },
      });
      const client = new CipherBoxClient(config);
      setupFolder(client, 'folder-ipns');

      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'new.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      // Upload should fail -- no silent CipherBox fallback
      await expect(
        client.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain')
      ).rejects.toThrow('Connection refused');

      // addToIpfs should NOT have been called (no fallback)
      expect(sdkCore.addToIpfs).not.toHaveBeenCalled();

      vi.unstubAllGlobals();
    });
  });

  describe('external mode + PSA', () => {
    it('uses CipherBox relay for CID then calls pinByCid', async () => {
      // Mock fetch for PsaProvider.pinByCid
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            requestid: 'req1',
            status: 'queued',
            pin: { cid: 'bafyCipherbox' },
          }),
      });
      vi.stubGlobal('fetch', mockFetch);

      const config = createTestConfig({
        pinningConfig: {
          mode: 'external',
          externalProvider: {
            endpoint: 'https://api.pinata.cloud/psa',
            authToken: 'psa-jwt',
            protocol: 'psa',
            providerName: 'Pinata',
          },
        },
      });
      const client = new CipherBoxClient(config);
      setupFolder(client, 'folder-ipns');

      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'new.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      await client.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain');

      // addToIpfs WAS called (CipherBox relay for CID acquisition -- PSA limitation)
      expect(sdkCore.addToIpfs).toHaveBeenCalled();
      // PsaProvider.pinByCid was called via fetch
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/pins'),
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('bafyCipherbox'),
        })
      );
      // unpinFromIpfs was called to clean up CipherBox relay copy
      expect(sdkCore.unpinFromIpfs).toHaveBeenCalled();
      // registerCid was called for advisory tracking
      expect(sdkCore.registerCid).toHaveBeenCalled();

      vi.unstubAllGlobals();
    });
  });

  describe('dual mode', () => {
    it('uses CipherBox as primary and external as secondary', async () => {
      // Mock fetch for KuboProvider secondary pin
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ Hash: 'bafyCipherbox', Size: '200' })),
      });
      vi.stubGlobal('fetch', mockFetch);

      const config = createTestConfig({
        pinningConfig: {
          mode: 'dual',
          externalProvider: {
            endpoint: 'http://my-kubo:5001',
            authToken: '',
            protocol: 'kubo',
          },
        },
      });
      const client = new CipherBoxClient(config);
      setupFolder(client, 'folder-ipns');

      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'new.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      await client.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain');

      // addToIpfs was called (CipherBox primary)
      expect(sdkCore.addToIpfs).toHaveBeenCalled();
      // KuboProvider secondary was also attempted
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('http://my-kubo:5001/api/v0/add'),
        expect.anything()
      );

      vi.unstubAllGlobals();
    });

    it('emits pin:secondaryFailed when secondary fails (non-blocking)', async () => {
      // Mock fetch to fail for secondary KuboProvider
      const mockFetch = vi.fn().mockRejectedValue(new Error('Kubo offline'));
      vi.stubGlobal('fetch', mockFetch);

      const config = createTestConfig({
        pinningConfig: {
          mode: 'dual',
          externalProvider: {
            endpoint: 'http://my-kubo:5001',
            authToken: '',
            protocol: 'kubo',
            providerName: 'My Backup Node',
          },
        },
      });
      const client = new CipherBoxClient(config);
      setupFolder(client, 'folder-ipns');

      vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
        updatedChildren: [],
        newRef: {
          name: 'new.txt',
          ipnsName: 'k51',
          generation: 0,
          versionFloor: 0n,
          readKeySealed: 'enc',
        },
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      // Upload should succeed (secondary failure is non-blocking)
      await client.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain');

      // Find pin:secondaryFailed event
      const pinFailedEvent = events.find((e) => e.type === 'pin:secondaryFailed');
      expect(pinFailedEvent).toBeDefined();
      expect(pinFailedEvent).toMatchObject({
        type: 'pin:secondaryFailed',
        providerName: 'My Backup Node',
      });

      vi.unstubAllGlobals();
    });
  });

  describe('BYO-06: IPNS operations unchanged', () => {
    it('batchPublishIpnsRecords is called identically regardless of pinning mode', async () => {
      // Mock fetch for KuboProvider
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        text: () => Promise.resolve(JSON.stringify({ Hash: 'bafyKubo', Size: '100' })),
      });
      vi.stubGlobal('fetch', mockFetch);

      const commonSetup = (client: CipherBoxClient) => {
        setupFolder(client, 'folder-ipns');
        vi.mocked(sdkCore.addFilePointerToFolder).mockResolvedValue({
          updatedChildren: [],
          newRef: {
            name: 'new.txt',
            ipnsName: 'k51',
            generation: 0,
            versionFloor: 0n,
            readKeySealed: 'enc',
          },
        });
        vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
          cid: 'bafynew',
          newSequenceNumber: 2n,
          publishedChildren: [],
        });
      };

      // Upload with external mode
      const externalConfig = createTestConfig({
        pinningConfig: {
          mode: 'external',
          externalProvider: {
            endpoint: 'http://my-kubo:5001',
            authToken: '',
            protocol: 'kubo',
          },
        },
      });
      const externalClient = new CipherBoxClient(externalConfig);
      commonSetup(externalClient);

      await externalClient.uploadFile('folder-ipns', new Uint8Array([1]), 'new.txt', 'text/plain');

      // batchPublishIpnsRecords should still be called (IPNS untouched)
      expect(sdkCore.batchPublishIpnsRecords).toHaveBeenCalled();

      vi.unstubAllGlobals();
    });
  });
});
