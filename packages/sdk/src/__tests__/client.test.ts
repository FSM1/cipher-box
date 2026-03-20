import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { CipherBoxClientConfig } from '../types';
import type { SdkEvent } from '../events';

// Mock sdk-core to avoid real IPFS/IPNS calls
vi.mock('@cipherbox/sdk-core', () => ({
  loadFolderMetadata: vi.fn(),
  createSubfolder: vi.fn(),
  updateFolderMetadataAndPublish: vi.fn(),
  renameInFolder: vi.fn(),
  deleteFromFolder: vi.fn(),
  moveItem: vi.fn(),
  addFilePointerToFolder: vi.fn(),
  uploadFile: vi.fn(),
  downloadAndDecrypt: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
  createAndPublishIpnsRecord: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';

function createTestConfig(overrides?: Partial<CipherBoxClientConfig>): CipherBoxClientConfig {
  return {
    apiUrl: 'http://localhost:3000',
    getAccessToken: vi.fn().mockResolvedValue('test-token'),
    vaultKeypair: {
      publicKey: new Uint8Array(33).fill(1),
      privateKey: new Uint8Array(32).fill(2),
    },
    rootIpnsName: 'k51test',
    rootFolderKey: new Uint8Array(32).fill(3),
    ...overrides,
  };
}

describe('CipherBoxClient', () => {
  let client: CipherBoxClient;
  let config: CipherBoxClientConfig;

  beforeEach(() => {
    vi.clearAllMocks();
    config = createTestConfig();
    client = new CipherBoxClient(config);
  });

  describe('constructor', () => {
    it('creates internal state objects', () => {
      // The client should be created without errors
      expect(client).toBeDefined();
      expect(client).toBeInstanceOf(CipherBoxClient);
    });

    it('stores config and creates SdkContext from apiUrl + getAccessToken', () => {
      // Verify by checking that getContext returns expected shape
      const ctx = client.getContext();
      expect(ctx.apiUrl).toBe('http://localhost:3000');
      expect(ctx.getAccessToken).toBe(config.getAccessToken);
    });
  });

  describe('destroy', () => {
    it('clears folder tree keys (fills with 0)', () => {
      const folderKey = new Uint8Array(32).fill(0xaa);
      const ipnsPrivateKey = new Uint8Array(64).fill(0xbb);

      // Manually set folder state to test key clearing
      client.getFolderTree().set('test-ipns', {
        ipnsName: 'test-ipns',
        folderKey,
        ipnsKeypair: {
          publicKey: new Uint8Array(32).fill(0xcc),
          privateKey: ipnsPrivateKey,
        },
        sequenceNumber: 0n,
        children: [],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      client.destroy();

      // Keys should be zeroed
      expect(folderKey.every((b) => b === 0)).toBe(true);
      expect(ipnsPrivateKey.every((b) => b === 0)).toBe(true);
    });

    it('removes all event handlers', () => {
      const handler = vi.fn();
      client.on(handler);

      client.destroy();

      // Events after destroy should not reach the handler
      client.emitEvent({ type: 'operation:start', operation: 'test' });
      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('event subscription', () => {
    it('on() receives events via emitEvent', () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      client.emitEvent({ type: 'operation:start', operation: 'test' });

      expect(events).toHaveLength(1);
      expect(events[0]).toEqual({ type: 'operation:start', operation: 'test' });
    });

    it('off() stops receiving events', () => {
      const handler = vi.fn();
      client.on(handler);

      client.emitEvent({ type: 'operation:start', operation: 'test1' });
      expect(handler).toHaveBeenCalledOnce();

      client.off(handler);

      client.emitEvent({ type: 'operation:start', operation: 'test2' });
      expect(handler).toHaveBeenCalledOnce();
    });
  });

  describe('operations emit start/end events', () => {
    it('emits operation:start and operation:end on success', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      // Mock loadFolderMetadata to return data
      vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
        metadata: { version: 'v2', children: [] },
        sequenceNumber: 1n,
        cid: 'bafytest',
      });

      await client.loadFolder('test-ipns', new Uint8Array(32), {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      });

      const startEvent = events.find((e) => e.type === 'operation:start');
      const endEvent = events.find((e) => e.type === 'operation:end');

      expect(startEvent).toBeDefined();
      expect(startEvent!.type).toBe('operation:start');
      expect((startEvent as { operation: string }).operation).toBe('loadFolder');

      expect(endEvent).toBeDefined();
      expect(endEvent!.type).toBe('operation:end');
      expect(
        (endEvent as { operation: string; durationMs: number }).durationMs
      ).toBeGreaterThanOrEqual(0);
    });

    it('emits error event when operation fails', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      const testError = new Error('load failed');
      vi.mocked(sdkCore.loadFolderMetadata).mockRejectedValue(testError);

      await expect(
        client.loadFolder('test-ipns', new Uint8Array(32), {
          publicKey: new Uint8Array(32),
          privateKey: new Uint8Array(64),
        })
      ).rejects.toThrow('load failed');

      const errorEvent = events.find((e) => e.type === 'error');
      expect(errorEvent).toBeDefined();
      expect((errorEvent as { error: Error }).error).toBe(testError);
    });

    it('calls config.onOperationStart and onOperationEnd callbacks', async () => {
      const onStart = vi.fn();
      const onEnd = vi.fn();
      const clientWithCallbacks = new CipherBoxClient(
        createTestConfig({ onOperationStart: onStart, onOperationEnd: onEnd })
      );

      vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
        metadata: { version: 'v2', children: [] },
        sequenceNumber: 1n,
        cid: 'bafytest',
      });

      await clientWithCallbacks.loadFolder('test-ipns', new Uint8Array(32), {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      });

      expect(onStart).toHaveBeenCalledWith('loadFolder');
      expect(onEnd).toHaveBeenCalledWith('loadFolder');
    });

    it('calls config.onError callback on failure', async () => {
      const onError = vi.fn();
      const clientWithCallback = new CipherBoxClient(createTestConfig({ onError }));

      const testError = new Error('fail');
      vi.mocked(sdkCore.loadFolderMetadata).mockRejectedValue(testError);

      await expect(
        clientWithCallback.loadFolder('test-ipns', new Uint8Array(32), {
          publicKey: new Uint8Array(32),
          privateKey: new Uint8Array(64),
        })
      ).rejects.toThrow('fail');

      expect(onError).toHaveBeenCalledWith(testError);
    });
  });

  describe('loadFolder', () => {
    it('stores FolderState in internal tree and emits folder:loaded', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      const mockChildren = [
        {
          type: 'folder' as const,
          id: 'child1',
          name: 'SubFolder',
          ipnsName: 'k51child',
          ipnsPrivateKeyEncrypted: 'abc',
          folderKeyEncrypted: 'def',
          createdAt: Date.now(),
          modifiedAt: Date.now(),
        },
      ];

      vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
        metadata: { version: 'v2', children: mockChildren },
        sequenceNumber: 5n,
        cid: 'bafytest',
      });

      const folderKey = new Uint8Array(32).fill(4);
      const ipnsKeypair = {
        publicKey: new Uint8Array(32).fill(5),
        privateKey: new Uint8Array(64).fill(6),
      };

      const result = await client.loadFolder('test-ipns', folderKey, ipnsKeypair);

      // Verify state stored
      expect(result).not.toBeNull();
      expect(result!.ipnsName).toBe('test-ipns');
      expect(result!.sequenceNumber).toBe(5n);
      expect(result!.children).toEqual(mockChildren);

      // Verify folder:loaded event
      const loadedEvent = events.find((e) => e.type === 'folder:loaded');
      expect(loadedEvent).toBeDefined();
      expect((loadedEvent as { folderId: string }).folderId).toBe('test-ipns');
      expect((loadedEvent as { children: unknown[] }).children).toEqual(mockChildren);
    });

    it('returns null when IPNS record not found', async () => {
      vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue(null);

      const result = await client.loadFolder('nonexistent', new Uint8Array(32), {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      });

      expect(result).toBeNull();
    });
  });

  describe('deleteItem', () => {
    it('removes item and emits folder:updated', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));

      // Set up folder state
      const child = {
        type: 'file' as const,
        id: 'file1',
        name: 'test.txt',
        fileMetaIpnsName: 'k51file',
        ipnsPrivateKeyEncrypted: 'abc',
        createdAt: Date.now(),
        modifiedAt: Date.now(),
      };

      client.getFolderTree().set('folder-ipns', {
        ipnsName: 'folder-ipns',
        folderKey: new Uint8Array(32).fill(1),
        ipnsKeypair: {
          publicKey: new Uint8Array(32).fill(2),
          privateKey: new Uint8Array(64).fill(3),
        },
        sequenceNumber: 1n,
        children: [child],
        metadata: null,
        lastLoadedAt: Date.now(),
      });

      vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
        updatedChildren: [],
        removedItem: child,
      });

      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafynew',
        newSequenceNumber: 2n,
      });

      const result = await client.deleteItem('folder-ipns', 'file1');

      expect(result.removedItem).toEqual(child);

      // Verify folder:updated event emitted
      const updatedEvent = events.find((e) => e.type === 'folder:updated');
      expect(updatedEvent).toBeDefined();
    });
  });
});
