/**
 * Phase 68.2 Plan 03 (TDD): proves `client.getFolderMetadata` delegates to
 * the gated `ensureFolderLoaded` path (D-05 single gated read entrypoint --
 * no bypass) and that the pure structural utils (`getDepth`,
 * `isDescendantOf`, `calculateSubtreeDepth`, `selectEncryptionMode`) are
 * re-exported from `@cipherbox/sdk`'s public surface (D-07 write scope).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { Node } from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

const ROOT_IPNS = 'k51root-folder-metadata-facade';

function seedRoot(client: CipherBoxClient, metadata: Node) {
  client.getFolderTree().set(ROOT_IPNS, {
    ipnsName: ROOT_IPNS,
    folderKey: new Uint8Array(32).fill(0x10),
    writeKey: new Uint8Array(32).fill(0x11),
    ipnsKeypair: {
      publicKey: new Uint8Array(32).fill(0x12),
      privateKey: new Uint8Array(64).fill(0x13),
    },
    sequenceNumber: 1n,
    children: [],
    metadata,
    lastLoadedAt: Date.now(),
    nodeId: 'root-node-id',
    nodeGeneration: 0,
  });
}

describe('CipherBoxClient.getFolderMetadata', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the already-loaded folder’s decoded metadata by delegating to ensureFolderLoaded', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsName: ROOT_IPNS }));
    const metadata: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: 'root-node-id',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
      writeBody: {
        ipnsPrivateKey: new Uint8Array(64).fill(0x01),
        writeChildren: [],
      },
    };
    seedRoot(client, metadata);

    const result = await client.getFolderMetadata(ROOT_IPNS);

    expect(result).toBe(metadata);
  });

  it('returns null when ensureFolderLoaded cannot bootstrap the target (no gate bypass -- delegates entirely)', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsName: ROOT_IPNS }));
    const ensureFolderLoadedSpy = vi.spyOn(client, 'ensureFolderLoaded').mockResolvedValue(null);

    const result = await client.getFolderMetadata('k51unreachable');

    expect(result).toBeNull();
    expect(ensureFolderLoadedSpy).toHaveBeenCalledWith('k51unreachable');
  });
});

describe('@cipherbox/sdk pure structural util re-exports (D-07)', () => {
  it('re-exports getDepth, isDescendantOf, calculateSubtreeDepth, selectEncryptionMode', async () => {
    const sdk = await import('../index');

    expect(typeof sdk.getDepth).toBe('function');
    expect(typeof sdk.isDescendantOf).toBe('function');
    expect(typeof sdk.calculateSubtreeDepth).toBe('function');
    expect(typeof sdk.selectEncryptionMode).toBe('function');

    // Sanity-check behavior, not just presence.
    const folders = { a: { id: 'a', parentId: null }, b: { id: 'b', parentId: 'a' } };
    expect(sdk.getDepth('b', folders)).toBe(1);
    expect(sdk.isDescendantOf('b', 'a', folders)).toBe(true);
    expect(sdk.calculateSubtreeDepth('a', folders)).toBe(1);
    expect(sdk.selectEncryptionMode('video/mp4', 1024)).toBeTruthy();
  });
});
