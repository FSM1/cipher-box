import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderEntry, FolderMetadata } from '@cipherbox/core';

// Mock sdk-core: keep everything real except loadFolderMetadata, which we drive
// per-folder so the DFS walk has metadata to descend through.
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
  };
});

// Mock crypto: ensureFolderLoaded unwraps each subfolder's keys with these.
// Return value content is irrelevant — loadFolderMetadata is mocked, so the
// "decrypted" key is never actually used to decrypt anything.
vi.mock('@cipherbox/crypto', () => ({
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(9)),
  hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
  clearBytes: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';

const ROOT = 'k51test'; // matches createTestConfig().rootIpnsName

function folderEntry(ipnsName: string, name: string): FolderEntry {
  return {
    type: 'folder',
    id: `id-${ipnsName}`,
    name,
    ipnsName,
    ipnsPrivateKeyEncrypted: 'aa',
    folderKeyEncrypted: 'bb',
    createdAt: 1,
    modifiedAt: 1,
  };
}

function metadata(children: FolderMetadata['children']): FolderMetadata {
  return { version: 'v2', children };
}

/** Drive loadFolderMetadata to return canned metadata keyed by IPNS name. */
function mockTree(tree: Record<string, FolderMetadata['children']>) {
  vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async ({ ipnsName }) => {
    const children = tree[ipnsName];
    if (!children) return null;
    return { metadata: metadata(children), sequenceNumber: 1n, cid: `cid-${ipnsName}` };
  });
}

const rootIpnsKeypair = {
  publicKey: new Uint8Array(32).fill(7),
  privateKey: new Uint8Array(64).fill(8),
};

describe('CipherBoxClient.ensureFolderLoaded', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the existing state without resolving IPNS when already loaded', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsKeypair }));
    client.getFolderTree().set('k51a', {
      ipnsName: 'k51a',
      folderKey: new Uint8Array(32).fill(1),
      ipnsKeypair: { publicKey: new Uint8Array(0), privateKey: new Uint8Array(32).fill(2) },
      sequenceNumber: 5n,
      children: [],
      metadata: null,
      lastLoadedAt: 1,
    });

    const result = await client.ensureFolderLoaded('k51a');

    expect(result?.ipnsName).toBe('k51a');
    expect(result?.sequenceNumber).toBe(5n);
    expect(sdkCore.loadFolderMetadata).not.toHaveBeenCalled();
  });

  it('returns null without resolving IPNS when no root IPNS keypair is configured', async () => {
    const client = new CipherBoxClient(createTestConfig()); // no rootIpnsKeypair

    const result = await client.ensureFolderLoaded('k51missing');

    expect(result).toBeNull();
    expect(sdkCore.loadFolderMetadata).not.toHaveBeenCalled();
  });

  it('bootstraps the root folder when the target IS the root', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsKeypair }));
    mockTree({ [ROOT]: [] });

    const result = await client.ensureFolderLoaded(ROOT);

    expect(result?.ipnsName).toBe(ROOT);
    expect(client.hasFolder(ROOT)).toBe(true);
    expect(sdkCore.loadFolderMetadata).toHaveBeenCalledTimes(1);
  });

  it('walks from root down to a deep target, registering every folder on the path', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsKeypair }));
    // root -> A -> B(target)
    mockTree({
      [ROOT]: [folderEntry('k51a', 'A')],
      k51a: [folderEntry('k51b', 'B')],
      k51b: [],
    });

    const result = await client.ensureFolderLoaded('k51b');

    expect(result?.ipnsName).toBe('k51b');
    // Whole path cached for cheap subsequent lookups.
    expect(client.hasFolder(ROOT)).toBe(true);
    expect(client.hasFolder('k51a')).toBe(true);
    expect(client.hasFolder('k51b')).toBe(true);
  });

  it('returns null when the target is not reachable from root', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsKeypair }));
    mockTree({
      [ROOT]: [folderEntry('k51a', 'A')],
      k51a: [], // no further descendants; target k51zzz absent
    });

    const result = await client.ensureFolderLoaded('k51zzz');

    expect(result).toBeNull();
    // Still cached what it walked.
    expect(client.hasFolder('k51a')).toBe(true);
  });

  it('short-circuits a subfolder that has no IPNS record (skips, keeps walking)', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsKeypair }));
    // root has A (unresolvable) and B(target); A returns null from loadFolderMetadata.
    mockTree({
      [ROOT]: [folderEntry('k51a', 'A'), folderEntry('k51b', 'B')],
      // k51a intentionally absent -> loadFolderMetadata returns null
      k51b: [],
    });

    const result = await client.ensureFolderLoaded('k51b');

    expect(result?.ipnsName).toBe('k51b');
    expect(client.hasFolder('k51a')).toBe(false);
    expect(client.hasFolder('k51b')).toBe(true);
  });

  it('skips a sibling whose key unwrap fails and still reaches the target', async () => {
    const client = new CipherBoxClient(createTestConfig({ rootIpnsKeypair }));
    mockTree({
      [ROOT]: [folderEntry('k51a', 'A'), folderEntry('k51b', 'B')],
      k51a: [],
      k51b: [],
    });
    const crypto = await import('@cipherbox/crypto');
    // First unwrap (folder A's folderKey) throws; later unwraps succeed — one
    // corrupt sibling must not abort the whole bootstrap.
    vi.mocked(crypto.unwrapKey).mockRejectedValueOnce(new Error('unwrap failed'));

    const result = await client.ensureFolderLoaded('k51b');

    expect(result?.ipnsName).toBe('k51b');
    expect(client.hasFolder('k51a')).toBe(false); // skipped on unwrap failure
    expect(client.hasFolder('k51b')).toBe(true);
  });
});
