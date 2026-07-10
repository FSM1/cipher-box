import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { Node, SealedChildRef } from '@cipherbox/core';

// Mock sdk-core: keep everything real except loadFolderMetadata, which we drive
// to return canned IPNS-resolved state (simulating a stale IPNS snapshot).
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
  };
});

// Mock crypto (not exercised by loadFolder directly, but the module is imported).
vi.mock('@cipherbox/crypto', () => ({
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(9)),
  hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
  clearBytes: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';

const IPNS = 'k51reconcile';

const folderKey = new Uint8Array(32).fill(1);
// All-zero: matches FolderState's documented "legacy zero-fallback" writeKey
// (types.ts) so getWriteBodyParams's hasRealWriteKey check short-circuits to
// `{}` — loadFolder never exercises the write-body path, so this is inert.
const writeKey = new Uint8Array(32);
const ipnsKeypair = {
  publicKey: new Uint8Array(32).fill(2),
  privateKey: new Uint8Array(64).fill(3),
};

/** Build a canned loadFolderMetadata result with the given sequenceNumber. */
function mockResolve(sequenceNumber: bigint) {
  const metadata: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: 'reconcile-node-id',
    generation: 0,
    createdAt: 0,
    modifiedAt: 0,
    children: [],
  };
  vi.mocked(sdkCore.loadFolderMetadata).mockResolvedValue({
    metadata,
    sequenceNumber,
    cid: `cid-${sequenceNumber}`,
  });
}

describe('CipherBoxClient.loadFolder — sequenceNumber reconcile guard (REQ-1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  /**
   * Test A (keep-fresher): in-memory entry with sequenceNumber >= resolved value.
   *
   * The IPNS snapshot is STALE (resolved = 3n, in-memory = 5n).
   * loadFolder must NOT clobber the fresher in-memory entry.
   *
   * RED state: this fails against current source because loadFolder unconditionally
   * calls folderTree.set() and overwrites the existing entry with the stale snapshot.
   */
  it('keeps the fresher in-memory entry when resolved sequenceNumber is older', async () => {
    const client = new CipherBoxClient(createTestConfig());

    // Seed in-memory entry at sequence 5 with known children
    const existingChildren: SealedChildRef[] = [
      {
        name: 'important.txt',
        ipnsName: 'kept-file',
        generation: 0,
        versionFloor: 1n,
        readKeySealed: 'sealed-kept-file',
      },
    ];
    client.getFolderTree().set(IPNS, {
      ipnsName: IPNS,
      folderKey,
      writeKey,
      ipnsKeypair,
      sequenceNumber: 5n,
      children: existingChildren,
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: '',
      nodeGeneration: 0,
    });

    // IPNS resolves a STALE snapshot at sequence 3 with empty children
    mockResolve(3n);

    const result = await client.loadFolder(IPNS, folderKey, ipnsKeypair);

    // Must return the EXISTING (fresher) entry — not the stale snapshot
    expect(result?.sequenceNumber).toBe(5n);
    expect(result?.children).toEqual(existingChildren);

    // folderTree must still hold the fresher entry
    const stored = client.getFolderTree().get(IPNS);
    expect(stored?.sequenceNumber).toBe(5n);
    expect(stored?.children).toEqual(existingChildren);

    // IPNS was queried (we don't avoid the network call — just skip the set)
    expect(sdkCore.loadFolderMetadata).toHaveBeenCalledTimes(1);
  });

  /**
   * Test B (no-#498-regression): genuinely absent folder is loaded and set.
   *
   * When there is NO in-memory entry, loadFolder must resolve, set, and return.
   * Guard must not suppress the set when no existing entry is present.
   */
  it('resolves and sets state when no in-memory entry exists', async () => {
    const client = new CipherBoxClient(createTestConfig());

    // No in-memory entry — folder is genuinely absent
    expect(client.getFolderTree().get(IPNS)).toBeUndefined();

    mockResolve(1n);

    const result = await client.loadFolder(IPNS, folderKey, ipnsKeypair);

    expect(result?.sequenceNumber).toBe(1n);
    expect(result?.ipnsName).toBe(IPNS);

    // Must have been written into the folderTree
    expect(client.getFolderTree().get(IPNS)?.sequenceNumber).toBe(1n);
    expect(sdkCore.loadFolderMetadata).toHaveBeenCalledTimes(1);
  });

  /**
   * Test C (older-in-memory overwritten): in-memory entry has LOWER sequenceNumber.
   *
   * When the resolved snapshot is FRESHER (resolved = 7n, in-memory = 2n),
   * loadFolder must overwrite the stale in-memory entry with the fresher snapshot.
   */
  it('overwrites the in-memory entry when the resolved sequenceNumber is newer', async () => {
    const client = new CipherBoxClient(createTestConfig());

    // Seed stale in-memory entry at sequence 2
    client.getFolderTree().set(IPNS, {
      ipnsName: IPNS,
      folderKey,
      writeKey,
      ipnsKeypair,
      sequenceNumber: 2n,
      children: [],
      metadata: null,
      lastLoadedAt: Date.now(),
      nodeId: '',
      nodeGeneration: 0,
    });

    // IPNS resolves a FRESHER snapshot at sequence 7
    mockResolve(7n);

    const result = await client.loadFolder(IPNS, folderKey, ipnsKeypair);

    // Must return the resolved (fresher) snapshot
    expect(result?.sequenceNumber).toBe(7n);

    // folderTree must hold the updated entry
    expect(client.getFolderTree().get(IPNS)?.sequenceNumber).toBe(7n);
    expect(sdkCore.loadFolderMetadata).toHaveBeenCalledTimes(1);
  });
});
