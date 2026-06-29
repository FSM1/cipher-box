/**
 * TDD test (49-01 RED): enumerateSharedSubtree
 *
 * Covers:
 * - Returns all reachable subfolders (DFS traversal)
 * - writable=true only when a keyType:folder-ipns entry exists for that node
 * - A node missing its keyType:folder key is skipped (not returned)
 * - A repeated ipnsName does not cause infinite loop (visited set guard)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { unwrapKey } from '@cipherbox/crypto';
import { CipherBoxClient } from '../client';
import type { SharedFolderState } from '../types';
import type { SealedChildRef } from '@cipherbox/core';
import { createTestConfig } from './helpers';

// ── crypto mock ───────────────────────────────────────────────────────────────
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xab)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(Math.max(hex.length / 2, 1)).fill(0x01)),
}));

// ── sdk-core mock ─────────────────────────────────────────────────────────────
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    moveItem: vi.fn(),
    createSubfolder: vi.fn(),
    renameInFolder: vi.fn(),
    deleteFromFolder: vi.fn(),
    addFilePointerToFolder: vi.fn(),
    uploadFile: vi.fn(),
    downloadAndDecrypt: vi.fn(),
    resolveFileMetadata: vi.fn(),
    updateFileMetadata: vi.fn(),
    batchPublishIpnsRecords: vi.fn(),
    createAndPublishIpnsRecord: vi.fn(),
    addToIpfs: vi.fn(),
    fetchFromIpfs: vi.fn(),
    unpinFromIpfs: vi.fn(),
  };
});

vi.mock('../bin', () => ({
  loadBin: vi.fn(),
  addToBin: vi.fn(),
  restoreFromBin: vi.fn(),
  permanentDeleteFromBin: vi.fn(),
  emptyBin: vi.fn(),
  purgeExpiredEntries: vi.fn(),
}));

vi.mock('../share', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../share')>();
  return {
    ...actual,
    uploadToSharedFolder: vi.fn(),
  };
});

vi.mock('../reencrypt', () => ({
  reencryptFileMetadataForFolderChange: vi.fn().mockResolvedValue(undefined),
}));

import * as sdkCore from '@cipherbox/sdk-core';

// ── constants ─────────────────────────────────────────────────────────────────
const SHARE_ID = 'share-enum-test';
const ROOT_IPNS = 'k51root-shared';

// Three subfolders in the tree:
//   root -> [subA (writable), subB (read-only), subC (no key = skip)]
// subA -> [subA1 (writable)]

const SUB_A_IPNS = 'k51sub-a';
const SUB_A_NAME = 'FolderA';

const SUB_B_IPNS = 'k51sub-b';
const SUB_B_NAME = 'FolderB';

const SUB_C_IPNS = 'k51sub-c';
const SUB_C_NAME = 'FolderC'; // no folder key → must be skipped

const SUB_A1_IPNS = 'k51sub-a1';
const SUB_A1_NAME = 'FolderA1';

function makeRef(name: string, ipnsName: string): SealedChildRef {
  return {
    name,
    ipnsName,
    generation: 0,
    versionFloor: 0n,
    readKeySealed: `enc-${ipnsName}`,
  };
}

// Root children: subA, subB, subC (subC has no share_keys folder entry)
const rootChildren: SealedChildRef[] = [
  makeRef(SUB_A_NAME, SUB_A_IPNS),
  makeRef(SUB_B_NAME, SUB_B_IPNS),
  makeRef(SUB_C_NAME, SUB_C_IPNS),
];

// subA children: subA1
const subAChildren: SealedChildRef[] = [makeRef(SUB_A1_NAME, SUB_A1_IPNS)];

type ShareKeyEntry = { keyType: string; itemId: string; encryptedKey: string };

function makeShareKeys(): ShareKeyEntry[] {
  return [
    // subA: readable + writable (itemId is ipnsName)
    { keyType: 'folder', itemId: SUB_A_IPNS, encryptedKey: 'enc-sub-a-folder' },
    { keyType: 'folder-ipns', itemId: SUB_A_IPNS, encryptedKey: 'enc-sub-a-ipns' },
    // subB: readable only (no folder-ipns → writable=false)
    { keyType: 'folder', itemId: SUB_B_IPNS, encryptedKey: 'enc-sub-b-folder' },
    // subC: NO folder key → DFS must skip this node
    // (intentionally absent)
    // subA1: readable + writable
    { keyType: 'folder', itemId: SUB_A1_IPNS, encryptedKey: 'enc-sub-a1-folder' },
    { keyType: 'folder-ipns', itemId: SUB_A1_IPNS, encryptedKey: 'enc-sub-a1-ipns' },
  ];
}

function seedSharedFolder(client: CipherBoxClient): void {
  const state: SharedFolderState = {
    shareId: SHARE_ID,
    ipnsName: ROOT_IPNS,
    folderKey: new Uint8Array(32).fill(0x01),
    ipnsPrivateKey: new Uint8Array(64).fill(0x02),
    sequenceNumber: 1n,
    children: rootChildren,
    ownerPublicKey: new Uint8Array(33).fill(0x03),
    recipientPublicKey: new Uint8Array(33).fill(0x04),
    addShareKeysFn: vi.fn().mockResolvedValue(undefined),
  };
  client.loadSharedFolder(SHARE_ID, state);
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('CipherBoxClient.enumerateSharedSubtree', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());

    // loadFolderMetadata: return subA children for subA's ipnsName; empty for others
    vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async (p) => {
      if (p.ipnsName === SUB_A_IPNS) {
        return {
          metadata: { children: subAChildren } as never,
          sequenceNumber: 2n,
          cid: 'bafysuba',
        };
      }
      return { metadata: { children: [] } as never, sequenceNumber: 1n, cid: 'bafyempty' };
    });
  });

  it('returns all reachable subfolders in DFS order', async () => {
    seedSharedFolder(client);

    const result = await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    // Should include subA, subB, subA1 — but NOT subC (no folder key)
    const ids = result.map((n) => n.id);
    expect(ids).toContain(SUB_A_IPNS);
    expect(ids).toContain(SUB_B_IPNS);
    expect(ids).toContain(SUB_A1_IPNS);
    expect(ids).not.toContain(SUB_C_IPNS);
    expect(result).toHaveLength(3);
  });

  it('sets writable=true only when a folder-ipns entry exists', async () => {
    seedSharedFolder(client);

    const result = await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    const subA = result.find((n) => n.id === SUB_A_IPNS);
    const subB = result.find((n) => n.id === SUB_B_IPNS);
    const subA1 = result.find((n) => n.id === SUB_A1_IPNS);

    expect(subA?.writable).toBe(true);
    expect(subB?.writable).toBe(false); // read-only (no folder-ipns key)
    expect(subA1?.writable).toBe(true);
  });

  it('skips a node that has no keyType:folder entry in share_keys', async () => {
    seedSharedFolder(client);

    const result = await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    const subC = result.find((n) => n.id === SUB_C_IPNS);
    expect(subC).toBeUndefined();
  });

  it('does not loop on a cyclic ipnsName (visited set guard)', async () => {
    // Make subA's children contain a ref with the same ipnsName as subA (cycle)
    const cyclicRef: SealedChildRef = makeRef('CyclicFolder', SUB_A_IPNS);

    vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async (p) => {
      if (p.ipnsName === SUB_A_IPNS) {
        return {
          metadata: { children: [cyclicRef] } as never,
          sequenceNumber: 2n,
          cid: 'bafysuba',
        };
      }
      return { metadata: { children: [] } as never, sequenceNumber: 1n, cid: 'bafyempty' };
    });

    seedSharedFolder(client);

    // Should complete without infinite loop (the visited guard for SUB_A_IPNS prevents re-visiting)
    const result = await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    // subA itself is returned, but the cyclic re-occurrence is deduplicated
    const subAOccurrences = result.filter((n) => n.ipnsName === SUB_A_IPNS);
    expect(subAOccurrences).toHaveLength(1);
  });

  it('returns correct ipnsName and name for each node', async () => {
    seedSharedFolder(client);

    const result = await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    const subA = result.find((n) => n.id === SUB_A_IPNS)!;
    expect(subA.name).toBe(SUB_A_NAME);
    expect(subA.ipnsName).toBe(SUB_A_IPNS);
    // Root-level subfolder → no parent id (used by the move-cycle guard).
    expect(subA.parentId).toBeNull();

    const subA1 = result.find((n) => n.id === SUB_A1_IPNS)!;
    expect(subA1.name).toBe(SUB_A1_NAME);
    expect(subA1.ipnsName).toBe(SUB_A1_IPNS);
    // Nested subfolder → parentId points at containing folder's ipnsName.
    expect(subA1.parentId).toBe(SUB_A_IPNS);
  });

  it('throws "Shared folder not loaded" when share is not seeded', async () => {
    await expect(
      client.enumerateSharedSubtree('nonexistent-share', {
        getShareKeysFn: async () => [],
        vaultPrivateKey: new Uint8Array(32).fill(0x99),
      })
    ).rejects.toThrow('Shared folder not loaded');
  });

  it('never calls .fill(0) on vaultPrivateKey (caller owns zeroing)', async () => {
    seedSharedFolder(client);
    const vaultPrivateKey = new Uint8Array(32).fill(0x99);

    await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey,
    });

    // vaultPrivateKey must NOT be zeroed by the method
    expect(vaultPrivateKey.every((b) => b === 0x99)).toBe(true);
  });

  it('zeros every per-iteration folderKey after use (no plaintext key left in heap)', async () => {
    seedSharedFolder(client);
    // Hand back a fresh buffer per unwrap so we can assert each is zeroed.
    const unwrapped: Uint8Array[] = [];
    vi.mocked(unwrapKey).mockImplementation(async () => {
      const k = new Uint8Array(32).fill(0xab);
      unwrapped.push(k);
      return k;
    });

    await client.enumerateSharedSubtree(SHARE_ID, {
      getShareKeysFn: async () => makeShareKeys(),
      vaultPrivateKey: new Uint8Array(32).fill(0x99),
    });

    expect(unwrapped.length).toBeGreaterThan(0);
    for (const k of unwrapped) {
      expect(k.every((b) => b === 0)).toBe(true);
    }
  });
});
