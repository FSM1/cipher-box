/**
 * moveItem descendant enumeration (D-12) — depth-2+ walk regression.
 *
 * Guards the zeroization ORDER inside enumerateMoveDescendants: a non-root
 * node's readKey is the AAD-bearing parent key for its own children, so it
 * must stay intact through the children loop and be zeroed only afterwards
 * (terminal-owner rule). Zeroing it in the unseal try/finally made every
 * depth-2+ descendant unseal against an all-zero key and misclassified the
 * whole sub-subtree as unreadable (false D-12 warnings).
 *
 * The @cipherbox/core mock below enforces the key-liveness contract the real
 * AEAD provides: unsealing with an all-zero parent key throws.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig, setupFolder } from './helpers';

vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x55)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(hex.length / 2)),
}));

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    loadFolderMetadata: vi.fn(),
    updateFolderMetadataAndPublish: vi.fn(),
    renameInFolder: vi.fn(),
    deleteFromFolder: vi.fn(),
    moveItem: vi.fn(),
    resolveIpnsRecord: vi.fn(),
    fetchFromIpfs: vi.fn(),
    rotateReadFromNode: vi.fn(),
  };
});

vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    sealChildReadKey: vi.fn().mockResolvedValue('resealed-dest-hex'),
    unsealChildReadKey: vi.fn(async (readKeySealed: string, parentReadKey: Uint8Array) => {
      if (parentReadKey.every((b) => b === 0)) {
        throw new Error('AEAD failure: unseal attempted with a zeroed parent readKey');
      }
      if (readKeySealed === 'sealed-broken') {
        throw new Error('AEAD failure: corrupt sealed blob');
      }
      return new Uint8Array(32).fill(0x42);
    }),
    unsealNode: vi.fn(),
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

vi.mock('../share', () => ({
  createShareKey: vi.fn(),
  revokeShare: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';
import { unsealNode } from '@cipherbox/core';

const SRC_IPNS = 'src-ipns';
const DEST_IPNS = 'dest-ipns';
const MOVED_IPNS = 'k51moved';
const DEPTH1_IPNS = 'k51depth1';
const DEPTH2_IPNS = 'k51depth2';

/**
 * Wire a moved-FOLDER subtree: moved folder → depth-1 subfolder → depth-2 file.
 * `depth2Sealed` lets the control test hand the grandchild a corrupt blob.
 */
function setupMovedFolderTree(depth2Sealed = 'sealed-g') {
  vi.mocked(sdkCore.moveItem).mockReturnValue({
    updatedSource: [],
    updatedDest: [
      {
        name: 'moved-folder',
        ipnsName: MOVED_IPNS,
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'sealed-moved',
      },
    ],
    movedRef: {
      name: 'moved-folder',
      ipnsName: MOVED_IPNS,
      generation: 0,
      versionFloor: 0n,
      readKeySealed: 'sealed-moved',
    },
  });

  vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => ({
    cid: `cid-${ipnsName}`,
    sequenceNumber: 1n,
    signatureVerified: true,
  }));

  const publishedById: Record<string, { id: string; kind: string }> = {
    [`cid-${MOVED_IPNS}`]: { id: 'moved-id', kind: 'folder' },
    [`cid-${DEPTH1_IPNS}`]: { id: 'depth1-id', kind: 'folder' },
    [`cid-${DEPTH2_IPNS}`]: { id: 'depth2-id', kind: 'file' },
  };
  vi.mocked(sdkCore.fetchFromIpfs).mockImplementation(async (_ctx, cid: string) => {
    const published = publishedById[cid];
    if (!published) throw new Error(`unexpected cid ${cid}`);
    return new TextEncoder().encode(JSON.stringify(published));
  });

  const childrenById: Record<string, unknown[]> = {
    'moved-id': [
      {
        name: 'depth1',
        ipnsName: DEPTH1_IPNS,
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'sealed-c1',
      },
    ],
    'depth1-id': [
      {
        name: 'depth2',
        ipnsName: DEPTH2_IPNS,
        generation: 0,
        versionFloor: 0n,
        readKeySealed: depth2Sealed,
      },
    ],
    'depth2-id': [],
  };
  vi.mocked(unsealNode).mockImplementation(
    async (published: { id: string }) => ({ children: childrenById[published.id] ?? [] }) as never
  );

  vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
    cid: 'bafynew',
    newSequenceNumber: 2n,
    publishedChildren: [],
  });
}

describe('moveItem — D-12 descendant enumeration walks past depth 1', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it('unseals depth-2 descendants with the still-live depth-1 key (no false D-12 unreadable)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS);
    setupFolder(client, DEST_IPNS);
    setupMovedFolderTree();

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'file1');

    // The walk is fire-and-forget; wait until it has dequeued the depth-2 node.
    await vi.waitFor(() => {
      const unsealedIds = vi.mocked(unsealNode).mock.calls.map(([p]) => (p as { id: string }).id);
      expect(unsealedIds).toContain('depth2-id');
    });

    const d12Warnings = warnSpy.mock.calls.filter((call) =>
      String(call[0]).includes('could not be read after move')
    );
    expect(d12Warnings).toEqual([]);
  });

  it('still reports a genuinely unreadable descendant via the D-12 warning (control)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS);
    setupFolder(client, DEST_IPNS);
    setupMovedFolderTree('sealed-broken');

    await client.moveItem(SRC_IPNS, DEST_IPNS, 'file1');

    await vi.waitFor(() => {
      const d12Warnings = warnSpy.mock.calls.filter((call) =>
        String(call[0]).includes('could not be read after move')
      );
      expect(d12Warnings).toHaveLength(1);
      expect(d12Warnings[0]?.[1]).toEqual([DEPTH2_IPNS]);
    });
  });
});
