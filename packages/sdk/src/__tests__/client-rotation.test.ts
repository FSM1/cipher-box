/**
 * TDD tests for Phase 68 Plan 05: scope-exit read-key rotation and
 * reconcile-before-publish wiring at the SDK client chokepoint (client.ts).
 *
 * Covers:
 *  - Task 1: ReconcileStaleError / reconcile-before-publish (SC#3 / D-04)
 *  - Task 2: maybeRotateOnScopeExit wiring + injection seam (SC#2 / SC#4)
 *  - Task 3: moveItem dest-before-source publish ordering (D-12)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient, ReconcileStaleError } from '../client';
import { createTestConfig, setupFolder } from './helpers';

// ── crypto mock ──────────────────────────────────────────────────────────
vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(64).fill(0x55)),
  hexToBytes: vi.fn((hex: string) => new Uint8Array(hex.length / 2)),
}));

// ── sdk-core mock ────────────────────────────────────────────────────────
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

// ── @cipherbox/core mock (moveItem's FLAG-63-U2 re-seal) ────────────────
vi.mock('@cipherbox/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/core')>();
  return {
    ...actual,
    sealChildReadKey: vi.fn().mockResolvedValue('resealed-dest-hex'),
    unsealChildReadKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0x42)),
  };
});

// ── bin / share mocks (not under test, silence missing-module errors) ────
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
import * as binOps from '../bin';

const FOLDER_IPNS = 'folder-ipns';
const SRC_IPNS = 'src-ipns';
const DEST_IPNS = 'dest-ipns';

/** Mock resolveIpnsRecord to return a matching sequenceNumber for every call. */
function mockResolveMatching(sequenceNumber: bigint) {
  vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({
    cid: 'bafyresolved',
    sequenceNumber,
    signatureVerified: true,
  });
}

describe('CipherBoxClient — reconcile-before-publish (SC#3 / D-04, Task 1)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('ReconcileStaleError is instanceof-distinguishable with a stable name', () => {
    const err = new ReconcileStaleError('k51x', 1n, 2n);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('ReconcileStaleError');
  });

  it('renameItem defers with ReconcileStaleError when the network sequence is AHEAD of the in-memory entry', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(2n); // network ahead of local (1n)

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
    expect(sdkCore.rotateReadFromNode).not.toHaveBeenCalled();
  });

  it('renameItem defers with ReconcileStaleError when the LOCAL entry is ahead of the network', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(0n); // network behind local (1n)

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('renameItem proceeds to publish when the sequences agree', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    mockResolveMatching(1n); // agrees
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('renameItem proceeds when resolveIpnsRecord returns null (no record to reconcile against)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.renameInFolder).mockReturnValue({
      updatedChildren: [],
      renamedChild: {} as never,
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue(null);
    vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
      cid: 'bafynew',
      newSequenceNumber: 2n,
      publishedChildren: [],
    });

    await expect(client.renameItem(FOLDER_IPNS, 'file1', 'new.txt')).resolves.toBeUndefined();
    expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalledTimes(1);
  });

  it('deleteItem defers with ReconcileStaleError on sequence mismatch', async () => {
    const client = new CipherBoxClient(createTestConfig());
    const child = setupFolder(client, FOLDER_IPNS);
    vi.mocked(sdkCore.deleteFromFolder).mockReturnValue({
      updatedChildren: [],
      removedItem: child,
    });
    mockResolveMatching(5n);

    await expect(client.deleteItem(FOLDER_IPNS, 'file1')).rejects.toThrow(ReconcileStaleError);
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('deleteToBin defers with ReconcileStaleError on sequence mismatch (before addToBin publishes)', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, FOLDER_IPNS);
    vi.mocked(binOps.loadBin).mockResolvedValue({
      entries: [],
      sequenceNumber: 0,
      ipnsName: 'k51bin',
    });
    mockResolveMatching(9n);

    await expect(client.deleteToBin(FOLDER_IPNS, 'file1', 'My Vault')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(binOps.addToBin).not.toHaveBeenCalled();
  });

  it('moveItem defers with ReconcileStaleError when the SOURCE folder sequence mismatches', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS); // sequenceNumber: 1n
    setupFolder(client, DEST_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === SRC_IPNS) return { cid: 'x', sequenceNumber: 99n, signatureVerified: true };
      return { cid: 'x', sequenceNumber: 1n, signatureVerified: true };
    });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, 'file1')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });

  it('moveItem defers with ReconcileStaleError when the DEST folder sequence mismatches', async () => {
    const client = new CipherBoxClient(createTestConfig());
    setupFolder(client, SRC_IPNS); // sequenceNumber: 1n
    setupFolder(client, DEST_IPNS); // sequenceNumber: 1n
    vi.mocked(sdkCore.moveItem).mockReturnValue({
      updatedSource: [],
      updatedDest: [],
      movedRef: {
        name: 'x',
        ipnsName: 'k51file',
        generation: 0,
        versionFloor: 0n,
        readKeySealed: 'x',
      },
    });
    vi.mocked(sdkCore.resolveIpnsRecord).mockImplementation(async (ipnsName: string) => {
      if (ipnsName === DEST_IPNS) return { cid: 'x', sequenceNumber: 99n, signatureVerified: true };
      return { cid: 'x', sequenceNumber: 1n, signatureVerified: true };
    });

    await expect(client.moveItem(SRC_IPNS, DEST_IPNS, 'file1')).rejects.toThrow(
      ReconcileStaleError
    );
    expect(sdkCore.updateFolderMetadataAndPublish).not.toHaveBeenCalled();
  });
});
