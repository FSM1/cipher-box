import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import {
  renameInFolder,
  deleteFromFolder,
  addFilePointerToFolder,
  moveItem,
  updateFolderMetadataAndPublish,
} from '../folder';
import { isConflictExhausted } from '../errors';
import { createMockContext } from './helpers';

// ---------------------------------------------------------------------------
// Module mocks for updateFolderMetadataAndPublish tests
// vi.mock calls are hoisted to the top of the file by vitest.
// vi.hoisted() is hoisted before vi.mock() so its result is available in factories.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
  encryptFolderMetadata: vi.fn(),
  decryptFolderMetadata: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  generateEd25519Keypair: vi.fn(),
  deriveIpnsName: vi.fn(),
  deriveEd25519PublicKey: vi.fn().mockReturnValue(new Uint8Array(32).fill(7)),
  generateRandomBytes: vi.fn(),
  wrapKey: vi.fn(),
  bytesToHex: vi.fn(),
  hexToBytes: vi.fn(),
}));

vi.mock('@cipherbox/core', () => ({
  encryptFolderMetadata: mockFns.encryptFolderMetadata,
  decryptFolderMetadata: mockFns.decryptFolderMetadata,
  createIpnsRecord: vi.fn(),
  marshalIpnsRecord: vi.fn(),
}));

vi.mock('../ipfs', () => ({
  addToIpfs: mockFns.addToIpfs,
  fetchFromIpfs: mockFns.fetchFromIpfs,
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  batchPublishIpnsRecords: vi.fn(),
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
}));

// These tests cover the pure (synchronous) folder metadata operations.
// async operations (loadFolderMetadata, updateFolderMetadataAndPublish, createSubfolder)
// require mocking IPFS/IPNS and are covered in integration tests.

const makeFolder = (id: string, name: string): FolderEntry => ({
  type: 'folder',
  id,
  name,
  ipnsName: `k51-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  folderKeyEncrypted: 'encrypted-folder-key',
  createdAt: 1000,
  modifiedAt: 1000,
});

const makeFile = (id: string, name: string): FilePointer => ({
  type: 'file',
  id,
  name,
  fileMetaIpnsName: `k51-file-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  createdAt: 1000,
  modifiedAt: 1000,
});

describe('Folder operations', () => {
  describe('renameInFolder', () => {
    it('renames a child and updates modifiedAt', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents'), makeFile('f2', 'photo.jpg')];

      const result = renameInFolder({
        children,
        childId: 'f1',
        newName: 'My Documents',
      });

      expect(result.updatedChildren).toHaveLength(2);
      expect(result.renamedChild.name).toBe('My Documents');
      expect(result.renamedChild.modifiedAt).toBeGreaterThan(1000);
      // Original array not mutated
      expect(children[0].name).toBe('Documents');
    });

    it('throws when child not found', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents')];

      expect(() => renameInFolder({ children, childId: 'nonexistent', newName: 'New' })).toThrow(
        'Item not found'
      );
    });

    it('throws on name collision', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents'), makeFolder('f2', 'Photos')];

      expect(() => renameInFolder({ children, childId: 'f1', newName: 'Photos' })).toThrow(
        'An item with this name already exists'
      );
    });
  });

  describe('deleteFromFolder', () => {
    it('removes child and returns it', () => {
      const children: FolderChild[] = [
        makeFolder('f1', 'Documents'),
        makeFile('f2', 'photo.jpg'),
        makeFile('f3', 'video.mp4'),
      ];

      const result = deleteFromFolder({ children, childId: 'f2' });

      expect(result.updatedChildren).toHaveLength(2);
      expect(result.removedItem.id).toBe('f2');
      expect(result.removedItem.name).toBe('photo.jpg');
      expect(result.updatedChildren.find((c) => c.id === 'f2')).toBeUndefined();
    });

    it('throws when child not found', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents')];

      expect(() => deleteFromFolder({ children, childId: 'missing' })).toThrow('Item not found');
    });
  });

  describe('addFilePointerToFolder', () => {
    it('adds file pointer to children', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents')];

      const result = addFilePointerToFolder({
        children,
        fileId: 'file-1',
        fileName: 'readme.txt',
        fileMetaIpnsName: 'k51-file-meta',
        ipnsPrivateKeyEncrypted: 'wrapped-key',
      });

      expect(result.updatedChildren).toHaveLength(2);
      expect(result.filePointer.type).toBe('file');
      expect(result.filePointer.id).toBe('file-1');
      expect(result.filePointer.name).toBe('readme.txt');
      expect(result.filePointer.fileMetaIpnsName).toBe('k51-file-meta');
    });

    it('throws on name collision', () => {
      const children: FolderChild[] = [makeFile('f1', 'readme.txt')];

      expect(() =>
        addFilePointerToFolder({
          children,
          fileId: 'file-2',
          fileName: 'readme.txt',
          fileMetaIpnsName: 'k51-new',
          ipnsPrivateKeyEncrypted: 'key',
        })
      ).toThrow('A file with this name already exists');
    });
  });

  describe('moveItem', () => {
    it('moves item from source to destination', () => {
      const sourceChildren: FolderChild[] = [
        makeFolder('f1', 'Documents'),
        makeFile('f2', 'photo.jpg'),
      ];
      const destChildren: FolderChild[] = [makeFolder('f3', 'Archive')];

      const result = moveItem({
        sourceChildren,
        destChildren,
        childId: 'f2',
      });

      expect(result.updatedSourceChildren).toHaveLength(1);
      expect(result.updatedDestChildren).toHaveLength(2);
      expect(result.movedItem.name).toBe('photo.jpg');
      expect(result.movedItem.modifiedAt).toBeGreaterThan(1000);
    });

    it('throws when item not found in source', () => {
      expect(() =>
        moveItem({
          sourceChildren: [makeFolder('f1', 'Docs')],
          destChildren: [],
          childId: 'missing',
        })
      ).toThrow('Item not found');
    });

    it('throws on name collision in destination', () => {
      const sourceChildren: FolderChild[] = [makeFile('f1', 'readme.txt')];
      const destChildren: FolderChild[] = [makeFile('f2', 'readme.txt')];

      expect(() => moveItem({ sourceChildren, destChildren, childId: 'f1' })).toThrow(
        'An item with this name already exists in destination'
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Conflict handling tests for updateFolderMetadataAndPublish
// Uses the shared mockFns references wired into the vi.mock factories above.
// ---------------------------------------------------------------------------

/** Build a minimal remote metadata blob for fetchFromIpfs to return. */
function makeRemoteBlob(): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ iv: 'r', data: 'd' }));
}

describe('updateFolderMetadataAndPublish conflict handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmFreshCid' });
    mockFns.encryptFolderMetadata.mockResolvedValue({ iv: 'iv', data: 'data' });
  });

  it('merges remote children on 409 then republishes (no lost update)', async () => {
    const ctx = createMockContext();
    const localChild = makeFile('local-1', 'local-file.txt');
    const remoteChild = makeFile('remote-1', 'remote-file.txt');

    const conflictErr = Object.assign(new Error('conflict'), { status: 409 });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(conflictErr)
      .mockResolvedValueOnce({ success: true, sequenceNumber: '6', ipnsName: 'k51test' });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 5n,
      cid: 'QmRemoteCid',
      ipnsName: 'k51test',
    });

    mockFns.fetchFromIpfs.mockResolvedValue(makeRemoteBlob());

    mockFns.decryptFolderMetadata.mockResolvedValue({
      version: 'v2' as const,
      children: [remoteChild],
    });

    // Track what FolderMetadata is encrypted each attempt
    const encryptedMetas: unknown[] = [];
    mockFns.encryptFolderMetadata.mockImplementation(async (meta: unknown) => {
      encryptedMetas.push(meta);
      return { iv: 'iv', data: 'data' };
    });

    const result = await updateFolderMetadataAndPublish({
      children: [localChild],
      baseChildren: [],
      folderKey: new Uint8Array(32).fill(1),
      ipnsPrivateKey: new Uint8Array(64).fill(2),
      ipnsName: 'k51test',
      sequenceNumber: 4n,
      ctx,
    });

    expect(result.cid).toBe('QmFreshCid');
    expect(result.newSequenceNumber).toBe(6n);

    // Second encrypt call must include BOTH local and remote children (merged, no lost update)
    expect(encryptedMetas).toHaveLength(2);
    const secondMeta = encryptedMetas[1] as { version: string; children: FolderChild[] };
    const childIds = secondMeta.children.map((c: FolderChild) => c.id);
    expect(childIds).toContain('local-1');
    expect(childIds).toContain('remote-1');
  });

  it('logs a union-fallback warning when baseChildren omitted', async () => {
    const ctx = createMockContext();
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const conflictErr = Object.assign(new Error('conflict'), { status: 409 });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(conflictErr)
      .mockResolvedValueOnce({ success: true, sequenceNumber: '2', ipnsName: 'k51warn' });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 1n,
      cid: 'QmRemote',
      ipnsName: 'k51warn',
    });

    mockFns.fetchFromIpfs.mockResolvedValue(makeRemoteBlob());
    mockFns.decryptFolderMetadata.mockResolvedValue({ version: 'v2' as const, children: [] });

    await updateFolderMetadataAndPublish({
      children: [makeFile('f1', 'test.txt')],
      // baseChildren intentionally omitted to trigger union fallback (D-02)
      folderKey: new Uint8Array(32),
      ipnsPrivateKey: new Uint8Array(64),
      ipnsName: 'k51warn',
      sequenceNumber: 0n,
      ctx,
    });

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('baseChildren not provided'));

    warnSpy.mockRestore();
  });

  it('throws ConflictError after 4 failed attempts', async () => {
    const ctx = createMockContext();

    const conflictErr = Object.assign(new Error('conflict'), { status: 409 });
    mockFns.createAndPublishIpnsRecord.mockRejectedValue(conflictErr);

    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 10n,
      cid: 'QmAlwaysConflict',
      ipnsName: 'k51exhaust',
    });

    mockFns.fetchFromIpfs.mockResolvedValue(makeRemoteBlob());
    mockFns.decryptFolderMetadata.mockResolvedValue({ version: 'v2' as const, children: [] });

    await expect(
      updateFolderMetadataAndPublish({
        children: [makeFile('f1', 'file.txt')],
        baseChildren: [],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51exhaust',
        sequenceNumber: 9n,
        ctx,
      })
    ).rejects.toSatisfy((err: unknown) => {
      return isConflictExhausted(err) && err.attempts === 4 && err.ipnsName === 'k51exhaust';
    });
  });

  it('does not throw ConflictError for non-409 errors', async () => {
    const ctx = createMockContext();

    const serverErr = Object.assign(new Error('Internal Server Error'), { status: 500 });
    mockFns.createAndPublishIpnsRecord.mockRejectedValue(serverErr);

    await expect(
      updateFolderMetadataAndPublish({
        children: [makeFile('f1', 'file.txt')],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51nonconflict',
        sequenceNumber: 0n,
        ctx,
      })
    ).rejects.toSatisfy((err: unknown) => {
      return !isConflictExhausted(err) && (err as Error).message === 'Internal Server Error';
    });
  });

  it('returns publishedChildren containing merged local+remote set after 409 (WR-08 folder)', async () => {
    // Tests CR-01: the published merged children must be surfaced to callers so
    // the next write composes from the correct base, not the stale pre-merge local set.
    // Non-empty baseChildren exercises the three-way merge path (WR-08).
    const ctx = createMockContext();
    const baseChild = makeFile('base-1', 'base-file.txt');
    const localChild = makeFile('local-2', 'local-file.txt');
    const remoteChild = makeFile('remote-3', 'remote-file.txt');

    const conflictErr = Object.assign(new Error('conflict'), { status: 409 });
    mockFns.createAndPublishIpnsRecord
      .mockRejectedValueOnce(conflictErr)
      .mockResolvedValueOnce({ success: true, sequenceNumber: '8', ipnsName: 'k51merged' });

    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 7n,
      cid: 'QmRemoteMerged',
      ipnsName: 'k51merged',
    });

    mockFns.fetchFromIpfs.mockResolvedValue(makeRemoteBlob());
    // Remote folder already has baseChild + remoteChild (remote-only child not in local set)
    mockFns.decryptFolderMetadata.mockResolvedValue({
      version: 'v2' as const,
      children: [baseChild, remoteChild],
    });

    const result = await updateFolderMetadataAndPublish({
      children: [baseChild, localChild],
      // Non-empty baseChildren — exercises three-way merge (WR-08)
      baseChildren: [baseChild],
      folderKey: new Uint8Array(32).fill(1),
      ipnsPrivateKey: new Uint8Array(64).fill(2),
      ipnsName: 'k51merged',
      sequenceNumber: 6n,
      ctx,
    });

    // publishedChildren must be the merged published set, not the stale pre-merge local set
    expect(result.publishedChildren).toBeDefined();
    const publishedIds = result.publishedChildren.map((c: FolderChild) => c.id);
    // Local-only child must survive the merge
    expect(publishedIds).toContain('local-2');
    // Remote-only child must be included (proves three-way merge ran, not a local-only publish)
    expect(publishedIds).toContain('remote-3');
  });
});

// ---------------------------------------------------------------------------
// S3 zeroization guard for updateFolderMetadataAndPublish (D-05 / T-47-01)
//
// Decision: SKIP zeroing — caller retains ownership of keys (see folder/index.ts comment).
// Guard test: assert keys are UNCHANGED after the call returns, documenting the deliberate
// non-zeroing and preventing accidental future fill(0) from breaking live-session callers.
// ---------------------------------------------------------------------------

describe('updateFolderMetadataAndPublish zeroization decision guard (S3/D-05)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmGuardCid' });
    mockFns.encryptFolderMetadata.mockResolvedValue({ iv: 'iv', data: 'data' });
  });

  it('SKIP guard: does NOT zero ipnsPrivateKey or folderKey (caller retains ownership)', async () => {
    const ctx = createMockContext();

    // Use distinctly non-zero buffers so zeroing would be detectable
    const ipnsKey = new Uint8Array(64).fill(0x77);
    const folderKey = new Uint8Array(32).fill(0x88);

    // Snapshot initial values to compare after the call
    const ipnsKeySnapshot = new Uint8Array(ipnsKey);
    const folderKeySnapshot = new Uint8Array(folderKey);

    mockFns.createAndPublishIpnsRecord.mockResolvedValueOnce({
      success: true,
      sequenceNumber: 1n,
      ipnsName: 'k51guard',
    });

    await updateFolderMetadataAndPublish({
      children: [],
      baseChildren: [],
      folderKey,
      ipnsPrivateKey: ipnsKey,
      ipnsName: 'k51guard',
      sequenceNumber: 0n,
      ctx,
    });

    // Keys must be UNCHANGED — caller (sdk/client.ts) stores them in live folderTree state
    // and reuses them across subsequent operations. Zeroing here would corrupt session state.
    expect(ipnsKey).toEqual(ipnsKeySnapshot);
    expect(folderKey).toEqual(folderKeySnapshot);
  });
});
