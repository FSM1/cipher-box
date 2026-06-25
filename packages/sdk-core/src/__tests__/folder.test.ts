import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import {
  renameInFolder,
  deleteFromFolder,
  addFilePointerToFolder,
  moveItem,
  updateFolderMetadataAndPublish,
  loadFolderMetadata,
  fetchAndDecryptMetadata,
  createSubfolder,
  addFileToFolder,
  addFilesToFolder,
  replaceFileInFolder,
} from '../folder';
import type { FileIpnsRecordPayload } from '../file';
import type { TeeKeys } from '../types';
import { isConflictExhausted } from '../errors';
import { createMockContext } from './helpers';

// ---------------------------------------------------------------------------
// Module mocks for updateFolderMetadataAndPublish tests
// vi.mock calls are hoisted to the top of the file by vitest.
// vi.hoisted() is hoisted before vi.mock() so its result is available in factories.
// ---------------------------------------------------------------------------

const mockFns = vi.hoisted(() => ({
  createAndPublishIpnsRecord: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
  encryptFolderMetadata: vi.fn(),
  decryptFolderMetadata: vi.fn(),
  createIpnsRecord: vi.fn(),
  marshalIpnsRecord: vi.fn(),
  generateEd25519Keypair: vi.fn(),
  deriveIpnsName: vi.fn(),
  generateRandomBytes: vi.fn(),
  wrapKey: vi.fn(),
  bytesToHex: vi.fn(),
  hexToBytes: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  generateEd25519Keypair: mockFns.generateEd25519Keypair,
  deriveIpnsName: mockFns.deriveIpnsName,
  deriveEd25519PublicKey: vi.fn().mockReturnValue(new Uint8Array(32).fill(7)),
  generateRandomBytes: mockFns.generateRandomBytes,
  wrapKey: mockFns.wrapKey,
  bytesToHex: mockFns.bytesToHex,
  hexToBytes: mockFns.hexToBytes,
}));

vi.mock('@cipherbox/core', () => ({
  encryptFolderMetadata: mockFns.encryptFolderMetadata,
  decryptFolderMetadata: mockFns.decryptFolderMetadata,
  createIpnsRecord: mockFns.createIpnsRecord,
  marshalIpnsRecord: mockFns.marshalIpnsRecord,
}));

vi.mock('../ipfs', () => ({
  addToIpfs: mockFns.addToIpfs,
  fetchFromIpfs: mockFns.fetchFromIpfs,
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  batchPublishIpnsRecords: mockFns.batchPublishIpnsRecords,
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

// ---------------------------------------------------------------------------
// load.ts — fetchAndDecryptMetadata + loadFolderMetadata
// fetchFromIpfs / resolveIpnsRecord / decryptFolderMetadata are mocked above.
// ---------------------------------------------------------------------------

describe('fetchAndDecryptMetadata', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches the encrypted blob, JSON-parses it, and decrypts with the folder key', async () => {
    const ctx = createMockContext();
    const folderKey = new Uint8Array(32).fill(9);
    const encryptedBlob = { iv: 'the-iv', data: 'the-data' };
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(encryptedBlob))
    );
    const decrypted = { version: 'v2' as const, children: [makeFile('x', 'a.txt')] };
    mockFns.decryptFolderMetadata.mockResolvedValue(decrypted);

    const result = await fetchAndDecryptMetadata('QmCid123', folderKey, ctx);

    expect(mockFns.fetchFromIpfs).toHaveBeenCalledWith(ctx, 'QmCid123');
    // The parsed encrypted object and the folder key must be passed to decrypt
    expect(mockFns.decryptFolderMetadata).toHaveBeenCalledWith(encryptedBlob, folderKey);
    expect(result).toBe(decrypted);
  });
});

describe('loadFolderMetadata', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns null when IPNS resolution finds no record', async () => {
    const ctx = createMockContext();
    mockFns.resolveIpnsRecord.mockResolvedValue(null);

    const result = await loadFolderMetadata({
      ipnsName: 'k51missing',
      folderKey: new Uint8Array(32),
      ctx,
    });

    expect(result).toBeNull();
    // Must short-circuit before attempting an IPFS fetch
    expect(mockFns.fetchFromIpfs).not.toHaveBeenCalled();
  });

  it('resolves IPNS, fetches+decrypts, and surfaces metadata, sequenceNumber and cid', async () => {
    const ctx = createMockContext();
    const folderKey = new Uint8Array(32).fill(3);
    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 42n,
      cid: 'QmResolved',
      ipnsName: 'k51found',
    });
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify({ iv: 'i', data: 'd' }))
    );
    const metadata = { version: 'v2' as const, children: [makeFolder('sub', 'Sub')] };
    mockFns.decryptFolderMetadata.mockResolvedValue(metadata);

    const result = await loadFolderMetadata({ ipnsName: 'k51found', folderKey, ctx });

    expect(mockFns.resolveIpnsRecord).toHaveBeenCalledWith('k51found', ctx);
    expect(mockFns.fetchFromIpfs).toHaveBeenCalledWith(ctx, 'QmResolved');
    expect(result).toEqual({ metadata, sequenceNumber: 42n, cid: 'QmResolved' });
  });
});

// ---------------------------------------------------------------------------
// registration.ts — createSubfolder
// crypto primitives are mocked above; we assert the wrapped-key wiring and the
// shape of the returned FolderEntry + decrypted keys.
// ---------------------------------------------------------------------------

describe('createSubfolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Deterministic crypto stubs
    mockFns.generateEd25519Keypair.mockResolvedValue({
      publicKey: new Uint8Array(32).fill(1),
      privateKey: new Uint8Array(64).fill(2),
    });
    mockFns.deriveIpnsName.mockResolvedValue('k51-derived-name');
    mockFns.generateRandomBytes.mockReturnValue(new Uint8Array(32).fill(3));
    // wrapKey returns a tagged buffer; bytesToHex turns it into a stable hex token
    mockFns.wrapKey.mockImplementation(async (key: Uint8Array) => key);
    mockFns.bytesToHex.mockReturnValue('hex-wrapped');
    mockFns.hexToBytes.mockReturnValue(new Uint8Array(32).fill(8));
  });

  it('generates keys, derives the ipnsName, and builds a folder entry without TEE keys', async () => {
    const userPublicKey = new Uint8Array(32).fill(5);

    const result = await createSubfolder({ name: 'NewFolder', userPublicKey });

    expect(mockFns.generateEd25519Keypair).toHaveBeenCalled();
    // deriveIpnsName is called with the generated keypair public key
    expect(mockFns.deriveIpnsName).toHaveBeenCalledWith(new Uint8Array(32).fill(1));
    expect(result.folder.type).toBe('folder');
    expect(result.folder.name).toBe('NewFolder');
    expect(result.folder.ipnsName).toBe('k51-derived-name');
    expect(result.folder.ipnsPrivateKeyEncrypted).toBe('hex-wrapped');
    expect(result.folder.folderKeyEncrypted).toBe('hex-wrapped');
    expect(typeof result.folder.id).toBe('string');
    // Decrypted keys returned to caller
    expect(result.folderKey).toEqual(new Uint8Array(32).fill(3));
    expect(result.ipnsPrivateKey).toEqual(new Uint8Array(64).fill(2));
    // No TEE keys → no encrypted republish key / epoch
    expect(result.encryptedIpnsPrivateKey).toBeUndefined();
    expect(result.keyEpoch).toBeUndefined();
    // The user public key must be used to wrap both private/folder keys
    expect(mockFns.wrapKey).toHaveBeenCalledWith(expect.anything(), userPublicKey);
  });

  it('encrypts the IPNS private key for the TEE when teeKeys are provided', async () => {
    const userPublicKey = new Uint8Array(32).fill(5);
    const teeKeys: TeeKeys = { currentPublicKey: 'aabbcc', currentEpoch: 7 };

    const result = await createSubfolder({ name: 'TeeFolder', userPublicKey, teeKeys });

    expect(mockFns.hexToBytes).toHaveBeenCalledWith('aabbcc');
    expect(result.encryptedIpnsPrivateKey).toBe('hex-wrapped');
    expect(result.keyEpoch).toBe(7);
  });

  it('zeros key material and rethrows if TEE wrapping fails', async () => {
    const userPublicKey = new Uint8Array(32).fill(5);
    const teeKeys: TeeKeys = { currentPublicKey: 'deadbeef', currentEpoch: 1 };

    // First two wrapKey calls succeed (private + folder key for user pubkey),
    // the third (TEE wrap) rejects → triggers the catch/zero branch.
    const ipnsPriv = new Uint8Array(64).fill(2);
    const folderKey = new Uint8Array(32).fill(3);
    mockFns.generateEd25519Keypair.mockResolvedValue({
      publicKey: new Uint8Array(32).fill(1),
      privateKey: ipnsPriv,
    });
    mockFns.generateRandomBytes.mockReturnValue(folderKey);
    mockFns.wrapKey
      .mockResolvedValueOnce(new Uint8Array([1]))
      .mockResolvedValueOnce(new Uint8Array([2]))
      .mockRejectedValueOnce(new Error('tee wrap failed'));

    await expect(createSubfolder({ name: 'Boom', userPublicKey, teeKeys })).rejects.toThrow(
      'tee wrap failed'
    );

    // Both buffers must be zeroed on the error path
    expect(ipnsPriv.every((b) => b === 0)).toBe(true);
    expect(folderKey.every((b) => b === 0)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// registration.ts — addFileToFolder / addFilesToFolder / replaceFileInFolder
// These drive buildFolderIpnsRecord + batchPublishIpnsRecords.
// ---------------------------------------------------------------------------

const makeFileIpnsRecord = (ipnsName: string): FileIpnsRecordPayload => ({
  ipnsName,
  recordBase64: 'cmVjb3Jk',
  publicKey: 'cHVi',
  metadataCid: `Qm-${ipnsName}`,
});

describe('addFileToFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.encryptFolderMetadata.mockResolvedValue({ iv: 'iv', data: 'data' });
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmFolderBlob' });
    mockFns.createIpnsRecord.mockResolvedValue({ signed: true });
    mockFns.marshalIpnsRecord.mockReturnValue(new Uint8Array([1, 2, 3]));
    mockFns.batchPublishIpnsRecords.mockResolvedValue({ totalFailed: 0, results: [] });
  });

  it('creates a file pointer, builds the folder record, and batch-publishes file+folder', async () => {
    const ctx = createMockContext();
    const fileIpnsRecord = makeFileIpnsRecord('k51-file-aaa');

    const result = await addFileToFolder({
      children: [makeFolder('f1', 'Docs')],
      folderKey: new Uint8Array(32).fill(1),
      ipnsPrivateKey: new Uint8Array(64).fill(2),
      ipnsName: 'k51-parent',
      sequenceNumber: 4n,
      fileId: 'file-new',
      name: 'doc.pdf',
      fileIpnsRecord,
      ipnsPrivateKeyEncrypted: 'wrapped',
      ctx,
    });

    expect(result.filePointer.id).toBe('file-new');
    expect(result.filePointer.name).toBe('doc.pdf');
    expect(result.filePointer.fileMetaIpnsName).toBe('k51-file-aaa');
    // buildFolderIpnsRecord increments the sequence number by one
    expect(result.newSequenceNumber).toBe(5n);

    // Batch publish must include both the file record and the folder record.
    // The folder record carries expectedSequenceNumber (CAS); file records do not.
    const published = mockFns.batchPublishIpnsRecords.mock.calls[0][0];
    expect(published).toHaveLength(2);
    expect(published[0].expectedSequenceNumber).toBeUndefined();
    expect(published[1].expectedSequenceNumber).toBe('4');
  });

  it('throws on name collision and never publishes', async () => {
    const ctx = createMockContext();
    await expect(
      addFileToFolder({
        children: [makeFile('f1', 'doc.pdf')],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51-parent',
        sequenceNumber: 0n,
        fileId: 'file-2',
        name: 'doc.pdf',
        fileIpnsRecord: makeFileIpnsRecord('k51-file-bbb'),
        ipnsPrivateKeyEncrypted: 'wrapped',
        ctx,
      })
    ).rejects.toThrow('A file with this name already exists');
    expect(mockFns.batchPublishIpnsRecords).not.toHaveBeenCalled();
  });

  it('throws when the batch publish reports failures', async () => {
    const ctx = createMockContext();
    mockFns.batchPublishIpnsRecords.mockResolvedValue({ totalFailed: 1, results: [] });

    await expect(
      addFileToFolder({
        children: [],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51-parent',
        sequenceNumber: 0n,
        fileId: 'file-3',
        name: 'x.txt',
        fileIpnsRecord: makeFileIpnsRecord('k51-file-ccc'),
        ipnsPrivateKeyEncrypted: 'wrapped',
        ctx,
      })
    ).rejects.toThrow('Failed to publish one or more IPNS records');
  });
});

describe('addFilesToFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.encryptFolderMetadata.mockResolvedValue({ iv: 'iv', data: 'data' });
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmFolderBlob' });
    mockFns.createIpnsRecord.mockResolvedValue({ signed: true });
    mockFns.marshalIpnsRecord.mockReturnValue(new Uint8Array([1, 2, 3]));
    mockFns.batchPublishIpnsRecords.mockResolvedValue({ totalFailed: 0, results: [] });
  });

  it('creates N file pointers and publishes N file records + 1 folder record', async () => {
    const ctx = createMockContext();

    const result = await addFilesToFolder({
      children: [makeFolder('f1', 'Docs')],
      folderKey: new Uint8Array(32).fill(1),
      ipnsPrivateKey: new Uint8Array(64).fill(2),
      ipnsName: 'k51-parent',
      sequenceNumber: 10n,
      files: [
        {
          fileId: 'a',
          name: 'a.txt',
          fileIpnsRecord: makeFileIpnsRecord('k51-a'),
          ipnsPrivateKeyEncrypted: 'wa',
        },
        {
          fileId: 'b',
          name: 'b.txt',
          fileIpnsRecord: makeFileIpnsRecord('k51-b'),
          ipnsPrivateKeyEncrypted: 'wb',
        },
      ],
      ctx,
    });

    expect(result.filePointers).toHaveLength(2);
    expect(result.filePointers.map((p) => p.name)).toEqual(['a.txt', 'b.txt']);
    expect(result.newSequenceNumber).toBe(11n);

    const published = mockFns.batchPublishIpnsRecords.mock.calls[0][0];
    expect(published).toHaveLength(3); // 2 files + 1 folder
    // File records come first (no CAS sequence), the folder record is last.
    expect(
      published.filter((r: { expectedSequenceNumber?: string }) => r.expectedSequenceNumber)
    ).toHaveLength(1);
    expect(published[2].expectedSequenceNumber).toBe('10');
  });

  it('throws when two of the incoming files share a name', async () => {
    const ctx = createMockContext();
    await expect(
      addFilesToFolder({
        children: [],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51-parent',
        sequenceNumber: 0n,
        files: [
          {
            fileId: 'a',
            name: 'dup.txt',
            fileIpnsRecord: makeFileIpnsRecord('k51-a'),
            ipnsPrivateKeyEncrypted: 'wa',
          },
          {
            fileId: 'b',
            name: 'dup.txt',
            fileIpnsRecord: makeFileIpnsRecord('k51-b'),
            ipnsPrivateKeyEncrypted: 'wb',
          },
        ],
        ctx,
      })
    ).rejects.toThrow('A file with name "dup.txt" already exists');
    expect(mockFns.batchPublishIpnsRecords).not.toHaveBeenCalled();
  });

  it('throws when an incoming file collides with an existing child', async () => {
    const ctx = createMockContext();
    await expect(
      addFilesToFolder({
        children: [makeFile('existing', 'taken.txt')],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51-parent',
        sequenceNumber: 0n,
        files: [
          {
            fileId: 'a',
            name: 'taken.txt',
            fileIpnsRecord: makeFileIpnsRecord('k51-a'),
            ipnsPrivateKeyEncrypted: 'wa',
          },
        ],
        ctx,
      })
    ).rejects.toThrow('A file with name "taken.txt" already exists');
  });

  it('throws when the batch publish reports failures', async () => {
    const ctx = createMockContext();
    mockFns.batchPublishIpnsRecords.mockResolvedValue({ totalFailed: 2, results: [] });

    await expect(
      addFilesToFolder({
        children: [],
        folderKey: new Uint8Array(32),
        ipnsPrivateKey: new Uint8Array(64),
        ipnsName: 'k51-parent',
        sequenceNumber: 0n,
        files: [
          {
            fileId: 'a',
            name: 'a.txt',
            fileIpnsRecord: makeFileIpnsRecord('k51-a'),
            ipnsPrivateKeyEncrypted: 'wa',
          },
        ],
        ctx,
      })
    ).rejects.toThrow('Failed to publish one or more IPNS records');
  });
});

describe('replaceFileInFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.batchPublishIpnsRecords.mockResolvedValue({ totalFailed: 0, results: [] });
  });

  it('publishes ONLY the file record (folder metadata untouched) when the file exists', async () => {
    const ctx = createMockContext();
    const fileIpnsRecord = makeFileIpnsRecord('k51-file-existing');

    await replaceFileInFolder({
      children: [makeFile('file-1', 'report.pdf'), makeFolder('f2', 'Docs')],
      fileId: 'file-1',
      fileIpnsRecord,
      ctx,
    });

    const published = mockFns.batchPublishIpnsRecords.mock.calls[0][0];
    expect(published).toHaveLength(1);
    expect(published[0].ipnsName).toBe('k51-file-existing');
    // Folder metadata must NOT be encrypted/uploaded for a content replace
    expect(mockFns.encryptFolderMetadata).not.toHaveBeenCalled();
    expect(mockFns.addToIpfs).not.toHaveBeenCalled();
  });

  it('throws when the file id is not present in the folder children', async () => {
    const ctx = createMockContext();
    await expect(
      replaceFileInFolder({
        children: [makeFolder('f1', 'Docs')],
        fileId: 'missing-file',
        fileIpnsRecord: makeFileIpnsRecord('k51-file-x'),
        ctx,
      })
    ).rejects.toThrow('File not found');
    expect(mockFns.batchPublishIpnsRecords).not.toHaveBeenCalled();
  });

  it('throws when the file IPNS publish fails', async () => {
    const ctx = createMockContext();
    mockFns.batchPublishIpnsRecords.mockResolvedValue({ totalFailed: 1, results: [] });

    await expect(
      replaceFileInFolder({
        children: [makeFile('file-1', 'report.pdf')],
        fileId: 'file-1',
        fileIpnsRecord: makeFileIpnsRecord('k51-file-existing'),
        ctx,
      })
    ).rejects.toThrow('Failed to publish file IPNS record');
  });
});
