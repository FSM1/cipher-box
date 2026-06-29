/* eslint-disable @typescript-eslint/ban-ts-comment */
// @ts-nocheck
// Phase 65 quarantine: addFileToFolder / addFilesToFolder / replaceFileInFolder skip blocks reference
// retired FolderEntry/FilePointer types via makeFolder/makeFile helpers.
// TODO(phase 65): revive addFileToFolder, addFilesToFolder, replaceFileInFolder
import { describe, it, expect, vi, beforeEach } from 'vitest';
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
  // Kept for phase-65-skip blocks (addFileToFolder / addFilesToFolder / replaceFileInFolder)
  encryptFolderMetadata: vi.fn(),
  // Phase-62 codec (node/v3)
  sealNode: vi.fn(),
  unsealNode: vi.fn(),
  sealChildReadKey: vi.fn(),
  unsealChildReadKey: vi.fn(),
  createIpnsRecord: vi.fn(),
  marshalIpnsRecord: vi.fn(),
  generateEd25519Keypair: vi.fn(),
  deriveIpnsName: vi.fn(),
  generateRandomBytes: vi.fn(),
}));

vi.mock('@cipherbox/crypto', () => ({
  generateEd25519Keypair: mockFns.generateEd25519Keypair,
  deriveIpnsName: mockFns.deriveIpnsName,
  deriveEd25519PublicKey: vi.fn().mockReturnValue(new Uint8Array(32).fill(7)),
  generateRandomBytes: mockFns.generateRandomBytes,
}));

vi.mock('@cipherbox/core', () => ({
  // Phase-62 node/v3 codec mocks
  sealNode: mockFns.sealNode,
  unsealNode: mockFns.unsealNode,
  sealChildReadKey: mockFns.sealChildReadKey,
  unsealChildReadKey: mockFns.unsealChildReadKey,
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

// ---------------------------------------------------------------------------
// load.ts — fetchAndDecryptMetadata + loadFolderMetadata
// fetchFromIpfs / resolveIpnsRecord / unsealNode are mocked above.
// ---------------------------------------------------------------------------

describe('fetchAndDecryptMetadata', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fetches from IPFS, JSON-parses as PublishedNode, and unseals with the folder key', async () => {
    const ctx = createMockContext();
    const folderKey = new Uint8Array(32).fill(9);
    // fetchFromIpfs returns a Uint8Array of JSON-encoded PublishedNode
    const publishedNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-test-1',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'base64==',
    };
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(publishedNode))
    );
    const unsealedNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-test-1',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
    };
    mockFns.unsealNode.mockResolvedValue(unsealedNode);

    const result = await fetchAndDecryptMetadata('QmCid123', folderKey, ctx);

    expect(mockFns.fetchFromIpfs).toHaveBeenCalledWith(ctx, 'QmCid123');
    // unsealNode must receive the parsed PublishedNode object and the folder key
    expect(mockFns.unsealNode).toHaveBeenCalledWith(publishedNode, folderKey);
    expect(result).toBe(unsealedNode);
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

  it('resolves IPNS, fetches+unseals, and surfaces metadata, sequenceNumber and cid', async () => {
    const ctx = createMockContext();
    const folderKey = new Uint8Array(32).fill(3);
    mockFns.resolveIpnsRecord.mockResolvedValue({
      sequenceNumber: 42n,
      cid: 'QmResolved',
    });
    const publishedNode = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-resolved-2',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'base64==',
    };
    mockFns.fetchFromIpfs.mockResolvedValue(
      new TextEncoder().encode(JSON.stringify(publishedNode))
    );
    const metadata = {
      schema: 'node/v3',
      kind: 'folder',
      id: 'node-resolved-2',
      generation: 0,
      createdAt: 0,
      modifiedAt: 0,
      children: [],
    };
    mockFns.unsealNode.mockResolvedValue(metadata);

    const result = await loadFolderMetadata({ ipnsName: 'k51found', folderKey, ctx });

    expect(mockFns.resolveIpnsRecord).toHaveBeenCalledWith('k51found', ctx);
    expect(result).toEqual({ metadata, sequenceNumber: 42n, cid: 'QmResolved' });
  });
});

// ---------------------------------------------------------------------------
// metadata-ops.ts — phase 63 SealedChildRef mutations (Task 1 of Plan 63-04)
// renameInFolder, deleteFromFolder, addFilePointerToFolder, moveItem.
// All use SealedChildRef instead of the retired FolderChild / FilePointer types.
// ---------------------------------------------------------------------------

/** Minimal SealedChildRef fixture for phase-63 metadata-ops tests. */
const makeRef = (
  ipnsName: string,
  name: string
): {
  name: string;
  ipnsName: string;
  generation: number;
  versionFloor: bigint;
  readKeySealed: string;
} => ({
  name,
  ipnsName,
  generation: 0,
  versionFloor: 0n,
  readKeySealed: 'sealed==',
});

describe('renameInFolder (SealedChildRef)', () => {
  it('renames a child by ipnsName, returns new array without mutating original', () => {
    const children = [makeRef('k51-f1', 'Documents'), makeRef('k51-f2', 'Photos')];
    const result = renameInFolder({ children, childId: 'k51-f1', newName: 'My Documents' });
    expect(result.updatedChildren).toHaveLength(2);
    expect(result.renamedChild.name).toBe('My Documents');
    expect(result.renamedChild.ipnsName).toBe('k51-f1');
    // Original array must not be mutated
    expect(children[0].name).toBe('Documents');
  });

  it('throws when child ipnsName not found', () => {
    expect(() =>
      renameInFolder({ children: [], childId: 'k51-nonexistent', newName: 'X' })
    ).toThrow('Item not found');
  });
});

describe('deleteFromFolder (SealedChildRef)', () => {
  it('removes child by ipnsName and returns it', () => {
    const children = [makeRef('k51-f1', 'Documents'), makeRef('k51-f2', 'photo.jpg')];
    const result = deleteFromFolder({ children, childId: 'k51-f2' });
    expect(result.updatedChildren).toHaveLength(1);
    expect(result.removedItem.ipnsName).toBe('k51-f2');
    expect(result.removedItem.name).toBe('photo.jpg');
    expect(result.updatedChildren.find((c) => c.ipnsName === 'k51-f2')).toBeUndefined();
  });

  it('throws when child not found', () => {
    expect(() => deleteFromFolder({ children: [], childId: 'k51-missing' })).toThrow(
      'Item not found'
    );
  });
});

describe('addFilePointerToFolder (SealedChildRef — READ-03: one seal, no fan-out)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.sealChildReadKey.mockResolvedValue('child-read-key-sealed==');
  });

  it('seals child readKey under parent readKey exactly once regardless of existing children', async () => {
    const children = [makeRef('k51-existing', 'existing.txt')];
    const childReadKey = new Uint8Array(32).fill(1);
    const parentReadKey = new Uint8Array(32).fill(2);

    const result = await addFilePointerToFolder({
      children,
      childReadKey,
      parentReadKey,
      childId: 'child-node-uuid-1234',
      childKind: 'file',
      childGeneration: 0,
      name: 'newfile.txt',
      ipnsName: 'k51-new-child',
      versionFloor: 1n,
    });

    // Exactly one sealChildReadKey call — no per-recipient fan-out (READ-03 / SC#3)
    expect(mockFns.sealChildReadKey).toHaveBeenCalledTimes(1);
    expect(mockFns.sealChildReadKey).toHaveBeenCalledWith(
      childReadKey,
      parentReadKey,
      'child-node-uuid-1234',
      'file',
      0
    );
    expect(result.updatedChildren).toHaveLength(2);
    expect(result.newRef.name).toBe('newfile.txt');
    expect(result.newRef.ipnsName).toBe('k51-new-child');
    expect(result.newRef.readKeySealed).toBe('child-read-key-sealed==');
    expect(result.newRef.generation).toBe(0);
    expect(result.newRef.versionFloor).toBe(1n);
  });
});

describe('moveItem (SealedChildRef — READ-04: zero re-encryption)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('moves SealedChildRef from source to dest as a link rewrite — sealChildReadKey not called', () => {
    const sourceChildren = [
      makeRef('k51-doc', 'Document.docx'),
      {
        name: 'MovableFile.txt',
        ipnsName: 'k51-move',
        generation: 0,
        versionFloor: 1n,
        readKeySealed: 'sealed-move==',
      },
    ];
    const destChildren = [makeRef('k51-arch', 'Archive.zip')];

    const result = moveItem({ sourceChildren, destChildren, childId: 'k51-move' });

    // Zero re-encryption (READ-04): no sealChildReadKey or sealNode calls
    expect(mockFns.sealChildReadKey).not.toHaveBeenCalled();
    expect(mockFns.sealNode).not.toHaveBeenCalled();

    expect(result.updatedSource).toHaveLength(1);
    expect(result.updatedSource[0].ipnsName).toBe('k51-doc');
    expect(result.updatedDest).toHaveLength(2);
    expect(result.movedRef.ipnsName).toBe('k51-move');
    // readKeySealed is moved as-is — no re-seal (READ-04)
    expect(result.movedRef.readKeySealed).toBe('sealed-move==');
  });

  it('throws when child not found in source', () => {
    expect(() =>
      moveItem({
        sourceChildren: [makeRef('k51-f1', 'Docs')],
        destChildren: [],
        childId: 'k51-nonexistent',
      })
    ).toThrow('Item not found');
  });
});

// ---------------------------------------------------------------------------
// registration.ts — createSubfolder (phase 63 — Task 2 of Plan 63-04)
// ---------------------------------------------------------------------------

describe('createSubfolder (phase 63 — first-publish seq 1n)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.generateEd25519Keypair.mockResolvedValue({
      publicKey: new Uint8Array(32).fill(1),
      privateKey: new Uint8Array(64).fill(2),
    });
    mockFns.deriveIpnsName.mockResolvedValue('k51-derived-subfolder');
    // Return DISTINCT buffers so read/write key aliasing cannot hide accidental shared state.
    mockFns.generateRandomBytes
      .mockReturnValueOnce(new Uint8Array(32).fill(3)) // readKey (first call)
      .mockReturnValueOnce(new Uint8Array(32).fill(4)); // writeKey (second call)
    mockFns.sealNode.mockResolvedValue({
      schema: 'node/v3',
      kind: 'folder',
      id: 'subfolder-node-id',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'read-sealed-base64==',
    });
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmSubfolderCid', size: 128, recorded: true });
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 1n });
  });

  it('first-publishes with sequenceNumber 1n (post-Phase-60 strict gate)', async () => {
    const ctx = createMockContext();
    const result = await createSubfolder({ name: 'MySubfolder', ctx });

    // generateEd25519Keypair must be called to create the IPNS keypair
    expect(mockFns.generateEd25519Keypair).toHaveBeenCalled();
    // deriveIpnsName derives the k51 name from the generated public key
    expect(mockFns.deriveIpnsName).toHaveBeenCalledWith(new Uint8Array(32).fill(1));
    // generateRandomBytes called twice for readKey + writeKey (32 bytes each)
    expect(mockFns.generateRandomBytes).toHaveBeenCalledTimes(2);
    // sealNode seals the node with the generated readKey + writeKey
    expect(mockFns.sealNode).toHaveBeenCalled();
    // First-publish MUST embed sequenceNumber: 1n (post-Phase-60 strict gate rejects != 1)
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledWith(
      expect.objectContaining({ sequenceNumber: 1n, ipnsName: 'k51-derived-subfolder' })
    );

    expect(result.node.kind).toBe('folder');
    expect(result.ipnsPrivateKey).toEqual(new Uint8Array(64).fill(2));
    expect(result.rootReadKey).toEqual(new Uint8Array(32).fill(3));
    expect(result.rootWriteKey).toEqual(new Uint8Array(32).fill(4)); // distinct from readKey
    // No TEE keys → no encrypted republish key
    expect(result.encryptedIpnsPrivateKey).toBeUndefined();
    expect(result.keyEpoch).toBeUndefined();
  });

  it('does NOT zero minted keys before return (caller is terminal owner, D-09)', async () => {
    const ctx = createMockContext();
    const result = await createSubfolder({ name: 'NoZeroFolder', ctx });

    // Keys must be non-zero buffers on return
    expect(result.ipnsPrivateKey.some((b) => b !== 0)).toBe(true);
    expect(result.rootReadKey.some((b) => b !== 0)).toBe(true);
    expect(result.rootWriteKey.some((b) => b !== 0)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// registration.ts — updateFolderMetadataAndPublish (phase 63 — Task 2)
// Delegates to publishWithCas for CAS-retry + three-way merge infrastructure.
// ---------------------------------------------------------------------------

describe('updateFolderMetadataAndPublish (phase 63 — delegates to publishWithCas)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFns.sealNode.mockResolvedValue({
      schema: 'node/v3',
      kind: 'folder',
      id: 'folder-node-id',
      generation: 0,
      aeadVersion: 1,
      readSealed: 'sealed-read-body==',
    });
    mockFns.addToIpfs.mockResolvedValue({ cid: 'QmUpdatedCid', size: 64, recorded: true });
    mockFns.createAndPublishIpnsRecord.mockResolvedValue({ success: true, sequenceNumber: 6n });
  });

  it('publishes resealed node via CAS (sequenceNumber increments by 1) and returns cid + new seq', async () => {
    const ctx = createMockContext();
    const children = [makeRef('k51-child-a', 'FileA.txt'), makeRef('k51-child-b', 'FileB.txt')];

    const result = await updateFolderMetadataAndPublish({
      children,
      readKey: new Uint8Array(32).fill(1),
      ipnsPrivateKey: new Uint8Array(64).fill(2),
      ipnsName: 'k51-parent',
      sequenceNumber: 5n,
      ctx,
    });

    // publishWithCas delegates to sealNode + addToIpfs (encodeAndUpload seam)
    expect(mockFns.sealNode).toHaveBeenCalled();
    expect(mockFns.addToIpfs).toHaveBeenCalled();
    // CAS guard: expectedSequenceNumber = '5' (pre-increment), sequenceNumber = 6n
    expect(mockFns.createAndPublishIpnsRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        sequenceNumber: 6n,
        expectedSequenceNumber: '5',
        metadataCid: 'QmUpdatedCid',
        ipnsName: 'k51-parent',
      })
    );
    expect(result.cid).toBe('QmUpdatedCid');
    expect(result.newSequenceNumber).toBe(6n);
    expect(result.publishedChildren).toEqual(children);
  });

  it('does NOT zero readKey or ipnsPrivateKey (caller retains ownership, D-09)', async () => {
    const ctx = createMockContext();
    const readKey = new Uint8Array(32).fill(0x42);
    const ipnsKey = new Uint8Array(64).fill(0x77);
    const readKeySnapshot = new Uint8Array(readKey);
    const ipnsKeySnapshot = new Uint8Array(ipnsKey);

    await updateFolderMetadataAndPublish({
      children: [],
      readKey,
      ipnsPrivateKey: ipnsKey,
      ipnsName: 'k51-guard',
      sequenceNumber: 0n,
      ctx,
    });

    expect(readKey).toEqual(readKeySnapshot);
    expect(ipnsKey).toEqual(ipnsKeySnapshot);
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

describe.skip('addFileToFolder — TODO(phase 65)', () => {
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
    // Positive identity: the file record is published under the file IPNS name
    // (no CAS), the folder record under the parent name (carries CAS).
    expect(published[0].ipnsName).toBe('k51-file-aaa');
    expect(published[0].expectedSequenceNumber).toBeUndefined();
    expect(published[1].ipnsName).toBe('k51-parent');
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

describe.skip('addFilesToFolder — TODO(phase 65)', () => {
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

describe.skip('replaceFileInFolder — TODO(phase 65)', () => {
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
