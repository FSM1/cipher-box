/**
 * Shared-write tests — Phase 65 write-body model
 *
 * Three test sections:
 *   1. WRITE-01 security: read-only holder cannot reach writeBody (pure crypto, real @cipherbox/core)
 *   2. Write-body operations: 6 write ops on the write-body model (mock publishNodeFn / addToIpfsFn)
 *   3. WRITE-03 offline co-writer: tombstoned target throws CannotWriteUntilRefetchError
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

// ---- Real crypto for WRITE-01 security section ----------------------------
// sealNode / unsealNode / sealChildWriteKey / unsealChildWriteKey are accessed
// via vi.importActual inside individual tests so module-level mocks do not
// interfere. Only types are imported here.

import { sealNode, unsealNode } from '@cipherbox/core';
import type { Node, PublishedNode, SealedChildRef, WriteChildRef } from '@cipherbox/core';
import { generateRandomBytes, generateEd25519Keypair } from '@cipherbox/crypto';

// ---- Mocks for operation tests --------------------------------------------

// @cipherbox/crypto: mock key/keypair generation so tests are deterministic.
// sealChildWriteKey / unsealChildWriteKey / sealChildReadKey are handled by
// spreading the real @cipherbox/core below.
vi.mock('@cipherbox/crypto', async () => {
  const actual = await vi.importActual<typeof import('@cipherbox/crypto')>('@cipherbox/crypto');
  return {
    ...actual,
    generateRandomBytes: vi.fn().mockImplementation((n: number) => new Uint8Array(n).fill(0x42)),
    generateEd25519Keypair: vi.fn().mockReturnValue({
      publicKey: new Uint8Array(32).fill(0x44),
      privateKey: new Uint8Array(32).fill(0x55),
    }),
    deriveIpnsName: vi.fn().mockResolvedValue('k51child1234'),
  };
});

// @cipherbox/core: spread actual so real sealNode/unsealNode/sealChildWriteKey
// etc. work in operation tests too. We only override what is genuinely
// expensive or network-bound (none here — crypto runs in-process).
vi.mock('@cipherbox/core', async () => {
  const actual = await vi.importActual<typeof import('@cipherbox/core')>('@cipherbox/core');
  return { ...actual };
});

// ---- Imports under test (after mock hoisting) ----------------------------

import {
  uploadToSharedFolder,
  createSharedSubfolder,
  renameInSharedFolder,
  deleteFromSharedFolder,
  updateSharedFile,
  moveInSharedFolder,
  updateSharePermission,
  CannotWriteUntilRefetchError,
  type SharedWriteContext,
  type PublishNodeResult,
} from '../share/shared-write';

// ---- Helpers ---------------------------------------------------------------

/** Build a real sealed parent node for use in operation tests. */
async function buildSealedParent(opts?: {
  extraChildren?: SealedChildRef[];
  writeChildren?: WriteChildRef[];
  ipnsPrivKey?: Uint8Array;
}): Promise<{
  publishedNode: PublishedNode;
  readKey: Uint8Array;
  writeKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
}> {
  const readKey = new Uint8Array(32).fill(0x01);
  const writeKey = new Uint8Array(32).fill(0x02);
  const ipnsPrivateKey = new Uint8Array(32).fill(0x03);
  const parent: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    generation: 0,
    createdAt: 1000,
    modifiedAt: 1000,
    children: opts?.extraChildren ?? [],
    writeBody: {
      ipnsPrivateKey: opts?.ipnsPrivKey ?? ipnsPrivateKey,
      writeChildren: opts?.writeChildren ?? [],
    },
  };
  const publishedNode = await sealNode(parent, readKey, writeKey);
  return { publishedNode, readKey, writeKey, ipnsPrivateKey: opts?.ipnsPrivKey ?? ipnsPrivateKey };
}

const mockCtx = {
  apiUrl: 'http://localhost:3000',
  getAccessToken: async () => 'token',
};

function makePublishNodeFn(
  result: PublishNodeResult = { tombstoned: false, newSequenceNumber: 2n }
): SharedWriteContext['publishNodeFn'] {
  return vi.fn().mockResolvedValue(result);
}

function makeAddToIpfsFn(): SharedWriteContext['addToIpfsFn'] {
  return vi.fn().mockResolvedValue({ cid: 'QmMockedCid' });
}

async function makeSWCtx(overrides?: Partial<SharedWriteContext>): Promise<SharedWriteContext> {
  const { publishedNode, readKey, writeKey } = await buildSealedParent();
  return {
    ctx: mockCtx,
    readKey,
    writeKey,
    publishedNode,
    ipnsName: 'k51parentfolder',
    sequenceNumber: 1n,
    children: [],
    ownerPublicKey: new Uint8Array(33).fill(3),
    recipientPublicKey: new Uint8Array(33).fill(4),
    shareId: 'share-123',
    publishNodeFn: makePublishNodeFn(),
    addToIpfsFn: makeAddToIpfsFn(),
    ...overrides,
  };
}

// ===========================================================================
// Section 1: WRITE-01 security — read-only holder cannot reach writeBody
// ===========================================================================

describe('WRITE-01 security: read-only holder cannot reach writeBody', () => {
  it('unsealNode without writeKey returns a node with no writeBody', async () => {
    const { actual: coreActual } = await vi
      .importActual<typeof import('@cipherbox/core')>('@cipherbox/core')
      .then((a) => ({ actual: a }));

    const readKey = generateRandomBytes(32);
    const writeKey = generateRandomBytes(32);
    const ipnsPrivateKey = generateEd25519Keypair().privateKey;

    const node: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: '11111111-2222-3333-4444-555555555555',
      generation: 0,
      createdAt: 1000,
      modifiedAt: 1000,
      children: [],
      writeBody: {
        ipnsPrivateKey,
        writeChildren: [],
      },
    };

    const published = await coreActual.sealNode(node, readKey, writeKey);

    // A read-only holder (no writeKey) gets NO writeBody
    const readOnlyNode = await coreActual.unsealNode(published, readKey);
    expect(readOnlyNode.writeBody).toBeUndefined();

    // A write-capable holder (with writeKey) gets the writeBody + ipnsPrivateKey
    const writeCapableNode = await coreActual.unsealNode(published, readKey, writeKey);
    expect(writeCapableNode.writeBody).toBeDefined();
    expect(writeCapableNode.writeBody!.ipnsPrivateKey).toEqual(ipnsPrivateKey);
  });

  it('published envelope has writeSealed when writeBody is present', async () => {
    const { actual: coreActual } = await vi
      .importActual<typeof import('@cipherbox/core')>('@cipherbox/core')
      .then((a) => ({ actual: a }));

    const readKey = generateRandomBytes(32);
    const writeKey = generateRandomBytes(32);
    const node: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: '22222222-3333-4444-5555-666666666666',
      generation: 0,
      createdAt: 1000,
      modifiedAt: 1000,
      children: [],
      writeBody: {
        ipnsPrivateKey: generateEd25519Keypair().privateKey,
        writeChildren: [],
      },
    };

    const published = await coreActual.sealNode(node, readKey, writeKey);
    expect(published.writeSealed).toBeDefined();
    expect(typeof published.writeSealed).toBe('string');
  });

  it('write-link round-trip: buildChildWriteLink seals; walkChildWriteKey unseals back to original', async () => {
    const { actual: coreActual } = await vi
      .importActual<typeof import('@cipherbox/core')>('@cipherbox/core')
      .then((a) => ({ actual: a }));

    const parentWriteKey = generateRandomBytes(32);
    const childWriteKey = generateRandomBytes(32);
    const childId = '33333333-4444-5555-6666-777777777777';
    const childKind = 'folder' as const;
    const childGeneration = 0;

    // Seal childWriteKey under parentWriteKey
    const writeKeySealed = await coreActual.sealChildWriteKey(
      childWriteKey,
      parentWriteKey,
      childId,
      childKind,
      childGeneration
    );
    const childRef: WriteChildRef = { childId, writeKeySealed };

    // Unseal back
    const recovered = await coreActual.unsealChildWriteKey(
      childRef.writeKeySealed,
      parentWriteKey,
      childRef.childId,
      childKind,
      childGeneration
    );
    expect(recovered).toEqual(childWriteKey);
  });

  it('SealedChildRef carries no write field (NODE-03)', async () => {
    // This test ensures the type constraint is upheld: SealedChildRef
    // must not have writeKeySealed or any write field.
    const childRef: SealedChildRef = {
      name: 'test',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'base64sealed',
    };
    // TypeScript already guards this; also assert at runtime.
    expect('writeKeySealed' in childRef).toBe(false);
    expect(Object.keys(childRef).includes('writeKeySealed')).toBe(false);
  });
});

// ===========================================================================
// Section 2: SharedWriteContext shape
// ===========================================================================

describe('SharedWriteContext shape', () => {
  it('carries writeKey and readKey — no raw folderKey or top-level ipnsPrivateKey', async () => {
    const swCtx = await makeSWCtx();
    expect(swCtx).toHaveProperty('readKey');
    expect(swCtx).toHaveProperty('writeKey');
    expect(swCtx).not.toHaveProperty('folderKey');
    expect(swCtx).not.toHaveProperty('ipnsPrivateKey');
  });

  it('has publishNodeFn and addToIpfsFn transport seams', async () => {
    const swCtx = await makeSWCtx();
    expect(typeof swCtx.publishNodeFn).toBe('function');
    expect(typeof swCtx.addToIpfsFn).toBe('function');
  });
});

// ===========================================================================
// Section 3: Operation tests — write-body model, no fan-out
// ===========================================================================

describe('createSharedSubfolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns publishedChildren, newSequenceNumber, and folderEntry', async () => {
    const swCtx = await makeSWCtx();
    const result = await createSharedSubfolder(swCtx, { name: 'NewFolder' });

    expect(result.publishedChildren).toHaveLength(1);
    expect(result.folderEntry.name).toBe('NewFolder');
    expect(result.newSequenceNumber).toBe(2n);
  });

  it('folderEntry SealedChildRef has no writeKeySealed (NODE-03)', async () => {
    const swCtx = await makeSWCtx();
    const { folderEntry } = await createSharedSubfolder(swCtx, { name: 'Sub' });
    expect('writeKeySealed' in folderEntry).toBe(false);
  });

  it('calls publishNodeFn for the child and then the parent', async () => {
    const publishFn = makePublishNodeFn();
    const swCtx = await makeSWCtx({ publishNodeFn: publishFn });
    await createSharedSubfolder(swCtx, { name: 'Sub' });
    // Called at least twice: once for child, once for parent
    expect(publishFn).toHaveBeenCalledTimes(2);
  });
});

describe('uploadToSharedFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns publishedChildren, newSequenceNumber, and filePointer', async () => {
    const swCtx = await makeSWCtx();
    const result = await uploadToSharedFolder(swCtx, {
      data: new Uint8Array([1, 2, 3]),
      fileName: 'test.txt',
      mimeType: 'text/plain',
    });

    expect(result.publishedChildren).toHaveLength(1);
    expect(result.filePointer.name).toBe('test.txt');
    expect(result.newSequenceNumber).toBe(2n);
  });

  it('filePointer SealedChildRef has no writeKeySealed (NODE-03)', async () => {
    const swCtx = await makeSWCtx();
    const { filePointer } = await uploadToSharedFolder(swCtx, {
      data: new Uint8Array([1]),
      fileName: 'f.txt',
    });
    expect('writeKeySealed' in filePointer).toBe(false);
  });

  it('calls addToIpfsFn to upload file content', async () => {
    const addFn = makeAddToIpfsFn();
    const swCtx = await makeSWCtx({ addToIpfsFn: addFn });
    await uploadToSharedFolder(swCtx, { data: new Uint8Array([1, 2, 3]), fileName: 'f.txt' });
    expect(addFn).toHaveBeenCalled();
  });
});

describe('renameInSharedFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renames the item and republishes the parent', async () => {
    // Set up a parent with one child
    const existingChild: SealedChildRef = {
      name: 'old.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };

    // We need a parent node with that child in its read-body.
    // Build a properly sealed parent that includes the existing child.
    const {
      publishedNode: pn,
      readKey,
      writeKey,
    } = await buildSealedParent({
      extraChildren: [existingChild],
    });

    const swCtx = await makeSWCtx({
      publishedNode: pn,
      readKey,
      writeKey,
      children: [existingChild],
    });

    const result = await renameInSharedFolder(swCtx, {
      // Use ipnsName as identifier (the name is what we're changing)
      itemId: 'k51child',
      newName: 'new.txt',
    });

    expect(result.publishedChildren).toHaveLength(1);
    expect(result.publishedChildren[0].name).toBe('new.txt');
    expect(result.newSequenceNumber).toBe(2n);
  });
});

describe('deleteFromSharedFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const CHILD_UUID = 'cccccccc-dddd-eeee-ffff-000000000001';

  it('removes the item and republishes the parent', async () => {
    const child: SealedChildRef = {
      name: 'doomed.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };
    const {
      publishedNode: pn,
      readKey,
      writeKey,
    } = await buildSealedParent({
      extraChildren: [child],
    });
    const swCtx = await makeSWCtx({ publishedNode: pn, readKey, writeKey, children: [child] });

    const result = await deleteFromSharedFolder(swCtx, {
      itemId: 'k51child',
      childNodeId: CHILD_UUID,
    });

    expect(result.publishedChildren).toHaveLength(0);
    expect(result.newSequenceNumber).toBe(2n);
  });

  it('removes the WriteChildRef from the write-body on delete', async () => {
    const child: SealedChildRef = {
      name: 'doomed.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };
    // Seed the parent write-body with a WriteChildRef whose childId is the UUID
    const writeChild: WriteChildRef = {
      childId: CHILD_UUID,
      writeKeySealed: 'fakewritekeysealed',
    };
    const {
      publishedNode: pn,
      readKey,
      writeKey,
    } = await buildSealedParent({
      extraChildren: [child],
      writeChildren: [writeChild],
    });

    // Capture the PublishedNode passed to publishNodeFn so we can unseal it.
    let capturedPublished: PublishedNode | undefined;
    const publishFn = vi
      .fn()
      .mockImplementation(
        async (p: {
          published: PublishedNode;
          ipnsName: string;
          ipnsPrivateKey: Uint8Array;
          sequenceNumber: bigint;
        }) => {
          capturedPublished = p.published;
          return { tombstoned: false, newSequenceNumber: 2n };
        }
      );

    const swCtx = await makeSWCtx({
      publishedNode: pn,
      readKey,
      writeKey,
      children: [child],
      publishNodeFn: publishFn,
    });

    await deleteFromSharedFolder(swCtx, { itemId: 'k51child', childNodeId: CHILD_UUID });

    // Unseal the republished parent and verify write-body has no stale WriteChildRef.
    expect(capturedPublished).toBeDefined();
    const unsealed = await unsealNode(capturedPublished!, readKey, writeKey);
    expect(unsealed.writeBody).toBeDefined();
    expect(unsealed.writeBody!.writeChildren).toHaveLength(0);
  });
});

describe('updateSharedFile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('re-publishes the file node with new content', async () => {
    const publishFn = makePublishNodeFn();
    const addFn = makeAddToIpfsFn();
    const swCtx = await makeSWCtx({ publishNodeFn: publishFn, addToIpfsFn: addFn });

    const fileRef: SealedChildRef = {
      name: 'file.txt',
      ipnsName: 'k51file',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };
    const fileReadKey = new Uint8Array(32).fill(0xaa);
    const fileWriteKey = new Uint8Array(32).fill(0xbb);
    const fileIpnsPrivateKey = new Uint8Array(32).fill(0xcc);

    await updateSharedFile(swCtx, {
      fileRef,
      fileNodeId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      fileReadKey,
      fileWriteKey,
      fileIpnsPrivateKey,
      fileSequenceNumber: 1n,
      newData: new Uint8Array([10, 20, 30]),
      mimeType: 'text/plain',
    });

    // Should have published the file node
    expect(publishFn).toHaveBeenCalledWith(expect.objectContaining({ ipnsName: 'k51file' }));
  });
});

describe('moveInSharedFolder', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('moves item from src to dest and returns both results', async () => {
    const CHILD_UUID = '33333333-4444-5555-6666-777777777777';
    const child: SealedChildRef = {
      name: 'tomove.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };

    const {
      publishedNode: srcPn,
      readKey: srcReadKey,
      writeKey: srcWriteKey,
    } = await buildSealedParent({
      extraChildren: [child],
    });
    const {
      publishedNode: destPn,
      readKey: destReadKey,
      writeKey: destWriteKey,
    } = await buildSealedParent();

    const srcCtx = await makeSWCtx({
      publishedNode: srcPn,
      readKey: srcReadKey,
      writeKey: srcWriteKey,
      ipnsName: 'k51src',
      children: [child],
    });
    const destCtx = await makeSWCtx({
      publishedNode: destPn,
      readKey: destReadKey,
      writeKey: destWriteKey,
      ipnsName: 'k51dest',
      children: [],
    });

    const result = await moveInSharedFolder({
      srcCtx,
      destCtx,
      itemId: 'k51child',
      childNodeId: CHILD_UUID,
      childKind: 'folder',
      childGeneration: 0,
      childReadKey: new Uint8Array(32).fill(0xdd),
      // Supply childWriteKey so the write link is re-sealed for the destination.
      childWriteKey: new Uint8Array(32).fill(0xee),
    });

    expect(result.srcResult.publishedChildren).toHaveLength(0);
    expect(result.destResult.publishedChildren).toHaveLength(1);
    expect(result.destResult.publishedChildren[0].name).toBe('tomove.txt');
  });

  it('throws when no write key can be resolved for the child', async () => {
    const CHILD_UUID = '33333333-4444-5555-6666-777777777777';
    const child: SealedChildRef = {
      name: 'tomove.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };

    const {
      publishedNode: srcPn,
      readKey: srcReadKey,
      writeKey: srcWriteKey,
    } = await buildSealedParent({ extraChildren: [child] });
    const {
      publishedNode: destPn,
      readKey: destReadKey,
      writeKey: destWriteKey,
    } = await buildSealedParent();

    const srcCtx = await makeSWCtx({
      publishedNode: srcPn,
      readKey: srcReadKey,
      writeKey: srcWriteKey,
      ipnsName: 'k51src',
      children: [child],
    });
    const destCtx = await makeSWCtx({
      publishedNode: destPn,
      readKey: destReadKey,
      writeKey: destWriteKey,
      ipnsName: 'k51dest',
      children: [],
    });

    // Neither childWriteKey supplied nor a write-body entry exists in src — must throw.
    await expect(
      moveInSharedFolder({
        srcCtx,
        destCtx,
        itemId: 'k51child',
        childNodeId: CHILD_UUID,
        childKind: 'folder',
        childGeneration: 0,
        childReadKey: new Uint8Array(32).fill(0xdd),
        // childWriteKey intentionally omitted
      })
    ).rejects.toThrow('write link not found for child');
  });
});

// ===========================================================================
// Section 4: WRITE-03 — CannotWriteUntilRefetchError for tombstoned target
// ===========================================================================

describe('CannotWriteUntilRefetchError (WRITE-03 / D-03)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('CannotWriteUntilRefetchError is exported and has a stable code', () => {
    const err = new CannotWriteUntilRefetchError('k51test');
    expect(err.name).toBe('CannotWriteUntilRefetchError');
    expect(err.code).toBe('CANNOT_WRITE_UNTIL_REFETCH');
    expect(err.message).toMatch(/cannot write until re-fetch/i);
    expect(err instanceof Error).toBe(true);
  });

  it('createSharedSubfolder throws CannotWriteUntilRefetchError when publishNodeFn returns tombstoned', async () => {
    const tombstonedPublishFn = vi.fn().mockResolvedValue({ tombstoned: true });
    const swCtx = await makeSWCtx({ publishNodeFn: tombstonedPublishFn });

    await expect(createSharedSubfolder(swCtx, { name: 'Sub' })).rejects.toThrow(
      CannotWriteUntilRefetchError
    );
  });

  it('uploadToSharedFolder throws CannotWriteUntilRefetchError when publishNodeFn returns tombstoned', async () => {
    const tombstonedPublishFn = vi.fn().mockResolvedValue({ tombstoned: true });
    const swCtx = await makeSWCtx({ publishNodeFn: tombstonedPublishFn });

    await expect(
      uploadToSharedFolder(swCtx, { data: new Uint8Array([1]), fileName: 'f.txt' })
    ).rejects.toThrow(CannotWriteUntilRefetchError);
  });

  it('renameInSharedFolder throws CannotWriteUntilRefetchError when publishNodeFn returns tombstoned', async () => {
    const child: SealedChildRef = {
      name: 'old.txt',
      ipnsName: 'k51child',
      generation: 0,
      versionFloor: 1n,
      readKeySealed: 'fakebase64sealed',
    };
    const {
      publishedNode: pn,
      readKey,
      writeKey,
    } = await buildSealedParent({
      extraChildren: [child],
    });
    const tombstonedPublishFn = vi.fn().mockResolvedValue({ tombstoned: true });
    const swCtx = await makeSWCtx({
      publishedNode: pn,
      readKey,
      writeKey,
      children: [child],
      publishNodeFn: tombstonedPublishFn,
    });

    await expect(
      renameInSharedFolder(swCtx, { itemId: 'k51child', newName: 'new.txt' })
    ).rejects.toThrow(CannotWriteUntilRefetchError);
  });

  it('error is instanceof CannotWriteUntilRefetchError (discriminant works)', async () => {
    const tombstonedPublishFn = vi.fn().mockResolvedValue({ tombstoned: true });
    const swCtx = await makeSWCtx({ publishNodeFn: tombstonedPublishFn });

    let caught: unknown;
    try {
      await createSharedSubfolder(swCtx, { name: 'Sub' });
    } catch (e) {
      caught = e;
    }
    expect(caught instanceof CannotWriteUntilRefetchError).toBe(true);
    if (caught instanceof CannotWriteUntilRefetchError) {
      expect(caught.code).toBe('CANNOT_WRITE_UNTIL_REFETCH');
    }
  });

  it('no grace-period / notification / pending-rekey added (only typed error)', () => {
    const err = new CannotWriteUntilRefetchError('k51test');
    // Verify only the expected properties exist — no retry/notification state
    const extraKeys = Object.keys(err).filter(
      (k) => !['name', 'message', 'code', 'stack'].includes(k)
    );
    expect(extraKeys).toHaveLength(0);
  });
});

// ===========================================================================
// Section 5: updateSharePermission (unchanged from Phase 62)
// ===========================================================================

describe('updateSharePermission', () => {
  it('calls the provided updatePermissionFn with correct params', async () => {
    const updateFn = vi.fn().mockResolvedValue(undefined);

    await updateSharePermission({
      shareId: 'share-456',
      permission: 'write',
      encryptedIpnsKey: 'wrapped-key',
      updatePermissionFn: updateFn,
    });

    expect(updateFn).toHaveBeenCalledWith('share-456', {
      permission: 'write',
      encryptedIpnsKey: 'wrapped-key',
    });
  });

  it('calls without encryptedIpnsKey when not provided', async () => {
    const updateFn = vi.fn().mockResolvedValue(undefined);

    await updateSharePermission({
      shareId: 'share-456',
      permission: 'read',
      updatePermissionFn: updateFn,
    });

    expect(updateFn).toHaveBeenCalledWith('share-456', {
      permission: 'read',
      encryptedIpnsKey: undefined,
    });
  });
});
