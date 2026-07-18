/**
 * @cipherbox/sdk - Shared-write operations (Phase 65 write-body model)
 *
 * Implements the structured recursive write chain (WRITE-01) using the Phase-62
 * codec: sealNode / unsealNode / sealChildReadKey / sealChildWriteKey. Six
 * operations on the write-body model with no share-key fan-out (D-02).
 *
 * Security invariants:
 *   - ipnsPrivateKey is NEVER a top-level parameter — it lives inside the sealed
 *     write-body and is derived by unsealing with writeKey (WRITE-01).
 *   - No write field is ever placed on SealedChildRef (NODE-03 / §2.2).
 *   - Zero only minted keys on failure paths; never zero caller-supplied keys (D-09).
 *   - An offline co-writer whose target was rotated out gets a typed
 *     CannotWriteUntilRefetchError — no grace/notification/retry (WRITE-03/D-03).
 *
 * WriteChildRef.childId is a UUID (crypto.randomUUID()) matching the child's Node.id.
 * deleteFromSharedFolder/moveInSharedFolder match write-body entries by UUID childId;
 * callers must supply childNodeId (the UUID) alongside itemId (the IPNS name) so that
 * read-body and write-body deletions use the correct key type each.
 */

import type { SdkContext } from '@cipherbox/sdk-core';
import type {
  SealedChildRef,
  WriteChildRef,
  NodeKind,
  PublishedNode,
  Node,
  NodeContent,
} from '@cipherbox/core';
import {
  sealNode,
  unsealNode,
  sealChildReadKey,
  sealChildWriteKey,
  unsealChildWriteKey,
} from '@cipherbox/core';
import {
  generateRandomBytes,
  generateIv,
  generateEd25519Keypair,
  deriveIpnsName,
  encryptAesGcm,
} from '@cipherbox/crypto';
import type { ShareKeyEntryDtoKeyType } from '@cipherbox/api-client';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Re-export the canonical share key type for consumers */
export type ShareKeyType = ShareKeyEntryDtoKeyType;

/**
 * Result from publishNodeFn; tombstoned=true signals the write target was
 * rotated out (mock seam for Phase-66 live publish-gate reject).
 */
export type PublishNodeResult =
  | { tombstoned: true }
  | { tombstoned: false; newSequenceNumber: bigint };

/**
 * Context for shared-write operations on a write-capable folder node.
 *
 * Carries the write-body model keys: readKey decrypts the read-body,
 * writeKey decrypts the write-body (which holds ipnsPrivateKey).
 * All transport operations are injected as callbacks (D-02) so operations
 * are mock-testable without live apps/api.
 */
export type SharedWriteContext = {
  /** SDK context for IPFS/IPNS API access */
  ctx: SdkContext;
  /** 32-byte AES key for sealing/unsealing the node's read-body */
  readKey: Uint8Array;
  /** 32-byte AES key for sealing/unsealing the node's write-body */
  writeKey: Uint8Array;
  /** Current on-wire published envelope — unsealed to obtain ipnsPrivateKey + writeChildren */
  publishedNode: PublishedNode;
  /** IPNS name of the current folder */
  ipnsName: string;
  /** Current IPNS sequence number for conflict detection */
  sequenceNumber: bigint;
  /** Current read-body children (pre-unsealed for convenience) */
  children: SealedChildRef[];
  /** Sharer's secp256k1 public key */
  ownerPublicKey: Uint8Array;
  /** Current user's secp256k1 public key */
  recipientPublicKey: Uint8Array;
  /** Share ID */
  shareId: string;
  /**
   * Transport-decoupled node publish seam (D-02).
   * Wraps addToIpfs + createAndPublishIpnsRecord.
   * Returns { tombstoned: true } when the IPNS name has been rotated out
   * (signals a revoked co-writer — Phase-66 live gate; mock here: WRITE-03).
   */
  publishNodeFn: (params: {
    published: PublishedNode;
    ipnsName: string;
    ipnsPrivateKey: Uint8Array;
    sequenceNumber: bigint;
  }) => Promise<PublishNodeResult>;
  /**
   * Transport-decoupled IPFS upload seam (D-02).
   * Returns the IPFS CID of the uploaded bytes.
   */
  addToIpfsFn: (data: Uint8Array) => Promise<{ cid: string }>;
};

// ---------------------------------------------------------------------------
// CannotWriteUntilRefetchError (WRITE-03 / D-03)
// ---------------------------------------------------------------------------

/**
 * Thrown when a co-writer attempts to write to a rotated-out IPNS name.
 *
 * The `code` discriminant (`'CANNOT_WRITE_UNTIL_REFETCH'`) is a string literal
 * (not a TS enum per project convention) so callers can pattern-match without
 * coupling to this module's type hierarchy.
 *
 * No retry, grace period, or notification state is added (D-03; Q1 → Phase 68).
 */
export class CannotWriteUntilRefetchError extends Error {
  readonly code = 'CANNOT_WRITE_UNTIL_REFETCH' as const;

  constructor(ipnsName: string) {
    super(`cannot write until re-fetch: IPNS name ${ipnsName} was rotated out`);
    this.name = 'CannotWriteUntilRefetchError';
  }
}

// ---------------------------------------------------------------------------
// File-local helpers
// ---------------------------------------------------------------------------

/**
 * Build a WriteChildRef by sealing childWriteKey under parentWriteKey (role 0x04).
 *
 * `childId` is the child node's UUID (from Node.id / crypto.randomUUID()).
 * Does NOT zero childWriteKey — caller is the terminal owner (D-09).
 */
async function buildChildWriteLink(
  childWriteKey: Uint8Array,
  parentWriteKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<WriteChildRef> {
  if (childWriteKey.length !== 32) {
    throw new Error(
      `buildChildWriteLink: childWriteKey must be 32 bytes, got ${childWriteKey.length}`
    );
  }
  const writeKeySealed = await sealChildWriteKey(
    childWriteKey,
    parentWriteKey,
    childId,
    childKind,
    childGeneration
  );
  return { childId, writeKeySealed };
}

/**
 * Walk the write chain: unseal a WriteChildRef to recover the child writeKey.
 *
 * The caller must provide child kind and generation (from the child's published
 * envelope or creation context).
 */
async function walkChildWriteKey(
  parentWriteKey: Uint8Array,
  childRef: WriteChildRef,
  childKind: NodeKind,
  childGeneration: number
): Promise<Uint8Array> {
  return unsealChildWriteKey(
    childRef.writeKeySealed,
    parentWriteKey,
    childRef.childId,
    childKind,
    childGeneration
  );
}

/**
 * Unseal the parent write-body, validate it, and return ipnsPrivateKey + writeChildren.
 * Throws if writeKey is wrong or write-body is absent.
 */
async function unsealParentWriteBody(swCtx: SharedWriteContext): Promise<{
  ipnsPrivateKey: Uint8Array;
  writeChildren: WriteChildRef[];
  parentNode: Node;
}> {
  const parentNode = await unsealNode(swCtx.publishedNode, swCtx.readKey, swCtx.writeKey);
  if (!parentNode.writeBody) {
    throw new Error(
      'shared-write: parent node has no writeBody — writeKey may be incorrect or node is read-only'
    );
  }
  return {
    ipnsPrivateKey: parentNode.writeBody.ipnsPrivateKey,
    writeChildren: parentNode.writeBody.writeChildren,
    parentNode,
  };
}

/**
 * Publish a sealed node; throw CannotWriteUntilRefetchError if tombstoned.
 * Returns the new sequence number on success.
 */
async function publishOrThrow(
  swCtx: SharedWriteContext,
  published: PublishedNode,
  ipnsName: string,
  ipnsPrivateKey: Uint8Array,
  sequenceNumber: bigint
): Promise<bigint> {
  const result = await swCtx.publishNodeFn({
    published,
    ipnsName,
    ipnsPrivateKey,
    sequenceNumber,
  });
  if (result.tombstoned) {
    throw new CannotWriteUntilRefetchError(ipnsName);
  }
  return result.newSequenceNumber;
}

/**
 * Re-seal and re-publish a parent node with updated children and writeChildren.
 * Returns the new published children and new sequence number.
 */
async function resealAndPublishParent(
  swCtx: SharedWriteContext,
  parentNode: Node,
  newChildren: SealedChildRef[],
  ipnsPrivateKey: Uint8Array,
  writeChildren: WriteChildRef[],
  modifiedAt: number
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
  publishedParent: PublishedNode;
}> {
  const updatedParent: Node = {
    ...parentNode,
    modifiedAt,
    children: newChildren,
    writeBody: {
      ipnsPrivateKey,
      writeChildren,
      // D-03 (Plan 80): preserve the parent's owner-sealed recipient pins
      // VERBATIM across every shared-write reseal. This is the single
      // chokepoint all shared-write ops route through; rebuilding the
      // write-body WITHOUT recipientPins republishes the shared folder root
      // pin-less, erasing the owner's pin on the wire — so the owner's next
      // re-resolve reads empty pins and a later upgrade/re-mint hard fails
      // closed (D-03e). Pins are public ECIES keys, copied never rotated
      // (mirrors the six owned client.ts sites + Rust build_folder_metadata,
      // which commit ddb7082e6 fixed but missed this shared-write module).
      ...(parentNode.writeBody?.recipientPins
        ? { recipientPins: parentNode.writeBody.recipientPins }
        : {}),
    },
  };
  const newParentPublished = await sealNode(updatedParent, swCtx.readKey, swCtx.writeKey);
  const newSeq = await publishOrThrow(
    swCtx,
    newParentPublished,
    swCtx.ipnsName,
    ipnsPrivateKey,
    swCtx.sequenceNumber + 1n
  );
  // 68.1-29: return the freshly-published envelope so the client can adopt it
  // into SharedFolderState.publishedNode — a subsequent same-session shared
  // write that unseals a STALE envelope re-publishes an outdated write chain,
  // silently dropping WriteChildRefs inserted by earlier ops (writable-shares
  // 3.3 mkdir dropped 3.2's upload write-link, breaking the 3.4 editor save).
  return {
    publishedChildren: newChildren,
    newSequenceNumber: newSeq,
    publishedParent: newParentPublished,
  };
}

// ---------------------------------------------------------------------------
// Shared-write operations
// ---------------------------------------------------------------------------

/**
 * Create a subfolder in a write-shared folder.
 *
 * Build path: mint child readKey + writeKey + Ed25519 keypair, build child node
 * with write-body (ipnsPrivateKey inside sealed writeBody), sealNode under
 * child readKey/writeKey, publish via seam (seq=1n), then insert SealedChildRef
 * into parent read-body AND WriteChildRef into parent write-body, re-seal+publish
 * the parent.
 */
export async function createSharedSubfolder(
  swCtx: SharedWriteContext,
  params: { name: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
  folderEntry: SealedChildRef;
  publishedParent: PublishedNode;
}> {
  if (swCtx.writeKey.length !== 32) {
    throw new Error(
      `createSharedSubfolder: writeKey must be 32 bytes, got ${swCtx.writeKey.length}`
    );
  }
  if (swCtx.readKey.length !== 32) {
    throw new Error(`createSharedSubfolder: readKey must be 32 bytes, got ${swCtx.readKey.length}`);
  }

  const {
    ipnsPrivateKey: parentIpnsPrivateKey,
    writeChildren: parentWriteChildren,
    parentNode,
  } = await unsealParentWriteBody(swCtx);

  // Mint child keys (we own these — zero on failure paths: D-09)
  let childReadKey: Uint8Array | null = generateRandomBytes(32);
  let childWriteKey: Uint8Array | null = generateRandomBytes(32);
  const childKeypair = generateEd25519Keypair();
  let childIpnsPrivateKey: Uint8Array | null = childKeypair.privateKey;

  try {
    const childIpnsName = await deriveIpnsName(childKeypair.publicKey);
    const childId = crypto.randomUUID();
    const now = Date.now();

    // Build child folder node with write-body
    const childNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: childId,
      generation: 0,
      createdAt: now,
      modifiedAt: now,
      children: [],
      writeBody: {
        ipnsPrivateKey: childIpnsPrivateKey,
        writeChildren: [],
      },
    };

    // Seal child node under child readKey + writeKey (codec — D-05)
    const childPublished = await sealNode(childNode, childReadKey, childWriteKey);

    // Publish child (first publish — sequence number MUST be 1n per strict gate)
    const childPublishResult = await swCtx.publishNodeFn({
      published: childPublished,
      ipnsName: childIpnsName,
      ipnsPrivateKey: childIpnsPrivateKey,
      sequenceNumber: 1n,
    });
    if (childPublishResult.tombstoned) {
      throw new CannotWriteUntilRefetchError(childIpnsName);
    }

    // Build SealedChildRef for parent's read-body (no write field — NODE-03)
    const readKeySealed = await sealChildReadKey(childReadKey, swCtx.readKey, childId, 'folder', 0);
    const folderEntry: SealedChildRef = {
      name: params.name,
      ipnsName: childIpnsName,
      generation: 0,
      versionFloor: 1n,
      readKeySealed,
    };

    // Build WriteChildRef for parent's write-body (write link — role 0x04)
    const writeChildRef = await buildChildWriteLink(
      childWriteKey,
      swCtx.writeKey,
      childId,
      'folder',
      0
    );

    // Re-seal and re-publish parent with updated children + writeChildren
    const newChildren = [...swCtx.children, folderEntry];
    const newWriteChildren = [...parentWriteChildren, writeChildRef];

    const { publishedChildren, newSequenceNumber, publishedParent } = await resealAndPublishParent(
      swCtx,
      parentNode,
      newChildren,
      parentIpnsPrivateKey,
      newWriteChildren,
      now
    );

    // Zero and null minted keys on the success path (clear sensitive bytes before GC)
    childReadKey.fill(0);
    childReadKey = null;
    childWriteKey.fill(0);
    childWriteKey = null;
    childIpnsPrivateKey.fill(0);
    childIpnsPrivateKey = null;

    return { publishedChildren, newSequenceNumber, folderEntry, publishedParent };
  } catch (err) {
    // Zero minted keys on failure — never zero caller-supplied keys (D-09)
    childReadKey?.fill(0);
    childWriteKey?.fill(0);
    childIpnsPrivateKey?.fill(0);
    throw err;
  }
}

/**
 * Upload a file to a write-shared folder.
 *
 * Mints fileKey + fileReadKey + fileWriteKey + file Ed25519 keypair. Encrypts
 * content with fileKey (AES-256-GCM), uploads to IPFS, builds a file node with
 * write-body, seals, publishes (seq=1n), then inserts SealedChildRef + WriteChildRef
 * into the parent and re-publishes.
 */
export async function uploadToSharedFolder(
  swCtx: SharedWriteContext,
  params: { data: Uint8Array; fileName: string; mimeType?: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
  filePointer: SealedChildRef;
  publishedParent: PublishedNode;
}> {
  if (swCtx.writeKey.length !== 32) {
    throw new Error(
      `uploadToSharedFolder: writeKey must be 32 bytes, got ${swCtx.writeKey.length}`
    );
  }
  if (swCtx.readKey.length !== 32) {
    throw new Error(`uploadToSharedFolder: readKey must be 32 bytes, got ${swCtx.readKey.length}`);
  }

  const {
    ipnsPrivateKey: parentIpnsPrivateKey,
    writeChildren: parentWriteChildren,
    parentNode,
  } = await unsealParentWriteBody(swCtx);

  // Mint child keys (we own these — zero on failure paths: D-09)
  let fileKey: Uint8Array | null = generateRandomBytes(32);
  let fileReadKey: Uint8Array | null = generateRandomBytes(32);
  let fileWriteKey: Uint8Array | null = generateRandomBytes(32);
  const fileKeypair = generateEd25519Keypair();
  let fileIpnsPrivateKey: Uint8Array | null = fileKeypair.privateKey;

  try {
    const fileIpnsName = await deriveIpnsName(fileKeypair.publicKey);
    const fileNodeId = crypto.randomUUID();
    const now = Date.now();
    const mimeType = params.mimeType ?? 'application/octet-stream';

    // Encrypt file content with fileKey (AES-256-GCM)
    const iv = generateIv();
    const encryptedContent = await encryptAesGcm(params.data, fileKey, iv);
    const ivBase64 = btoa(String.fromCharCode(...iv));

    // Upload encrypted content to IPFS
    const { cid } = await swCtx.addToIpfsFn(encryptedContent);

    // Build NodeContent (fileKey stored inside sealed read-body — D-07/NODE-02)
    const nodeContent: NodeContent = {
      cid,
      fileIv: ivBase64,
      size: params.data.length,
      mimeType,
      encryptionMode: 'GCM',
      fileKey: fileKey,
      versions: [],
    };

    // Build file node with write-body
    const fileNode: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: fileNodeId,
      generation: 0,
      createdAt: now,
      modifiedAt: now,
      content: nodeContent,
      writeBody: {
        ipnsPrivateKey: fileIpnsPrivateKey,
        writeChildren: [],
      },
    };

    // Seal file node (codec — D-05)
    const filePublished = await sealNode(fileNode, fileReadKey, fileWriteKey);

    // Publish file node (first publish — seq 1n)
    const filePublishResult = await swCtx.publishNodeFn({
      published: filePublished,
      ipnsName: fileIpnsName,
      ipnsPrivateKey: fileIpnsPrivateKey,
      sequenceNumber: 1n,
    });
    if (filePublishResult.tombstoned) {
      throw new CannotWriteUntilRefetchError(fileIpnsName);
    }

    // Build SealedChildRef for parent's read-body (no write field — NODE-03)
    const readKeySealed = await sealChildReadKey(fileReadKey, swCtx.readKey, fileNodeId, 'file', 0);
    const filePointer: SealedChildRef = {
      name: params.fileName,
      ipnsName: fileIpnsName,
      generation: 0,
      versionFloor: 1n,
      readKeySealed,
    };

    // Build WriteChildRef for parent's write-body (role 0x04)
    const writeChildRef = await buildChildWriteLink(
      fileWriteKey,
      swCtx.writeKey,
      fileNodeId,
      'file',
      0
    );

    // Re-seal and re-publish parent
    const newChildren = [...swCtx.children, filePointer];
    const newWriteChildren = [...parentWriteChildren, writeChildRef];

    const { publishedChildren, newSequenceNumber, publishedParent } = await resealAndPublishParent(
      swCtx,
      parentNode,
      newChildren,
      parentIpnsPrivateKey,
      newWriteChildren,
      now
    );

    // Zero and null minted keys on the success path (clear sensitive bytes before GC)
    fileKey.fill(0);
    fileKey = null;
    fileReadKey.fill(0);
    fileReadKey = null;
    fileWriteKey.fill(0);
    fileWriteKey = null;
    fileIpnsPrivateKey.fill(0);
    fileIpnsPrivateKey = null;

    return { publishedChildren, newSequenceNumber, filePointer, publishedParent };
  } catch (err) {
    fileKey?.fill(0);
    fileReadKey?.fill(0);
    fileWriteKey?.fill(0);
    fileIpnsPrivateKey?.fill(0);
    throw err;
  }
}

/**
 * Rename an item in a write-shared folder.
 *
 * Updates the item's display name in the parent's read-body children and
 * re-publishes the parent. Write-body writeChildren are preserved unchanged
 * (rename does not affect the write link).
 *
 * @param params.itemId - IPNS name of the item to rename (unique key in SealedChildRef)
 * @param params.newName - New display name
 */
export async function renameInSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string; newName: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
}> {
  const {
    ipnsPrivateKey: parentIpnsPrivateKey,
    writeChildren: parentWriteChildren,
    parentNode,
  } = await unsealParentWriteBody(swCtx);

  const now = Date.now();
  const targetIdx = swCtx.children.findIndex((c) => c.ipnsName === params.itemId);
  if (targetIdx === -1) {
    throw new Error(`renameInSharedFolder: item not found: ${params.itemId}`);
  }

  const newChildren = swCtx.children.map((c, i) =>
    i === targetIdx ? { ...c, name: params.newName } : c
  );

  return resealAndPublishParent(
    swCtx,
    parentNode,
    newChildren,
    parentIpnsPrivateKey,
    parentWriteChildren,
    now
  );
}

/**
 * Delete an item from a write-shared folder.
 *
 * Removes the item from the parent's read-body children (matched by IPNS name)
 * AND the corresponding WriteChildRef from the write-body (matched by child UUID).
 * Re-publishes the parent.
 *
 * @param params.itemId - IPNS name of the item to remove from the read-body children.
 * @param params.childNodeId - UUID of the child node (WriteChildRef.childId, minted at
 *   creation time via createSharedSubfolder/uploadToSharedFolder). Mirrors
 *   moveInSharedFolder's childNodeId param.
 */
export async function deleteFromSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string; childNodeId: string }
): Promise<{
  publishedChildren: SealedChildRef[];
  newSequenceNumber: bigint;
}> {
  const {
    ipnsPrivateKey: parentIpnsPrivateKey,
    writeChildren: parentWriteChildren,
    parentNode,
  } = await unsealParentWriteBody(swCtx);

  const now = Date.now();

  // Remove from read-body children by IPNS name
  const newChildren = swCtx.children.filter((c) => c.ipnsName !== params.itemId);

  // Remove from write-body writeChildren by UUID (WriteChildRef.childId is a UUID,
  // never an IPNS name — using itemId here would never match and leave a stale entry)
  const newWriteChildren = parentWriteChildren.filter((wc) => wc.childId !== params.childNodeId);

  return resealAndPublishParent(
    swCtx,
    parentNode,
    newChildren,
    parentIpnsPrivateKey,
    newWriteChildren,
    now
  );
}

/**
 * Update a file's content in a write-shared folder.
 *
 * The caller must supply the file's readKey, writeKey, and ipnsPrivateKey
 * (derived from the parent's write chain via walkChildWriteKey). Re-encrypts
 * the content, uploads to IPFS, builds a new file node sealed under the
 * existing keys, and publishes.
 */
export async function updateSharedFile(
  swCtx: SharedWriteContext,
  params: {
    /** SealedChildRef of the file in the parent's read-body */
    fileRef: SealedChildRef;
    /**
     * UUID of the file node — must match WriteChildRef.childId in the parent's write-body.
     * Callers obtain this from the creation result (uploadToSharedFolder returns the childId
     * via the WriteChildRef stored in the parent write-body at upload time).
     */
    fileNodeId: string;
    /** 32-byte AES key for the file node's read-body */
    fileReadKey: Uint8Array;
    /** 32-byte AES key for the file node's write-body */
    fileWriteKey: Uint8Array;
    /** Ed25519 seed (32 bytes) from the file node's writeBody.ipnsPrivateKey */
    fileIpnsPrivateKey: Uint8Array;
    /** Current IPNS sequence number of the file node */
    fileSequenceNumber: bigint;
    /** New raw file content to encrypt and upload */
    newData: Uint8Array;
    /** MIME type for the updated content (optional) */
    mimeType?: string;
    /**
     * Original creation timestamp of the file node (ms since epoch).
     * When supplied, preserved on the rebuilt node; otherwise defaults to now.
     * Phase-68 callers unseal the prior file node and forward this value.
     */
    originalCreatedAt?: number;
    /**
     * Prior version history to carry forward on the rebuilt node.
     * When supplied, preserved on the rebuilt node; otherwise defaults to [].
     * Phase-68 callers unseal the prior file node and forward this value.
     */
    originalVersions?: NodeContent['versions'];
  }
): Promise<void> {
  if (params.fileReadKey.length !== 32) {
    throw new Error(
      `updateSharedFile: fileReadKey must be 32 bytes, got ${params.fileReadKey.length}`
    );
  }
  if (params.fileWriteKey.length !== 32) {
    throw new Error(
      `updateSharedFile: fileWriteKey must be 32 bytes, got ${params.fileWriteKey.length}`
    );
  }
  if (params.fileIpnsPrivateKey.length !== 32) {
    throw new Error(
      `updateSharedFile: fileIpnsPrivateKey must be 32 bytes, got ${params.fileIpnsPrivateKey.length}`
    );
  }

  const mimeType = params.mimeType ?? 'application/octet-stream';
  const now = Date.now();

  // Mint new fileKey for this content revision (we own it — zero on failure: D-09)
  let newFileKey: Uint8Array | null = generateRandomBytes(32);

  try {
    // Encrypt new content
    const iv = generateIv();
    const encryptedContent = await encryptAesGcm(params.newData, newFileKey, iv);
    const ivBase64 = btoa(String.fromCharCode(...iv));

    // Upload encrypted content to IPFS
    const { cid } = await swCtx.addToIpfsFn(encryptedContent);

    // Build updated NodeContent — preserve version history when caller supplies it.
    // Phase-68 callers unseal the prior file node to obtain originalVersions.
    const nodeContent: NodeContent = {
      cid,
      fileIv: ivBase64,
      size: params.newData.length,
      mimeType,
      encryptionMode: 'GCM',
      fileKey: newFileKey,
      versions: params.originalVersions ?? [],
    };

    // Build updated file node — reuse caller-supplied fileNodeId so Node.id
    // stays aligned with WriteChildRef.childId in the parent's write-body.
    // Preserve original createdAt when caller supplies it (Phase-68 passes prior value).
    const fileNode: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: params.fileNodeId,
      generation: params.fileRef.generation,
      createdAt: params.originalCreatedAt ?? now,
      modifiedAt: now,
      content: nodeContent,
      writeBody: {
        ipnsPrivateKey: params.fileIpnsPrivateKey,
        writeChildren: [],
      },
    };

    // Seal file node (codec — D-05)
    const filePublished = await sealNode(fileNode, params.fileReadKey, params.fileWriteKey);

    // Publish file node
    await publishOrThrow(
      swCtx,
      filePublished,
      params.fileRef.ipnsName,
      params.fileIpnsPrivateKey,
      params.fileSequenceNumber + 1n
    );

    newFileKey.fill(0);
    newFileKey = null;
  } catch (err) {
    newFileKey?.fill(0);
    throw err;
  }
}

/**
 * Move an item between two subfolders within a shared write context.
 *
 * Re-seals the child's readKey under the destination parent's readKey and
 * moves WriteChildRef from src to dest write-body.
 *
 * @param params.srcCtx - Source parent write context
 * @param params.destCtx - Destination parent write context
 * @param params.itemId - IPNS name of the item to move
 * @param params.childNodeId - UUID of the child node (for write-body matching)
 * @param params.childKind - NodeKind of the child (for AAD binding)
 * @param params.childGeneration - Generation of the child (for AAD binding)
 * @param params.childReadKey - 32-byte readKey of the child node (caller-derived)
 * @param params.childWriteKey - Optional 32-byte writeKey of the child node (for write-body re-link)
 */
export async function moveInSharedFolder(params: {
  srcCtx: SharedWriteContext;
  destCtx: SharedWriteContext;
  itemId: string;
  childNodeId: string;
  childKind: NodeKind;
  childGeneration: number;
  childReadKey: Uint8Array;
  childWriteKey?: Uint8Array;
}): Promise<{
  srcResult: { publishedChildren: SealedChildRef[]; newSequenceNumber: bigint };
  destResult: { publishedChildren: SealedChildRef[]; newSequenceNumber: bigint };
}> {
  const { srcCtx, destCtx, itemId, childNodeId, childKind, childGeneration, childReadKey } = params;

  // Unseal both parent write-bodies
  const {
    ipnsPrivateKey: srcIpnsPrivateKey,
    writeChildren: srcWriteChildren,
    parentNode: srcParentNode,
  } = await unsealParentWriteBody(srcCtx);

  const {
    ipnsPrivateKey: destIpnsPrivateKey,
    writeChildren: destWriteChildren,
    parentNode: destParentNode,
  } = await unsealParentWriteBody(destCtx);

  // Find the child in src's read-body
  const movedChild = srcCtx.children.find((c) => c.ipnsName === itemId);
  if (!movedChild) {
    throw new Error(`moveInSharedFolder: item not found in src: ${itemId}`);
  }

  const now = Date.now();

  // Re-seal the child's readKey under the destination parent's readKey (Plan-02 restore pattern)
  const newReadKeySealed = await sealChildReadKey(
    childReadKey,
    destCtx.readKey,
    childNodeId,
    childKind,
    childGeneration
  );

  const destChildRef: SealedChildRef = {
    ...movedChild,
    readKeySealed: newReadKeySealed,
  };

  // Remove from src, add to dest (read-body)
  const srcNewChildren = srcCtx.children.filter((c) => c.ipnsName !== itemId);
  const destNewChildren = [...destCtx.children, destChildRef];

  // Handle write-body move
  const srcWriteChild = srcWriteChildren.find((wc) => wc.childId === childNodeId);
  const srcNewWriteChildren = srcWriteChildren.filter((wc) => wc.childId !== childNodeId);
  let destNewWriteChildren = destWriteChildren;

  // Derive child writeKey: prefer caller-supplied; fall back to walking the src write-body.
  // Track whether we derived the key so we can zero it after use (D-09: never zero caller-supplied).
  let resolvedChildWriteKey: Uint8Array | undefined = params.childWriteKey;
  let didDeriveWriteKey = false;
  if (!resolvedChildWriteKey && srcWriteChild) {
    resolvedChildWriteKey = await walkChildWriteKey(
      srcCtx.writeKey,
      srcWriteChild,
      childKind,
      childGeneration
    );
    didDeriveWriteKey = true;
  }
  if (!resolvedChildWriteKey) {
    throw new Error(
      `moveInSharedFolder: write link not found for child ${childNodeId} — cannot build destination write link`
    );
  }

  try {
    // Re-seal the child's writeKey under the destination parent's writeKey
    const destWriteChildRef = await buildChildWriteLink(
      resolvedChildWriteKey,
      destCtx.writeKey,
      childNodeId,
      childKind,
      childGeneration
    );
    destNewWriteChildren = [...destWriteChildren, destWriteChildRef];
  } finally {
    // Zero derived key immediately after use; never zero caller-supplied key (D-09)
    if (didDeriveWriteKey) {
      resolvedChildWriteKey.fill(0);
    }
  }

  // Publish destination first — if src removal subsequently fails, the item is
  // duplicated (recoverable) rather than orphaned (unrecoverable).
  const destResult = await resealAndPublishParent(
    destCtx,
    destParentNode,
    destNewChildren,
    destIpnsPrivateKey,
    destNewWriteChildren,
    now
  );

  // Remove from source only after destination is confirmed published.
  const srcResult = await resealAndPublishParent(
    srcCtx,
    srcParentNode,
    srcNewChildren,
    srcIpnsPrivateKey,
    srcNewWriteChildren,
    now
  );

  return { srcResult, destResult };
}
