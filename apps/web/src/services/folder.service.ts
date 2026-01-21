/**
 * Folder Service - Folder CRUD operations with encryption
 *
 * Handles folder creation, loading, and metadata updates with
 * client-side encryption using @cipherbox/crypto.
 */

import {
  generateEd25519Keypair,
  deriveIpnsName,
  generateRandomBytes,
  wrapKey,
  bytesToHex,
  encryptFolderMetadata,
  type FolderMetadata,
  type FolderEntry,
  type FolderChild,
} from '@cipherbox/crypto';
import { addToIpfs } from '../lib/api/ipfs';
import { createAndPublishIpnsRecord } from './ipns.service';
import type { FolderNode } from '../stores/folder.store';

/** Maximum folder nesting depth per FOLD-03 */
const MAX_FOLDER_DEPTH = 20;

/**
 * Calculate the depth of a folder from root.
 * Root folder has depth 0, immediate children have depth 1, etc.
 *
 * Used for enforcing FOLD-03 depth limit of 20.
 *
 * @param folderId - Folder ID to calculate depth for (null = root)
 * @param folders - Current folder tree
 * @returns Depth from root (0 for root)
 */
export function getDepth(folderId: string | null, folders: Record<string, FolderNode>): number {
  if (folderId === null) return 0; // root is depth 0

  let depth = 0;
  let currentId: string | null = folderId;

  while (currentId !== null) {
    const folder: FolderNode | undefined = folders[currentId];
    if (!folder) break;
    depth++;
    currentId = folder.parentId;
  }

  return depth;
}

/**
 * Load a folder's metadata from IPNS.
 *
 * For now, returns an empty folder structure. Actual metadata fetch
 * from IPFS and decryption will be implemented in Phase 05-04.
 *
 * @param folderId - Folder ID (null for root, or UUID)
 * @param folderKey - Decrypted AES-256 key for this folder
 * @param ipnsPrivateKey - Decrypted Ed25519 private key for IPNS
 * @param ipnsName - IPNS name for this folder
 */
export async function loadFolder(
  folderId: string | null,
  folderKey: Uint8Array,
  ipnsPrivateKey: Uint8Array,
  ipnsName: string
): Promise<FolderNode> {
  // TODO: Implement in 05-04
  // 1. Resolve IPNS to get current metadata CID (or use cached)
  // 2. Fetch encrypted metadata from IPFS gateway
  // 3. Decrypt with folderKey
  // 4. Return FolderNode with decrypted children

  // For now, return empty folder placeholder
  return {
    id: folderId ?? 'root',
    name: folderId ? 'Folder' : 'My Vault',
    ipnsName,
    parentId: null,
    children: [],
    isLoaded: true,
    isLoading: false,
    sequenceNumber: 0n,
    folderKey,
    ipnsPrivateKey,
  };
}

/**
 * Create a new subfolder with generated keys.
 *
 * Generates new Ed25519 IPNS keypair and AES-256 folder key,
 * wraps them with the user's public key for storage.
 *
 * @param params.parentFolderId - Parent folder ID (null for root)
 * @param params.name - Folder name
 * @param params.userPublicKey - User's secp256k1 public key for ECIES wrapping
 * @param params.folders - Current folder tree (for depth checking)
 * @returns Created folder entry and decrypted keys
 * @throws Error if depth limit exceeded (FOLD-03)
 */
export async function createFolder(params: {
  parentFolderId: string | null;
  name: string;
  userPublicKey: Uint8Array;
  folders: Record<string, FolderNode>;
}): Promise<{
  folder: FolderEntry;
  ipnsPrivateKey: Uint8Array;
  folderKey: Uint8Array;
}> {
  // 1. Check depth limit (FOLD-03)
  const parentDepth = getDepth(params.parentFolderId, params.folders);
  if (parentDepth >= MAX_FOLDER_DEPTH) {
    throw new Error(`Cannot create folder: maximum depth of ${MAX_FOLDER_DEPTH} exceeded`);
  }

  // 2. Generate Ed25519 keypair for folder IPNS
  const ipnsKeypair = await generateEd25519Keypair();
  const ipnsName = await deriveIpnsName(ipnsKeypair.publicKey);

  // 3. Generate random AES-256 folder key
  const folderKey = generateRandomBytes(32);

  // 4. Wrap keys with user's public key (ECIES encryption)
  // The 64-byte libp2p format private key (privateKey || publicKey) is wrapped
  const ipnsPrivateKeyEncrypted = bytesToHex(
    await wrapKey(ipnsKeypair.privateKey, params.userPublicKey)
  );
  const folderKeyEncrypted = bytesToHex(await wrapKey(folderKey, params.userPublicKey));

  // 5. Create folder entry for parent's metadata
  const now = Date.now();
  const folder: FolderEntry = {
    type: 'folder',
    id: crypto.randomUUID(),
    name: params.name,
    ipnsName,
    ipnsPrivateKeyEncrypted,
    folderKeyEncrypted,
    createdAt: now,
    modifiedAt: now,
  };

  return { folder, ipnsPrivateKey: ipnsKeypair.privateKey, folderKey };
}

/**
 * Update folder metadata and publish to IPNS.
 *
 * Encrypts the metadata with the folder key, uploads to IPFS,
 * and publishes an updated IPNS record pointing to the new CID.
 *
 * @param params.folderId - Folder being updated
 * @param params.children - New children array
 * @param params.folderKey - Decrypted AES-256 folder key
 * @param params.ipnsPrivateKey - Decrypted Ed25519 IPNS private key
 * @param params.ipnsName - IPNS name for this folder
 * @param params.sequenceNumber - Current sequence number
 * @param params.encryptedIpnsPrivateKey - TEE-wrapped key (first publish only)
 * @param params.keyEpoch - TEE key epoch (required with encryptedIpnsPrivateKey)
 * @returns New CID and sequence number
 */
export async function updateFolderMetadata(params: {
  folderId: string;
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint }> {
  // 1. Create folder metadata
  const metadata: FolderMetadata = {
    version: 'v1',
    children: params.children,
  };

  // 2. Encrypt metadata with folder key
  const encrypted = await encryptFolderMetadata(metadata, params.folderKey);

  // 3. Upload to IPFS via backend relay
  const blob = new Blob([JSON.stringify(encrypted)], {
    type: 'application/json',
  });
  const { cid } = await addToIpfs(blob);

  // 4. Publish IPNS record pointing to new CID
  const newSeq = params.sequenceNumber + 1n;
  await createAndPublishIpnsRecord({
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsName: params.ipnsName,
    metadataCid: cid,
    sequenceNumber: newSeq,
    encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
    keyEpoch: params.keyEpoch,
  });

  return { cid, newSequenceNumber: newSeq };
}
