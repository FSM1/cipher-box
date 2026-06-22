/**
 * Folder load operations - fetch and decrypt folder metadata from IPFS/IPNS.
 */

import { decryptFolderMetadata } from '@cipherbox/core';
import type { FolderMetadata, EncryptedFolderMetadata } from '@cipherbox/core';
import type { SdkContext } from '../types';
import { fetchFromIpfs } from '../ipfs';
import { resolveIpnsRecord } from '../ipns';
import { withPerf } from '../perf';

/**
 * Fetch and decrypt folder metadata from IPFS.
 *
 * @param cid - IPFS CID of the encrypted metadata blob
 * @param folderKey - Decrypted AES-256 folder key
 * @param ctx - SDK context for IPFS access
 * @returns Decrypted folder metadata (v2)
 */
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<FolderMetadata> {
  return withPerf('folder:fetch-decrypt', async () => {
    const encryptedBytes = await fetchFromIpfs(ctx, cid);

    // All folder metadata (including root) is v1 JSON {iv, data}.
    // v2 blob format is only for the vault key blob (separate IPNS name).
    try {
      const encryptedJson = new TextDecoder().decode(encryptedBytes);
      const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
      return await decryptFolderMetadata(encrypted, folderKey);
    } catch (cause) {
      throw new Error(
        `Failed to decode or decrypt folder metadata for CID ${cid}: ${String(cause)}`,
        { cause }
      );
    }
  });
}

/**
 * Load a folder's metadata from IPNS.
 *
 * Resolves the folder's IPNS name to get the current metadata CID,
 * fetches and decrypts the metadata.
 *
 * @returns Decrypted folder metadata, sequence number, and CID, or null if IPNS not found
 */
export async function loadFolderMetadata(params: {
  ipnsName: string;
  folderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{
  metadata: FolderMetadata;
  sequenceNumber: bigint;
  cid: string;
} | null> {
  return withPerf('folder:load', async () => {
    const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
    if (!resolved) return null;

    const metadata = await fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx);

    return {
      metadata,
      sequenceNumber: resolved.sequenceNumber,
      cid: resolved.cid,
    };
  });
}
