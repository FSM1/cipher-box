/**
 * Folder load operations - fetch and decrypt folder metadata from IPFS/IPNS.
 *
 * Phase 62 stub: read-chain navigation (decrypt + walk Node) is owned by phase 63.
 * These functions throw 'not implemented — phase 63 (read-chain navigation)' until that
 * phase rewires them.
 */

import type { Node } from '@cipherbox/core';
import type { SdkContext } from '../types';
import { withPerf } from '../perf';

/**
 * Fetch and decrypt folder metadata from IPFS.
 *
 * @stub phase 63 — will unseal the PublishedNode from IPFS and return the decrypted Node.
 *
 * @param cid - IPFS CID of the encrypted metadata blob
 * @param folderKey - Decrypted AES-256 folder key (rootReadKey or childReadKey)
 * @param ctx - SDK context for IPFS access
 * @returns Decrypted Node (phase 63 implements the read-chain unseal + decode)
 */
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<Node> {
  return withPerf('folder:fetch-decrypt', async () => {
    void cid;
    void folderKey;
    void ctx;
    throw new Error('not implemented — phase 63 (read-chain navigation)');
  });
}

/**
 * Load a folder's metadata from IPNS.
 *
 * @stub phase 63 — will resolve IPNS, fetch PublishedNode, unseal + walk the read-chain.
 *
 * @returns Decrypted Node, sequence number, and CID, or null if IPNS not found
 */
export async function loadFolderMetadata(params: {
  ipnsName: string;
  folderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<{
  metadata: Node;
  sequenceNumber: bigint;
  cid: string;
} | null> {
  return withPerf('folder:load', async () => {
    void params;
    throw new Error('not implemented — phase 63 (read-chain navigation)');
  });
}
