/**
 * Folder load operations - fetch and decrypt folder metadata from IPFS/IPNS.
 *
 * Composes the Phase-62 node/v3 codec (unsealNode) with IPFS fetch + IPNS resolve
 * to provide single-hop folder metadata loading. Does NOT zero the readKey/folderKey
 * parameter — the caller is the terminal owner (D-09).
 */

import { unsealNode } from '@cipherbox/core';
import type { Node, PublishedNode } from '@cipherbox/core';
import type { SdkContext } from '../types';
import { withPerf } from '../perf';
import { fetchFromIpfs } from '../ipfs';
import { resolveIpnsRecord } from '../ipns';

/**
 * Fetch and decrypt folder metadata from IPFS.
 *
 * Fetches the raw PublishedNode envelope from IPFS, JSON-parses it, and unseals
 * the read-body using the supplied folder read key via the Phase-62 codec.
 *
 * @param cid       - IPFS CID of the encrypted PublishedNode JSON
 * @param folderKey - 32-byte AES-256 read key (rootReadKey or childReadKey)
 * @param ctx       - SDK context for IPFS access
 * @returns Decrypted in-memory Node
 *
 * @security Does NOT zero `folderKey` — caller is the terminal owner (D-09).
 */
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<Node> {
  return withPerf('folder:fetch-decrypt', async () => {
    const raw = await fetchFromIpfs(ctx, cid);
    const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
    return unsealNode(published, folderKey);
  });
}

/**
 * Load a folder's metadata from IPNS.
 *
 * Resolves the IPNS record to find the current CID, then fetches and decrypts
 * the PublishedNode envelope. Returns null when the IPNS record is absent (404).
 *
 * @param params.ipnsName  - IPNS k51 name of the folder node
 * @param params.folderKey - 32-byte AES-256 read key
 * @param params.ctx       - SDK context for IPNS + IPFS access
 * @returns Decrypted Node, sequence number, and current CID; or null if record absent
 *
 * @security Does NOT zero `folderKey` — caller is the terminal owner (D-09).
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
    const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
    if (!resolved) return null;
    const metadata = await fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx);
    return { metadata, sequenceNumber: resolved.sequenceNumber, cid: resolved.cid };
  });
}
