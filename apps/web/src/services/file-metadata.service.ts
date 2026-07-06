/**
 * File Metadata Service - Per-file Node operations
 *
 * `resolveFileMetadata` is implemented (68.1-04) using the web-native read-chain
 * primitives — `resolveIpnsRecord` (ipns.service, ROT-07 anti-rollback gated) and
 * `fetchFromIpfs` (lib/api/ipfs, ctx-free relay client) — plus `@cipherbox/core`'s
 * `unsealChildReadKey`/`unsealNode` to recover the file's own readKey from its
 * `SealedChildRef` (sealed under the parent folder's readKey) and unseal its
 * `NodeContent`. This mirrors sdk-core's `resolveFileMetadata`
 * (packages/sdk-core/src/file/index.ts, 68.1-07) but sourced through the web's own
 * ctx-less IPNS/IPFS clients (which additionally apply the ROT-07 durable
 * anti-rollback floor sdk-core's raw resolveIpnsRecord does not) rather than the
 * sdk-core ctx-based helpers, since the web app has no `SdkContext` bridge.
 *
 * `resolveFileMetadata` is a deletion target for 68.2-11 (SC#1 read-chain
 * collapse) — its callers are rewired in 68.2-06/07/08 onto the SDK facade. The
 * three pure version-transform helpers that used to live in this file
 * (`shouldCreateVersion`/`computeRestoreVersionUpdate`/`computeDeleteVersionUpdate`)
 * were relocated to `../lib/version-transforms.ts` in 68.2-06 (RESEARCH Pitfall 4)
 * — they are NOT part of the read chain and must survive this file's deletion.
 */

import type { SealedChildRef, NodeContent, PublishedNode } from '@cipherbox/core';
import { unsealNode, unsealChildReadKey } from '@cipherbox/core';
import { resolveIpnsRecord } from './ipns.service';
import { fetchFromIpfs } from '../lib/api/ipfs';

/**
 * Resolve a file Node's content.
 *
 * `fileRef` is the file's `SealedChildRef` as it lives in the parent folder's
 * children (carries `readKeySealed` + `generation`, needed to derive the file's
 * own readKey); `folderKey` is the parent folder's decrypted readKey.
 *
 * Two-step read-chain hop (mirrors `navigateReadChain` / client.ts `dfsFindFolder`
 * generation-source rule — `fileRef.generation` is the PARENT MIRROR, never the
 * file's own envelope generation):
 *   1. Resolve + fetch the file's `PublishedNode` envelope (`kind`/`id` are
 *      plaintext — needed for the child-readkey AAD).
 *   2. `unsealChildReadKey(fileRef.readKeySealed, folderKey, envelope.id, 'file',
 *      fileRef.generation)` recovers the file's own readKey, then `unsealNode`
 *      unseals its `NodeContent`.
 *
 * @security The file readKey recovered here is minted internally by this
 *   function (never returned to the caller) — zeroed on every exit path. The
 *   returned `content.fileKey` is caller-owned and NOT zeroed (D-09), matching
 *   sdk-core's `resolveFileMetadata`.
 */
export async function resolveFileMetadata(
  fileRef: SealedChildRef,
  folderKey: Uint8Array
): Promise<{
  metadata: NodeContent;
  metadataCid: string;
}> {
  const resolved = await resolveIpnsRecord(fileRef.ipnsName, {
    generation: fileRef.generation,
    versionFloor: Number(fileRef.versionFloor),
  });
  if (!resolved) {
    throw new Error(`resolveFileMetadata: IPNS record not found for ${fileRef.ipnsName}`);
  }

  const raw = await fetchFromIpfs(resolved.cid);
  const publishedNode = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;

  let fileReadKey: Uint8Array | null = await unsealChildReadKey(
    fileRef.readKeySealed,
    folderKey,
    publishedNode.id,
    'file',
    fileRef.generation
  );

  try {
    const node = await unsealNode(publishedNode, fileReadKey);
    if (node.kind !== 'file' || !node.content) {
      throw new Error(`resolveFileMetadata: node at ${fileRef.ipnsName} is not a file node`);
    }
    return { metadata: node.content, metadataCid: resolved.cid };
  } finally {
    // fileReadKey is minted internally by this function (recovered from the
    // read-chain, never handed to the caller) — zero it on every exit path.
    fileReadKey.fill(0);
    fileReadKey = null;
  }
}
