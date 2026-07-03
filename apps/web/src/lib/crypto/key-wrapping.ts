/**
 * Shared key-wrapping utilities for ECIES re-wrapping operations (node/v3
 * model, D-02).
 *
 * `resolveChildNodeIdentity` walks ONE hop of the read-chain for a single
 * `SealedChildRef`: it fetches the child's own `PublishedNode` (plaintext
 * `id`/`kind`/`generation`, needed for the child-readkey AAD) and derives the
 * child's own readKey via `unsealChildReadKey` using the PARENT-MIRROR
 * generation (`childRef.generation`) as the AAD input -- never the child's own
 * envelope generation (generation-source rule, mirrors sdk-core's
 * `navigateReadChain` / web's `resolveFileMetadata`, 68.1-04/07).
 *
 * Architecture note (D-06/D-07): the live grant model
 * (`sdk-core/share/grant.ts` issueReadGrant/claimInvite, and the `/shares` +
 * `/shares/invites` REST endpoints) grants read access to an ENTIRE subtree
 * with a SINGLE ECIES wrap of the subtree root's readKey -- the recipient
 * recovers every descendant key on demand via the read-chain at read time
 * (`navigateReadChain`), not via a pre-computed per-child key array. Likewise
 * a write grant wraps only the ROOT writeKey (`writeDescriptorRef`), never a
 * per-child write-key fan-out.
 */

import { unsealChildReadKey } from '@cipherbox/core';
import type { SealedChildRef, PublishedNode, NodeKind } from '@cipherbox/core';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchFromIpfs } from '../api/ipfs';

/** A single child node's own readKey + plaintext identity, recovered via one read-chain hop. */
export type ChildNodeIdentity = {
  /** The child node's own 32-byte AES readKey. Caller-owned once returned (D-09). */
  readKey: Uint8Array;
  /** Plaintext UUID of the child node (from its own PublishedNode envelope). */
  nodeId: string;
  /** Plaintext node kind ('file' | 'folder' | 'root'). */
  kind: NodeKind;
  /** The child node's own current envelope generation (staleness witness for a grant root). */
  generation: number;
  /** The child's fetched PublishedNode envelope (avoids a re-fetch for callers that need it). */
  published: PublishedNode;
};

/**
 * Resolve a single `SealedChildRef`'s own readKey + plaintext node identity by
 * walking one hop of the read-chain.
 *
 * Used by ShareDialog / invite.service to derive the shared item's OWN
 * readKey + nodeId/generation before issuing a grant (the grant root IS the
 * shared item, not its parent).
 *
 * @param childRef - The SealedChildRef as it lives in the parent's children array
 * @param parentReadKey - The parent node's decrypted readKey (unwrapping key)
 * @security Does NOT zero `parentReadKey` -- caller is the terminal owner (D-09).
 *   The returned `readKey` is minted by this call; the caller becomes its
 *   terminal owner and must zero it on their own lifecycle boundary.
 */
export async function resolveChildNodeIdentity(
  childRef: SealedChildRef,
  parentReadKey: Uint8Array
): Promise<ChildNodeIdentity> {
  const resolved = await resolveIpnsRecord(childRef.ipnsName, {
    generation: childRef.generation,
    versionFloor: Number(childRef.versionFloor),
  });
  if (!resolved) {
    throw new Error(`resolveChildNodeIdentity: IPNS record not found for ${childRef.ipnsName}`);
  }

  const raw = await fetchFromIpfs(resolved.cid);
  const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;

  const readKey = await unsealChildReadKey(
    childRef.readKeySealed,
    parentReadKey,
    published.id,
    published.kind,
    childRef.generation // parent-mirror generation-source rule -- never published.generation
  );

  return {
    readKey,
    nodeId: published.id,
    kind: published.kind,
    generation: published.generation,
    published,
  };
}
