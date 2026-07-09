/**
 * Shared key-wrapping utilities for ECIES re-wrapping operations (node/v3
 * model, D-02).
 *
 * `resolveChildNodeIdentity` walks ONE hop of the read-chain for a single
 * `SealedChildRef`, recovering the child's own readKey + plaintext node
 * identity. It is a thin delegate to `client.resolveChildIdentity` (the SDK
 * facade, 68.2-07 Rule-2 addition) -- the web no longer performs the raw
 * IPNS resolve, raw IPFS fetch, or child-readkey unseal itself (D-07).
 *
 * Architecture note (D-06/D-07): the live grant model
 * (`sdk-core/share/grant.ts` issueReadGrant/claimInvite, and the `/shares` +
 * `/shares/invites` REST endpoints) grants read access to an ENTIRE subtree
 * with a SINGLE ECIES wrap of the subtree root's readKey -- the recipient
 * recovers every descendant key on demand via the read-chain at read time
 * (`navigateReadChain`), not via a pre-computed per-child key array. Likewise
 * a write grant wraps only the ROOT writeKey (`encryptedWriteKey`), never a
 * per-child write-key fan-out.
 */

import type { SealedChildRef, PublishedNode, NodeKind } from '@cipherbox/core';
import { getSdkClient } from '../sdk-provider';

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
  return getSdkClient().resolveChildIdentity(childRef, parentReadKey);
}
