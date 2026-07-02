/**
 * Shared key-wrapping utilities for ECIES re-wrapping operations + read-chain
 * subtree traversal (node/v3 model, D-02).
 *
 * `resolveChildNodeIdentity` walks ONE hop of the read-chain for a single
 * `SealedChildRef`: it fetches the child's own `PublishedNode` (plaintext
 * `id`/`kind`/`generation`, needed for the child-readkey AAD) and derives the
 * child's own readKey via `unsealChildReadKey` using the PARENT-MIRROR
 * generation (`childRef.generation`) as the AAD input -- never the child's own
 * envelope generation (generation-source rule, mirrors sdk-core's
 * `navigateReadChain` / web's `resolveFileMetadata`, 68.1-04/07).
 *
 * `collectChildKeys` DFS-walks a folder subtree using that same primitive,
 * ECIES-wrapping each descendant's readKey for a target public key.
 *
 * IMPORTANT (architecture note, D-06/D-07): the live grant model
 * (`sdk-core/share/grant.ts` issueReadGrant/claimInvite, and the `/shares` +
 * `/shares/invites` REST endpoints) grants read access to an ENTIRE subtree
 * with a SINGLE ECIES wrap of the subtree root's readKey -- the recipient
 * recovers every descendant key on demand via the read-chain at read time
 * (`navigateReadChain`), not via a pre-computed per-child key array. Likewise
 * a write grant wraps only the ROOT writeKey (`writeDescriptorRef`), never a
 * per-child write-key fan-out. `ChildKeyDto`/`collectChildKeys` therefore has
 * NO live consumer in the current share/invite creation flow (ShareDialog.tsx
 * and invite.service.ts call `resolveChildNodeIdentity` directly instead).
 * This function is kept functional (not a throwing stub) because it is a
 * genuinely correct, reusable read-chain subtree utility and is required as
 * a plan artifact; see the 68.1-11 SUMMARY for the full architecture note.
 */

import { unsealChildReadKey, unsealNode } from '@cipherbox/core';
import type { SealedChildRef, PublishedNode, NodeKind } from '@cipherbox/core';
import { wrapKey, bytesToHex } from '@cipherbox/crypto';
import type { ChildKeyDto } from '@cipherbox/api-client';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchFromIpfs } from '../api/ipfs';
import { logger } from '../logger';

/** Bounded fan-out for concurrent read-chain hops during subtree traversal. */
const COLLECT_CONCURRENCY = 4;

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
 * Used both by `collectChildKeys` (subtree DFS) and directly by ShareDialog /
 * invite.service to derive the shared item's OWN readKey + nodeId/generation
 * before issuing a grant (the grant root IS the shared item, not its parent).
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

/** Run `fn` over `items` with a bounded number of concurrent in-flight calls. */
async function mapWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>
): Promise<void> {
  let cursor = 0;
  async function worker(): Promise<void> {
    while (cursor < items.length) {
      const current = cursor;
      cursor += 1;
      await fn(items[current]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
}

/**
 * Collect all descendant read-chain keys from a folder subtree, ECIES-wrapped
 * for a target public key.
 *
 * DFS the subtree via `SealedChildRef.readKeySealed`, bounded to
 * {@link COLLECT_CONCURRENCY} concurrent read-chain hops. Tolerates an
 * unreadable descendant (logs + skips that branch rather than aborting the
 * whole walk) and reports progress via `onProgress` after each wrapped key.
 *
 * `permission` does not currently change behavior: the live grant model wraps
 * write access at the SHARE ROOT only (a single `writeDescriptorRef`), never
 * per descendant -- see the module-level architecture note. The parameter is
 * retained for signature/API stability and to keep the door open for a future
 * per-child write-key fan-out if the grant model changes.
 *
 * @param children - The subtree's top-level SealedChildRef list (a folder's own children)
 * @param folderKey - The readKey of the folder that owns `children` (unwrapping key)
 * @param _ownerPrivateKey - Unused under the node/v3 symmetric read-chain (no ECIES
 *   unwrap is needed to traverse SealedChildRef entries); retained for signature stability.
 * @param targetPubKeyBytes - 65-byte uncompressed secp256k1 public key to wrap for
 * @param _permission - See the doc note above; currently does not affect output
 * @param onProgress - Invoked with the running wrapped-key count after each key
 * @security Zeroes every derived readKey after wrapping (and after any subfolder
 *   descent completes). NEVER zeroes `folderKey` / `_ownerPrivateKey` -- caller-owned (D-09).
 */
export async function collectChildKeys(
  children: SealedChildRef[],
  folderKey: Uint8Array,
  _ownerPrivateKey: Uint8Array,
  targetPubKeyBytes: Uint8Array,
  _permission: 'read' | 'write',
  onProgress: (wrapped: number) => void
): Promise<ChildKeyDto[]> {
  const results: ChildKeyDto[] = [];
  let wrappedCount = 0;

  async function walk(refs: SealedChildRef[], parentReadKey: Uint8Array): Promise<void> {
    await mapWithConcurrency(refs, COLLECT_CONCURRENCY, async (ref) => {
      let childReadKey: Uint8Array | null = null;
      try {
        const identity = await resolveChildNodeIdentity(ref, parentReadKey);
        childReadKey = identity.readKey;

        const encryptedKey = bytesToHex(await wrapKey(childReadKey, targetPubKeyBytes));
        results.push({
          keyType: identity.kind === 'file' ? 'file' : 'folder',
          itemId: identity.nodeId,
          encryptedKey,
        });
        wrappedCount += 1;
        onProgress(wrappedCount);

        if (identity.kind !== 'file') {
          const node = await unsealNode(identity.published, childReadKey);
          if (node.children && node.children.length > 0) {
            await walk(node.children, childReadKey);
          }
        }
      } catch (err) {
        logger.warn(`[collectChildKeys] skipping unreadable descendant ${ref.ipnsName}`, err);
      } finally {
        childReadKey?.fill(0);
      }
    });
  }

  await walk(children, folderKey);
  return results;
}
