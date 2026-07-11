/**
 * @cipherbox/sdk - SDK-owned resolved folder listings (Phase 68.2 Plan 02)
 *
 * The SDK's single per-child metadata answer: given a folder's sealed
 * children (`SealedChildRef[]`) and the parent's readKey, resolves each
 * child's OWN `PublishedNode` through a caller-supplied gated resolve
 * function and assembles a `ResolvedChild[]` -- ipnsName, name, kind, an
 * optional file size, createdAt, modifiedAt, and the child's own IPNS
 * sequence.
 *
 * This subsumes the 68.1 web-side kind-cache, useFileSize, and
 * SealedChildRef size/modifiedAt display-mirror fields as the single
 * source of per-child listing metadata (D-02): the web renders directly
 * from `ResolvedChild` with no web-side per-child resolve or cache.
 *
 * Design: no CipherBoxClient dependency -- the gated resolve (ROT-07,
 * `RotationHighWater.enforceResolved`) and the in-SDK cache both live in
 * `client.ts`, which injects a `GatedResolveFn` here (D-05: the gated
 * resolve is the single read entrypoint; this module never resolves
 * un-gated).
 */

import type { SealedChildRef, PublishedNode, NodeKind } from '@cipherbox/core';
import { unsealChildReadKey, unsealNode } from '@cipherbox/core';

/**
 * The SDK's single per-child listing answer (D-02).
 *
 * `size` is populated for file children only (the child Node's
 * `NodeContent.size`, plaintext byte count) -- always `undefined` for
 * folder/root children. `sequence` is the child's OWN IPNS sequence
 * number, narrowed to `number` (the display/clock granularity this API
 * contracts to; the gated resolve upstream already guards
 * `Number.MAX_SAFE_INTEGER` overflow when `rotationHighWater` is
 * configured).
 */
export type ResolvedChild = {
  ipnsName: string;
  name: string;
  kind: NodeKind;
  size?: number;
  createdAt: number;
  modifiedAt: number;
  sequence: number;
};

/**
 * Resolves one child's PublishedNode envelope + current IPNS sequence
 * number through the caller's gated read path (ROT-07 anti-rollback,
 * `RotationHighWater.enforceResolved` -- see `client.ts`'s
 * `gatedResolveChild`). Returns `null` for a structurally unresolvable hop
 * (absent IPNS record). May also throw (ROT-07 rollback rejection, an
 * unverified-signature record, or a network error) -- `resolveChildren`
 * treats every such failure as a per-child skip (see below).
 */
export type GatedResolveFn = (
  childRef: SealedChildRef
) => Promise<{ published: PublishedNode; sequenceNumber: bigint } | null>;

/**
 * Resolves a folder's sealed children into `ResolvedChild[]`.
 *
 * For each `childRef`: gated-resolves the child's own PublishedNode, then
 * unseals the child's readKey under `parentReadKey` (generation-source
 * rule: `childRef.generation`, the PARENT mirror, NEVER the child's own
 * envelope generation -- §2.6, matching `dfsFindFolder`/
 * `navigateToSubfolder`), then unseals the child's own Node to read its
 * `kind`/`modifiedAt`/`content.size`.
 *
 * Skip semantics: a listing render degrades gracefully rather than failing
 * entirely because of ONE bad sibling. ANY failure resolving/unsealing an
 * individual child -- a structurally absent IPNS record, a ROT-07
 * anti-rollback rejection (T-68.2-01), an unverified-signature record, or a
 * corrupted/unopenable read-body -- is caught per-child and that child is
 * simply omitted from the result; it never fails the whole listing.
 *
 * This does not weaken T-68.2-01's mitigation: the ALREADY-LOADED target
 * folder itself is verified through the Plan-01 gate in
 * `ensureFolderLoaded`/`dfsFindFolder` before this function ever runs (D-05
 * -- the single gated read entrypoint). A sibling child this function can't
 * currently verify is never rendered with attacker-controlled or stale
 * content -- it is simply left out of view, which is an availability
 * trade-off, not a trust violation.
 *
 * Never zeros `parentReadKey` (caller/`FolderState`-owned, D-09). The
 * per-child `childReadKey` minted inside this function IS zeroed once
 * consumed -- this function is its terminal owner (T-68.1-01-01 pattern).
 */
export async function resolveChildren(
  children: SealedChildRef[],
  parentReadKey: Uint8Array,
  gatedResolve: GatedResolveFn
): Promise<ResolvedChild[]> {
  const resolved: ResolvedChild[] = [];

  for (const childRef of children) {
    let childReadKey: Uint8Array | null = null;
    try {
      const childResolved = await gatedResolve(childRef);
      if (!childResolved) continue; // structurally unresolvable hop -- skip, try siblings

      const { published, sequenceNumber } = childResolved;
      childReadKey = await unsealChildReadKey(
        childRef.readKeySealed,
        parentReadKey,
        published.id,
        published.kind,
        childRef.generation // parent mirror -- NEVER published.generation
      );
      const node = await unsealNode(published, childReadKey);
      resolved.push({
        ipnsName: childRef.ipnsName,
        name: childRef.name,
        kind: node.kind,
        size: node.kind === 'file' ? node.content?.size : undefined,
        createdAt: node.createdAt,
        modifiedAt: node.modifiedAt,
        sequence: Number(sequenceNumber),
      });
    } catch {
      // Any per-child resolve/unseal failure -- skip it, don't fail the
      // whole listing (see skip semantics above).
      continue;
    } finally {
      childReadKey?.fill(0);
    }
  }

  return resolved;
}
