/**
 * @cipherbox/sdk - Shared write-body helpers (D-03)
 *
 * `getWriteBodyParams` and `adoptPublishedFolderState` were maintained as two
 * textually-identical copies -- one as a `CipherBoxClient` instance method in
 * `client.ts` (reading `this.ctx` / `this.folderTree`), the other as a
 * stateless free function in `bin/index.ts` (the bin operations module has no
 * `this` to read, so it always took explicit params). Plan 04 made the two
 * `getWriteBodyParams` bodies byte-identical (including the SC#2 fail-closed
 * change), which is the precondition for collapsing them here (72-10 SC#6):
 * a single standalone implementation, taking explicit params, that both
 * `CipherBoxClient` (via a thin delegating private method) and the bin
 * operations module import directly. This removes the drift surface that let
 * the two copies silently disagree (the original SC#2 risk).
 */

import type { SdkContext } from '@cipherbox/sdk-core';
import * as sdkCore from '@cipherbox/sdk-core';
import { unsealNode } from '@cipherbox/core';
import type { SealedChildRef, WriteChildRef, PublishedNode } from '@cipherbox/core';
import type { FolderTree } from './state/folder-tree';
import type { FolderState } from './types';

/**
 * True only for a non-null, exactly-32-byte, not-all-zero writeKey (72-08
 * SC#6 / 72-10 SC#6: single definition shared by `client.ts` and
 * `bin/index.ts` -- replaces the two independent `hasRealWriteKey`-shaped
 * checks that previously lived in each file).
 *
 * Pure read -- a borrow per the D-09 buffer-ownership contract
 * (RESEARCH.md "Buffer Ownership Table"): never mutates or zeroes `wk`.
 */
export function hasRealWriteKey(wk: Uint8Array | null | undefined): boolean {
  return !!wk && wk.length === 32 && !wk.every((b) => b === 0);
}

/**
 * Resolve the write-body params (`writeKey` + current `writeChildren`) a
 * folder publish site must thread into `updateFolderMetadataAndPublish` so
 * the republished owned folder PRESERVES its existing write chain (D-03).
 *
 * Sourcing order:
 *   1. Legacy zero-fallback writeKey (registerFolder/loadFolder without a real
 *      key) -> return `{}` so the publish stays write-body-less, identical to
 *      pre-D-03 behavior. Sealing under a zero key is exactly the
 *      T-68.1-01-03 threat this avoids.
 *   2. In-memory `folder.metadata.writeBody` (populated by ensureFolderLoaded,
 *      which unseals with the real writeKey) -> use its writeChildren directly.
 *   3. Otherwise unseal the CURRENT on-wire node once per operation
 *      (shared-write pattern: unsealNode with readKey+writeKey ->
 *      writeBody.writeChildren). An absent on-wire write-body (pre-D-03
 *      publish) yields `[]` -- the republish then seals a fresh empty
 *      write-body going forward. A write-body that IS present but fails GCM
 *      auth under folder.writeKey propagates as a throw (fail-closed,
 *      T-68.1-01-03) rather than silently dropping entries. A genuinely
 *      transient IPNS resolve miss (record present but momentarily
 *      unresolvable) ALSO fails closed (72-04 SC#2) rather than returning
 *      `writeChildren: []`, which would let the next publish seal an EMPTY
 *      write-body and silently discard the entire write chain -- distinct
 *      from the `!writeSealed` case (a structurally never-write-capable
 *      folder), which stays fail-open (Pitfall 3 / A1).
 *
 * Never zeroes folder.folderKey / folder.writeKey (caller-owned, D-09).
 */
export async function getWriteBodyParams(
  folder: FolderState,
  ctx: SdkContext
): Promise<{ writeKey?: Uint8Array; writeChildren?: WriteChildRef[]; recipientPins?: string[] }> {
  const wk = folder.writeKey;
  if (!hasRealWriteKey(wk)) {
    return {};
  }
  if (folder.metadata?.writeBody) {
    // Surface the recipient pins alongside the write chain (D-03a) so a folder
    // republish preserves them and pin issuance can read the current list
    // without a second resolve.
    return {
      writeKey: wk,
      writeChildren: folder.metadata.writeBody.writeChildren,
      recipientPins: folder.metadata.writeBody.recipientPins,
    };
  }
  const resolved = await sdkCore.resolveIpnsRecord(folder.ipnsName, ctx);
  if (!resolved) {
    throw new Error(
      `getWriteBodyParams: transient IPNS resolve miss for folder ${folder.ipnsName}; refusing to seal an empty write-body and discard the write chain`
    );
  }
  const raw = await sdkCore.fetchFromIpfs(ctx, resolved.cid);
  const published = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
  if (!published.writeSealed) return { writeKey: wk, writeChildren: [] };
  const node = await unsealNode(published, folder.folderKey, wk);
  try {
    return {
      writeKey: wk,
      writeChildren: node.writeBody?.writeChildren ?? [],
      recipientPins: node.writeBody?.recipientPins,
    };
  } finally {
    // D-09: unsealNode just materialized a transient IPNS private key
    // (node.writeBody.ipnsPrivateKey) purely to let us read writeChildren.
    // This function is the terminal owner of that transient buffer -- it is
    // never returned or passed on -- so it must be zeroed here rather than
    // left to linger in memory.
    node.writeBody?.ipnsPrivateKey.fill(0);
  }
}

/**
 * Adopt a successful `updateFolderMetadataAndPublish` result into the
 * in-memory FolderState, INCLUDING the unsealed `metadata` Node mirror when
 * present (68.1-22).
 *
 * `getWriteBodyParams` prefers `metadata.writeBody.writeChildren` and
 * `dfsFindFolder` walks `metadata.writeBody` directly, so leaving the mirror
 * stale after a publish makes the NEXT mutation re-seal an OUTDATED write
 * chain -- silently dropping WriteChildRefs inserted by earlier mutations in
 * the same session. That drop is what made cold-reload DFS descent unable to
 * recover just-created subfolders (GAP-2 symptom) and made
 * resolveShareEncryptedWriteKey fail closed on freshly-created items.
 */
export function adoptPublishedFolderState(
  folderTree: FolderTree,
  folder: FolderState,
  publishedChildren: SealedChildRef[],
  newSequenceNumber: bigint,
  publishedWriteChildren?: WriteChildRef[]
): void {
  folder.children = publishedChildren;
  folder.sequenceNumber = newSequenceNumber;
  folder.lastLoadedAt = Date.now();
  if (folder.metadata) {
    folder.metadata.children = publishedChildren;
    if (publishedWriteChildren) {
      if (folder.metadata.writeBody) {
        folder.metadata.writeBody.writeChildren = publishedWriteChildren;
      } else {
        // 68.1-29: the folder carried a read-only metadata mirror (no
        // write-body -- e.g. loaded via loadFolder, or getWriteBodyParams
        // sourced the chain from the on-wire node rather than the mirror) but
        // this publish sealed a real write chain. CREATE the mirror so the
        // next getWriteBodyParams (prefers metadata.writeBody) and DFS descent
        // (walks metadata.writeBody.writeChildren) see the new WriteChildRefs
        // instead of the absent-mirror fallback that dropped them.
        folder.metadata.writeBody = {
          ipnsPrivateKey: new Uint8Array(folder.ipnsKeypair.privateKey),
          writeChildren: publishedWriteChildren,
        };
      }
    }
  }
  folderTree.set(folder.ipnsName, folder);
}
