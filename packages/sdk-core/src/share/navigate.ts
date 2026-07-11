/**
 * Read-chain navigation — multi-hop walk from grant root to a file leaf.
 *
 * Implements READ-02 / design §2.6, §3.3, §4.6.
 *
 * Algorithm:
 *   1. ONE ECIES unwrap of the grant encryptedReadKey → shareRootReadKey.
 *   2. Resolve + fetch the root PublishedNode.
 *   3. Behind-retry check: envelope generation > rootExpectedGeneration → soft-fail.
 *   4. Unseal root node.
 *   5. Walk path — O(depth) symmetric hops:
 *      a. Find SealedChildRef by ipnsName.
 *      b. Fetch child PublishedNode (plaintext id + kind needed for AAD).
 *      c. unsealChildReadKey using PARENT MIRROR generation (childRef.generation),
 *         NEVER the child envelope generation (generation-source rule, §2.6).
 *      d. unsealNode with the derived child readKey.
 *   6. Return { status: 'ok', content, nodeId } from the file leaf.
 *
 * Security invariants:
 *   - Does NOT zero `recipientPrivKey` — caller is terminal owner (D-09).
 *   - DOES zero navigate-minted intermediates (shareRootReadKey, per-hop childReadKeys) via
 *     a try/finally block so they are wiped on all exit paths (T-63-05 extension).
 *   - Never logs key material (T-63-03).
 *   - A missing IPNS record → revoked (fail-closed, T-63-04).
 *   - An AEAD auth failure during unsealChildReadKey propagates as a throw (not silent success).
 */

import { unsealNode, unsealChildReadKey } from '@cipherbox/core';
import type { NodeContent, PublishedNode } from '@cipherbox/core';
import { unwrapKey, base64ToBytes } from '@cipherbox/crypto';
import { resolveIpnsRecord } from '../ipns';
import { fetchFromIpfs } from '../ipfs';
import type { SdkContext } from '../types';
import { withPerf } from '../perf';

// ---------------------------------------------------------------------------
// Result type (string-literal union — no enums per project convention, D-06)
// ---------------------------------------------------------------------------

/**
 * Typed discriminated result for navigateReadChain (D-06 / §4.6).
 *
 * `'ok'`           — leaf file content and its node UUID recovered successfully.
 * `'behind-retry'` — root was rotated since the grant was issued; caller should
 *                    re-fetch the re-minted grant and retry.
 * `'revoked'`      — grant row absent, IPNS record missing, or SealedChildRef
 *                    absent on the path; hard fail.
 */
export type NavigateResult =
  | { status: 'ok'; content: NodeContent; nodeId: string }
  | { status: 'behind-retry' }
  | { status: 'revoked' };

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Resolve an IPNS name and return the raw PublishedNode envelope.
 *
 * Returns null when the IPNS record is absent (null from resolveIpnsRecord → 404).
 * The caller is responsible for deciding whether absence means `revoked`.
 */
async function fetchPublishedNode(
  ipnsName: string,
  ctx: SdkContext
): Promise<PublishedNode | null> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) return null;
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Walk a read-chain grant from the share root to a file leaf.
 *
 * @param params.encryptedReadKey        - Base64 ECIES-wrapped share-root readKey
 * @param params.recipientPrivKey         - Secp256k1 private key for ECIES unwrap (one op)
 * @param params.shareRootIpnsName        - IPNS k51 name of the grant root node
 * @param params.rootExpectedGeneration   - Generation at which the grant was issued (staleness witness)
 * @param params.path                     - Ordered child ipnsNames root→leaf; empty = root IS the file leaf
 * @param params.ctx                      - SDK context for IPNS + IPFS access
 *
 * @returns `NavigateResult` discriminated union (never throws for expected states;
 *          does throw for unexpected crypto failures such as AEAD auth failures)
 *
 * @security Does NOT zero `recipientPrivKey` — caller is the terminal owner (D-09).
 *   DOES zero navigate-minted intermediates (shareRootReadKey, per-hop childReadKeys)
 *   via a try/finally block so they are wiped on all exit paths (T-63-05 extension).
 *   The recovered content key returned inside `content` is caller-owned and NOT zeroed.
 */
export async function navigateReadChain(params: {
  encryptedReadKey: string;
  recipientPrivKey: Uint8Array;
  shareRootIpnsName: string;
  rootExpectedGeneration: number;
  path: string[];
  ctx: SdkContext;
}): Promise<NavigateResult> {
  return withPerf('share:navigate', async () => {
    // Collect every key this function mints so they can be wiped in the finally block.
    // D-09: recipientPrivKey is caller-owned — NOT added to mintedKeys.
    const mintedKeys: Uint8Array[] = [];

    try {
      // Step 1: ONE ECIES unwrap → share-root readKey
      // D-09: do NOT zero recipientPrivKey — caller is the terminal owner.
      const shareRootReadKey = await unwrapKey(
        base64ToBytes(params.encryptedReadKey),
        params.recipientPrivKey
      );
      mintedKeys.push(shareRootReadKey);

      // Step 2: Resolve + fetch the root PublishedNode
      const rootPublished = await fetchPublishedNode(params.shareRootIpnsName, params.ctx);
      if (!rootPublished) return { status: 'revoked' };

      // Step 3: Behind-retry check (§4.6 / D-06)
      // The envelope generation is plaintext; if it exceeds the grant's rootExpectedGeneration
      // the root has been rotated since the grant was issued. The caller should re-fetch the
      // re-minted grant (honest-reader liveness).
      if (rootPublished.generation > params.rootExpectedGeneration) {
        return { status: 'behind-retry' };
      }

      // Step 4: Unseal root node
      let currentNode = await unsealNode(rootPublished, shareRootReadKey);
      let currentReadKey = shareRootReadKey;

      // Step 5: Walk the path — O(depth) symmetric hops
      for (const hopIpnsName of params.path) {
        // 5a. Find the SealedChildRef for this hop by ipnsName
        const childRef = (currentNode.children ?? []).find((c) => c.ipnsName === hopIpnsName);
        if (!childRef) return { status: 'revoked' };

        // 5b. Fetch child PublishedNode (need plaintext id + kind for AAD construction)
        const childPublished = await fetchPublishedNode(hopIpnsName, params.ctx);
        if (!childPublished) return { status: 'revoked' };

        // 5c. Derive child readKey — generation-source rule (§2.6, Pitfall 1):
        //     AAD MUST use childRef.generation (the PARENT MIRROR), NOT childPublished.generation
        //     (the child's own envelope generation). A stale-CID serve fails GCM auth closed.
        const childReadKey = await unsealChildReadKey(
          childRef.readKeySealed,
          currentReadKey,
          childPublished.id, // plaintext from child envelope
          childPublished.kind, // plaintext from child envelope
          childRef.generation // ← parent mirror (NOT childPublished.generation)
        );
        mintedKeys.push(childReadKey);

        // 5d. Unseal child node
        const childNode = await unsealNode(childPublished, childReadKey);

        currentNode = childNode;
        currentReadKey = childReadKey;
      }

      // Step 6: At the leaf — must be a file node with content
      if (currentNode.kind !== 'file' || !currentNode.content) {
        // Path ended at a folder; callers should provide a complete path to a file.
        return { status: 'revoked' };
      }

      // Return content to caller — content.fileKey is caller-owned, NOT zeroed here (D-09).
      return { status: 'ok', content: currentNode.content, nodeId: currentNode.id };
    } finally {
      // Zero all navigate-minted intermediate keys on every exit path (success, early
      // return, or thrown error). recipientPrivKey is excluded — caller is terminal owner.
      for (const key of mintedKeys) {
        key.fill(0);
      }
    }
  });
}
