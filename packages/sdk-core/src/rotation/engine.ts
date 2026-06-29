/**
 * Rotation Engine — `rotateReadFromNode` / `rotateOne`
 *
 * Implements the Phase-63 read-revocation primitive (ROT-01): a resumable,
 * per-node-CAS-commit BFS walk that rotates the read key of every node in a
 * scope-exit subtree. Published IPNS records are the source of truth; the
 * RotationJobRecord is advisory.
 *
 * Host-agnostic pure logic (D-02): no FUSE / Tauri / web import here.
 *
 * @security
 * Zeroization rule (D-09 / T-63-10 / Pitfall 4):
 *   - `rotateOne` MINTS `readKeyPrime` — it zeros that buffer ONLY on its own
 *     failure paths (before re-throw), never on success (the frontier walk still
 *     needs it for children).
 *   - `rotateOne` NEVER zeros caller-supplied `parentReadKey` or any reused
 *     session key. Those belong to the caller.
 *   - A prior incident (48/89 sdk-e2e failures) was caused by a callee zeroing
 *     a reused session buffer. Flag this file in every security review.
 *
 * Coverage note (SC#5 / Pitfall 2):
 *   The sdk-core vitest config excludes `src/**\/index.ts` from coverage.
 *   This file MUST remain `src/rotation/engine.ts` — placing it in an
 *   `index.ts` barrel would silently drop rotation from coverage metrics.
 */

import { sealNode, unsealNode, sealChildReadKey, unsealChildReadKey } from '@cipherbox/core';
import type { Node, PublishedNode, SealedChildRef } from '@cipherbox/core';
import { generateRandomBytes, wrapKey } from '@cipherbox/crypto';
import { publishWithCas } from '../cas';
import { resolveIpnsRecord } from '../ipns';
import { fetchFromIpfs, addToIpfs } from '../ipfs';
import type { SdkContext } from '../types';
import { updateFolderMetadataAndPublish } from '../folder/registration';

// ---------------------------------------------------------------------------
// Types — string-literal unions, never TypeScript enums (project convention)
// ---------------------------------------------------------------------------

/**
 * Injectable callbacks for `reMintGrantsRootedAt` (D-04 transport seam).
 *
 * Keeps the rotation engine transport-decoupled: unit tests inject vi.fn()
 * mocks; production callers (Phase 66) will supply real API/DB callbacks.
 *
 * Callback contract:
 *   - `queryGrantsFn(nodeId)` — returns all grants whose root is `nodeId`.
 *   - `updateGrantFn(shareId, readDescriptorRef, newGeneration)` — persists the
 *     re-minted ECIES-wrapped descriptor for a non-revoked recipient.
 *   - `deleteGrantFn(shareId)` — removes a revoked recipient's grant row.
 */
export type GrantRemintCallbacks = {
  queryGrantsFn: (
    nodeId: string
  ) => Promise<
    ReadonlyArray<{ shareId: string; recipientPublicKey: Uint8Array; isRevoked: boolean }>
  >;
  updateGrantFn: (
    shareId: string,
    readDescriptorRef: string,
    newGeneration: number
  ) => Promise<void>;
  deleteGrantFn: (shareId: string) => Promise<void>;
};

/** Advisory status of a rotation job. */
export type RotationStatus = 'pending' | 'in-progress' | 'complete' | 'failed';

/**
 * Advisory in-memory job record for a rotation walk.
 *
 * Published IPNS records are the source of truth (D-10). This record is
 * advisory; callers may persist it via `persistCallback` for durable
 * resume (Phase 68/69). In Phase 63, a page-reload restarts the idempotent
 * walk from the Phase-64 `verifySubtreeClean` seam.
 */
export type RotationJobRecord = {
  /** Root of the subtree being rotated. */
  rootNodeId: string;
  /** Advisory status (not authoritative — IPNS records are). */
  status: RotationStatus;
  /**
   * Node IDs that have been committed (per-node CAS publish succeeded).
   * Used for idempotency: re-entering rotateOne for a completed node is a no-op.
   */
  completedNodeIds: Set<string>;
  /**
   * Pending frontier entries for the BFS walk.
   *
   * `ipnsPrivateKey` is optional in Phase 63 (publishWithCas is used with a
   * placeholder when absent); Phase 65 populates it from the write body.
   */
  frontier: Array<{
    nodeIpnsName: string;
    parentReadKey: Uint8Array;
    ipnsPrivateKey?: Uint8Array;
    ipnsPublicKey?: Uint8Array;
  }>;
  /**
   * Optional host-injected persistence callback (no-op by default — D-10).
   * Called after each per-node commit so hosts can durably checkpoint progress.
   */
  persistCallback?: (job: RotationJobRecord) => void | Promise<void>;
};

/** Return type for a successful (non-skipped) rotateOne call. */
type RotateOneDone = {
  skipped: false;
  /** Freshly minted readKey for this node (do NOT zero — frontier walk needs it). */
  childReadKey: Uint8Array;
  /** New generation number (node.generation + 1). */
  newGeneration: number;
  /**
   * New sealed readKey for the parent's SealedChildRef[N].readKeySealed.
   * Sealed under this node's OWN pre-rotation readKey (legacy from Phase-63 contract).
   * The D-02 re-seal (Phase 64) re-seals childReadKey under the PARENT's new readKey'
   * out-of-band in rotateReadFromNode — not here.
   */
  newReadKeySealed: string;
  /** Plaintext children of the rotated node (to enqueue in the BFS frontier). */
  children: SealedChildRef[];
  /**
   * IPNS sequence number produced by this node's publish.
   *
   * D-09 (Phase 64): used as the CAS sequence guard for the parent's batched
   * re-publish after all children rotate.  The parent's first publish returns
   * this value; the second (batched) publish passes it as `sequenceNumber` to
   * advance the CAS monotonic counter by 1.
   */
  newSequenceNumber: bigint;
};

/** Return type when a node was already completed (idempotency skip). */
type RotateOneSkipped = {
  skipped: true;
  /** Re-exported so the caller can still advance the frontier if needed. */
  childReadKey: Uint8Array;
  newGeneration: number;
};

/** Parameters for a single-node rotation step. */
type RotateOneParams = {
  /**
   * Node UUID (optional).
   * When provided: fast idempotency check before IPNS resolution.
   * When absent: derived from the unsealed node after resolution.
   */
  nodeId?: string;
  /** IPNS k51 name used to resolve and publish this node. */
  nodeIpnsName: string;
  /**
   * IPNS Ed25519 private-key seed for this node.
   *
   * REQUIRED for publish (D-01 fail-closed): `rotateOne` throws if absent.
   * Phase 64 callers supply this via `nodeKeySource` in `RotationParams`.
   * Phase 65 will derive it from the unsealed write-body instead.
   *
   * Field type remains optional (`?`) so callers can forward `undefined` from
   * `nodeKeySource` results; the runtime guard surfaces the absence as an error.
   */
  nodeIpnsPrivateKey?: Uint8Array;
  /** Optional: Ed25519 public key for faster publish (avoids re-deriving). */
  nodeIpnsPublicKey?: Uint8Array;
  /**
   * Read key used to UNSEAL this node's read-body — i.e. THIS node's own
   * pre-rotation readKey: the root's own readKey for the root; for a child,
   * the child's own readKey (derived via `unsealChildReadKey` from the parent
   * before the child is enqueued — see the BFS in `rotateReadFromNode`). The
   * field name is a legacy misnomer: it carries the node's OWN key, not the
   * parent's. NEVER zeroed by rotateOne — caller is the terminal owner (D-09).
   *
   * Phase 64 NOTE: `rotateOne` currently seals the returned `newReadKeySealed`
   * under THIS key, but the parent's `SealedChildRef[N].readKeySealed` must be
   * sealed under the PARENT's NEW readKey' for `unsealChildReadKey` to
   * authenticate. The Phase-64 parent-link publish must re-seal under the
   * parent's rotated key (a separate param or an out-of-band re-seal) — see
   * `.planning/todos/pending/2026-06-29-rotation-engine-walk-soundness-phase64.md`.
   */
  parentReadKey: Uint8Array;
  /**
   * IPNS name of the parent node (for the per-node parent-link publish — D-09).
   * Unused in Phase 63 (parent-link publish optimization deferred to Phase 64).
   */
  parentIpnsName: string;
  /**
   * Current IPNS sequence number of the parent (for CAS on the parent-link publish).
   * Unused in Phase 63 (per-node parent-link batching deferred to Phase 64 — D-09).
   */
  parentCurrentSeq: bigint;
  jobRecord: RotationJobRecord;
  ctx: SdkContext;
  /**
   * Non-empty when the caller knows there are inner grants rooted at this node.
   * Triggers `reMintGrantsRootedAt` SEAM (Phase 64 — ROT-04/HIGH-3).
   * MUST be absent on the clean happy-path so the seam is never invoked (D-01).
   */
  innerGrants?: ReadonlyArray<unknown>;
  /**
   * Optional injectable callbacks for the `reMintGrantsRootedAt` seam (D-04).
   * Threaded from `RotationParams.grantCallbacks` so the host can inject
   * real API callbacks in production and vi.fn() mocks in tests.
   */
  grantCallbacks?: GrantRemintCallbacks;
};

/** Parameters for the resumable frontier walk. */
export type RotationParams = {
  rootNodeId: string;
  rootNodeIpnsName: string;
  /** Read key used to unseal the root node's read-body. */
  rootReadKey: Uint8Array;
  /** IPNS private key for the root node (optional; Phase 65 provides from write-body). */
  rootIpnsPrivateKey?: Uint8Array;
  rootIpnsPublicKey?: Uint8Array;
  jobRecord: RotationJobRecord;
  ctx: SdkContext;
  /**
   * Optional test-supplied key source for per-node IPNS signing keys.
   *
   * Phase 64 uses this seam to thread real per-node signing keys through the BFS
   * walk in unit tests and sdk-e2e suites, without requiring the full Phase-65
   * write-body → key derivation chain. When provided, `rotateReadFromNode` calls
   * `nodeKeySource(childIpnsName)` when enqueuing each BFS child. If the source
   * returns undefined for a node, `rotateOne` for that node throws fail-closed (D-01).
   *
   * Production note: Phase 65 replaces this seam with write-body-derived keys.
   * Never ship a production rotation call that depends on this field.
   */
  nodeKeySource?: (
    ipnsName: string
  ) => { privateKey: Uint8Array; publicKey: Uint8Array } | undefined;
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Encode a Uint8Array to a base64 string.
 * Processes in chunks to avoid call-stack overflow on large ECIES ciphertexts.
 * Local copy — dedup with share/grant.ts is deferred per CONTEXT.md.
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunkSize, bytes.length)));
  }
  return btoa(binary);
}

/** Fetch a PublishedNode envelope from IPFS by CID. */
async function fetchPublishedNode(cid: string, ctx: SdkContext): Promise<PublishedNode> {
  const raw = await fetchFromIpfs(ctx, cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

// ---------------------------------------------------------------------------
// Named Phase-64 seams — individually testable, conditionally invoked (D-01)
//
// Each seam throws an Error naming Phase 64 and its requirement ID so that:
//   1. Phase 63 tests can assert the exact throw message.
//   2. Phase 64 replaces each function body without re-architecting the engine.
//   3. The conditional invocation rule (D-01) guarantees the clean happy-path
//      NEVER reaches a seam — tests prove this by passing without any seam throw.
// ---------------------------------------------------------------------------

/**
 * SEAM: Content-key rotation for file nodes.
 *
 * Phase 64 implementation: mint a fresh `fileKey'`, mark `contentRekeyPending`
 * on the file node, and schedule re-encryption of file content under `fileKey'`.
 *
 * Invoked ONLY when `node.kind === 'file'` (conditional — D-01).
 *
 * Phase 64 implementation: mints `fileKey' = generateRandomBytes(32)` and assigns
 * it to `node.content.fileKey` so that `rotateOne`'s subsequent `sealNode` re-seals
 * the read-body carrying the new fileKey. A holder of the old readKey/fileKey cannot
 * decrypt the NEXT published version (CRIT-1 / ADR 0002).
 *
 * Nodes without content (folder nodes) are a no-op — no content field is added.
 *
 * @security
 *   Do NOT zero `node.content.fileKey` after assignment — `rotateOne` consumes it via
 *   `sealNode` (terminal owner rule, D-09). Only zero on your own failure paths (none here).
 */
export async function mintFileKeyOnRotate(node: Node, _job: RotationJobRecord): Promise<void> {
  if (!node.content) {
    // Folder node (or any node without content) — no-op.
    return;
  }
  const fileKeyPrime = generateRandomBytes(32);
  node.content.fileKey = fileKeyPrime;
}

/**
 * SEAM: Re-mint read grants rooted at a rotated node.
 *
 * Phase 64 implementation (ROT-04/HIGH-3): for every non-revoked grant whose
 * `rootNodeId` is in the rotated set, ECIES-re-wrap the share-root readKey
 * under the new `readKey'` and re-issue a `readDescriptorRef` via
 * `callbacks.updateGrantFn`. Revoked recipients' rows are deleted via
 * `callbacks.deleteGrantFn`.
 *
 * Invoked ONLY when `innerGrants` is non-empty (conditional — D-01).
 * When `callbacks` is absent the function is a clean no-op (D-04 seam).
 *
 * @security
 *   Uses ECIES `wrapKey` (from `@cipherbox/crypto`) — never hand-roll key
 *   wrapping. Does NOT zero `newReadKey` — caller is terminal owner (D-09).
 */
export async function reMintGrantsRootedAt(
  nodeId: string,
  newReadKey: Uint8Array,
  newGeneration: number,
  _job: RotationJobRecord,
  _ctx: SdkContext,
  callbacks?: GrantRemintCallbacks
): Promise<void> {
  // D-04 transport seam: when no callbacks are supplied the function is a clean
  // no-op. This preserves the D-01 conditional-invocation contract — the clean
  // happy-path only supplies innerGrants, never callbacks, so no re-mint work runs.
  if (!callbacks) return;

  const grants = await callbacks.queryGrantsFn(nodeId);

  for (const grant of grants) {
    if (grant.isRevoked) {
      // Revoked recipient: delete the grant row. Do NOT re-mint a descriptor.
      // T-64-04b: re-minting for a revoked recipient defeats revocation.
      await callbacks.deleteGrantFn(grant.shareId);
    } else {
      // Non-revoked recipient: ECIES-wrap the new readKey under their public key.
      // T-64-04c: always use wrapKey — never hand-roll key wrapping.
      // Do NOT zero newReadKey here — caller is terminal owner (D-09).
      const wrappedBytes = await wrapKey(newReadKey, grant.recipientPublicKey);
      const readDescriptorRef = bytesToBase64(wrappedBytes);
      await callbacks.updateGrantFn(grant.shareId, readDescriptorRef, newGeneration);
    }
  }
}

/**
 * SEAM: Re-fetch and merge concurrent child additions on CAS-409.
 *
 * Phase 64 implementation: on a CAS-409, re-resolve the node, fetch the remote
 * children, merge them with the local children list, and retry the publish.
 *
 * Invoked ONLY on CAS-409 (conditional — D-01); never on the happy path.
 *
 * @throws Always in Phase 63 (ROT-05/HIGH-4 — deferred).
 */
export async function mergeConcurrentChildren(
  _node: Node,
  _resolved: unknown,
  _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)');
}

/**
 * SEAM: Verify the subtree is clean before a resume walk.
 *
 * Phase 64 implementation: re-resolve every node in the subtree against the
 * published IPNS records to rebuild an authoritative frontier from the committed
 * truth (crash-recovery convergence per §4.5).
 *
 * Invoked ONLY on resume (when `completedNodeIds` is non-empty at walk start —
 * conditional per D-01/D-10); never on a fresh run.
 *
 * @throws Always in Phase 63 (ROT-06 — deferred).
 */
export async function verifySubtreeClean(_rootNodeId: string, _ctx: SdkContext): Promise<boolean> {
  throw new Error('not implemented — phase 64 (ROT-06 crash-resume + verifySubtreeClean)');
}

// ---------------------------------------------------------------------------
// rotateOne — per-node CAS-committed rotation step (§4.5 9-step skeleton)
// ---------------------------------------------------------------------------

/**
 * Rotate a single node's read key via a per-node CAS publish.
 *
 * Implements the §4.5 design skeleton:
 *   1. Resolve N via IPNS
 *   2. Idempotency check (skip if already in jobRecord.completedNodeIds)
 *   3. Unseal N's read-body under the key chained from the parent
 *   4. Mint readKey' = 32 random bytes; generation' = node.generation + 1
 *   5. IF node.kind === 'file' → mintFileKeyOnRotate SEAM (Phase 64 — ROT-03)
 *   6. Re-seal N's read-body under readKey' (write-body skipped — Phase 63 read-chain only)
 *   7. Compute new SealedChildRef.readKeySealed for the parent via sealChildReadKey
 *   8. publishWithCas(N, sequenceNumber: resolved.sequenceNumber)
 *      Phase 64: batch parent-link publishes (D-09 optimization seam)
 *      On CAS-409: throw Phase-64 (mergeConcurrentChildren ROT-05 seam)
 *   9. Mark N done; invoke reMintGrantsRootedAt SEAM only when innerGrants supplied
 *
 * @security
 *   - Mints `readKeyPrime` — zeros it on failure paths before re-throw.
 *   - NEVER zeros `parentReadKey` — caller is terminal owner (D-09 / T-63-10).
 */
export async function rotateOne(
  params: RotateOneParams
): Promise<RotateOneDone | RotateOneSkipped> {
  const {
    nodeId: providedNodeId,
    nodeIpnsName,
    nodeIpnsPrivateKey,
    nodeIpnsPublicKey,
    parentReadKey,
    jobRecord,
    ctx,
    innerGrants,
    grantCallbacks,
  } = params;

  // Step 2 (fast path): idempotency check when nodeId is already known
  if (providedNodeId && jobRecord.completedNodeIds.has(providedNodeId)) {
    return { skipped: true, childReadKey: new Uint8Array(32), newGeneration: 0 };
  }

  // Step 1: Resolve the node's current IPNS record
  const resolved = await resolveIpnsRecord(nodeIpnsName, ctx);
  if (!resolved) {
    throw new Error(`rotateOne: node ${nodeIpnsName} not found in IPNS`);
  }

  // Fetch and unseal the node's read-body under parentReadKey
  // (parentReadKey is the key chained from the parent — for root nodes it is the
  //  root's own readKey, supplied by the rotation caller)
  const published = await fetchPublishedNode(resolved.cid, ctx);
  const node = await unsealNode(published, parentReadKey);

  // Step 2 (continued): idempotency check with the derived nodeId from the unsealed node
  const nodeId = providedNodeId ?? node.id;
  if (jobRecord.completedNodeIds.has(nodeId)) {
    return { skipped: true, childReadKey: new Uint8Array(32), newGeneration: node.generation };
  }

  // D-01 fail-closed: require a real IPNS signing key for every frontier node.
  // Phase 64 threads keys via nodeKeySource in RotationParams; Phase 65 derives them
  // from the unsealed write-body. Never publish an IPNS record with a placeholder.
  if (!nodeIpnsPrivateKey) {
    throw new Error(
      `rotateOne: no IPNS private key for ${nodeIpnsName} — ` +
        'provide via nodeKeySource (Phase 64) or write-body wiring (Phase 65)'
    );
  }

  // Step 4: Mint fresh readKey' (32 cryptographically random bytes) and generation'
  // Do NOT zero parentReadKey — caller is terminal owner (D-09).
  const readKeyPrime = crypto.getRandomValues(new Uint8Array(32));
  const generationPrime = node.generation + 1;

  try {
    // Step 5: SEAM — content-key rotation for file nodes (Phase 64 — ROT-03/CRIT-1)
    // Invoked CONDITIONALLY — clean happy-path (folder node) NEVER reaches this.
    if (node.kind === 'file') {
      await mintFileKeyOnRotate(node, jobRecord);
      // Phase 64 fills this seam; in Phase 63 it always throws above.
    }

    // Step 6: Re-seal the read-body under readKey' with the new generation'.
    // write-body is SKIPPED in Phase 63 (read-chain only; no writeKey supplied).
    // node.writeBody is absent since unsealNode was called without a writeKey.
    const updatedNode: Node = { ...node, generation: generationPrime };
    // Placeholder writeKey: unused because updatedNode.writeBody is absent (D-09 safe).
    const PLACEHOLDER_WRITE_KEY = new Uint8Array(32);
    const resealedPublished = await sealNode(updatedNode, readKeyPrime, PLACEHOLDER_WRITE_KEY);

    // Step 7: Compute the new sealed child-readKey for the parent's SealedChildRef[N].
    // The parent caller (rotateReadFromNode) uses newReadKeySealed to update the parent
    // node's children array before the next parent-link publish (D-09).
    const newReadKeySealed = await sealChildReadKey(
      readKeyPrime,
      parentReadKey,
      nodeId,
      node.kind,
      generationPrime
    );

    // Step 8: Publish the child node via CAS.
    // D-01: nodeIpnsPrivateKey is guaranteed non-null by the guard above.
    // D-09: capture newSequenceNumber so the caller can use it as the CAS guard
    // for the parent's batched re-publish after all children rotate.
    const casResult = await publishWithCas<PublishedNode>({
      ipnsName: nodeIpnsName,
      ipnsPrivateKey: nodeIpnsPrivateKey,
      ipnsPublicKey: nodeIpnsPublicKey,
      sequenceNumber: resolved.sequenceNumber,
      ctx,
      maxAttempts: 3,
      backoff: true,
      encodeAndUpload: async (_localData) => {
        const jsonBytes = new TextEncoder().encode(JSON.stringify(resealedPublished));
        const result = await addToIpfs(ctx, jsonBytes);
        return result.cid;
      },
      decodeRemote: async (cid) => {
        return fetchPublishedNode(cid, ctx);
      },
      merge: (_base, local, _remote) => {
        // Phase 64 (D-09): batch parent-link publishes + mergeConcurrentChildren seam.
        // On CAS-409, this merge is invoked. Phase 63 surfaces the gap explicitly —
        // a concurrent add during rotation is not handled until Phase 64 (ROT-05/HIGH-4).
        throw new Error(
          'not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge): CAS-409 on rotation publish'
        );
        // Unreachable: satisfies TypeScript return type constraint
        return { merged: local };
      },
      localData: resealedPublished,
      baseData: published,
    });

    // Step 9: Mark N done in the job record.
    jobRecord.completedNodeIds.add(nodeId);

    // Step 9 (continued): SEAM — re-mint inner grants only when supplied (D-01 conditional).
    // Clean happy-path (no inner grants) NEVER invokes this seam.
    if (innerGrants && innerGrants.length > 0) {
      await reMintGrantsRootedAt(
        nodeId,
        readKeyPrime,
        generationPrime,
        jobRecord,
        ctx,
        grantCallbacks
      );
    }

    return {
      skipped: false,
      childReadKey: readKeyPrime,
      newGeneration: generationPrime,
      newReadKeySealed,
      children: node.children ?? [],
      newSequenceNumber: casResult.newSequenceNumber,
    };
  } catch (err) {
    // Zero readKeyPrime on failure — rotateOne minted it, so rotateOne is terminal owner.
    // DO NOT zero parentReadKey — caller is terminal owner (D-09).
    readKeyPrime.fill(0);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// rotateReadFromNode — resumable BFS frontier walk (ROT-01, §4.2 / §4.5)
// ---------------------------------------------------------------------------

/**
 * Rotate the read key for every node in the subtree rooted at `rootNodeId`.
 *
 * Ordering: the scope-root is rotated FIRST (§4.2 — this is the actual cut that
 * revokes the reader's access at the cheapest commit point). The O(items) tail
 * runs as a BFS frontier walk, calling rotateOne per node and advancing the
 * frontier with each node's freshly minted readKey'.
 *
 * The job record is advisory (D-10). The optional `persistCallback` is called
 * after every per-node commit so the host can checkpoint progress durably.
 * A fresh run (completedNodeIds empty) does NOT call verifySubtreeClean —
 * that is the Phase-64 resume seam (D-01/D-10).
 *
 * Host-agnostic (D-02): no FUSE / Tauri / web import.
 *
 * @security Does NOT zero `rootReadKey` — caller is terminal owner (D-09).
 */
export async function rotateReadFromNode(params: RotationParams): Promise<void> {
  const {
    rootNodeId,
    rootNodeIpnsName,
    rootReadKey,
    rootIpnsPrivateKey,
    rootIpnsPublicKey,
    jobRecord,
    ctx,
    nodeKeySource,
  } = params;

  jobRecord.status = 'in-progress';

  // §4.2: Rotate the scope-root FIRST.
  // This is the actual cut: once the root's readKey is rotated and published,
  // a revoked grantee can no longer derive any child key from their old grant.
  const rootResult = await rotateOne({
    nodeId: rootNodeId,
    nodeIpnsName: rootNodeIpnsName,
    nodeIpnsPrivateKey: rootIpnsPrivateKey,
    nodeIpnsPublicKey: rootIpnsPublicKey,
    parentReadKey: rootReadKey,
    parentIpnsName: rootNodeIpnsName, // root has no parent; parentIpnsName unused in Phase 63
    parentCurrentSeq: 0n, // unused in Phase 63 (parent-link publish deferred to Phase 64)
    jobRecord,
    ctx,
  });

  if (rootResult.skipped) {
    // Root already committed (resume scenario — verifySubtreeClean is Phase 64).
    jobRecord.status = 'complete';
    if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);
    return;
  }

  // Persist after root commit (the high-value early checkpoint).
  if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);

  // ---------------------------------------------------------------------------
  // D-02 / D-09: parent tracking for out-of-band re-seal and batched republish
  //
  // Problem (Phase-63 CRITICAL bug): rotateOne seals the child's new readKey'
  // under the child's OWN old readKey (legacy contract). But the parent's
  // SealedChildRef[N].readKeySealed must be sealed under the PARENT's NEW readKey'
  // for `unsealChildReadKey` to authenticate on next read. This out-of-band
  // re-seal (D-02) and the single batched parent re-publish (D-09) happen HERE
  // in the walk caller, not inside rotateOne.
  //
  // Per-parent state tracks:
  //   - The parent's freshly minted readKey' (from the parent's rotateOne result)
  //   - A mutable copy of the parent's SealedChildRef array (to update in-place)
  //   - The IPNS keys needed for the batched re-publish
  //   - A pending-child counter (decremented per child; publishes when zero)
  // ---------------------------------------------------------------------------

  type ParentTrackingState = {
    parentNewReadKey: Uint8Array;
    parentIpnsName: string;
    parentIpnsPrivateKey?: Uint8Array;
    parentIpnsPublicKey?: Uint8Array;
    parentNodeId: string;
    parentNodeGeneration: number;
    parentLastSeq: bigint;
    children: SealedChildRef[]; // mutable copy updated as children rotate
    pendingChildCount: number;
  };

  // keyed by parent IPNS name (the IPNS name of the node that just rotated)
  const parentTracking = new Map<string, ParentTrackingState>();

  // BFS frontier: each entry carries the NODE's own pre-rotation readKey plus
  // the child's stable id/kind (needed for the D-02 AAD binding).
  //
  // DESIGN NOTE (Bug fix — confirmed during Phase-63 E2E):
  //   Each node in the tree has its OWN readKey (sealed inside the parent's
  //   SealedChildRef via sealChildReadKey). rotateOne receives a node's OWN
  //   readKey as `parentReadKey` to unseal that node's read-body. It does NOT
  //   receive the parent's readKey — that conflation was the root cause of the
  //   "Decryption failed" regression when the BFS passed the root's new readKey'
  //   to child rotateOne calls.
  //
  //   To derive a child's readKey from a SealedChildRef we need:
  //     1. The PARENT's OLD readKey (not the new readKey'; the sealed ref was
  //        created under the old key before rotation).
  //     2. The child's published node envelope (for id and kind — used in AAD).
  //   The parent's OLD readKey is the `parentReadKey` param that was just used
  //   to unseal the parent (D-09: never zeroed by rotateOne).
  const queue: Array<{
    childRef: SealedChildRef;
    /** The node's own pre-rotation readKey — used by rotateOne to unseal the node. */
    nodeReadKey: Uint8Array;
    parentIpnsName: string;
    ipnsPrivateKey?: Uint8Array;
    ipnsPublicKey?: Uint8Array;
    /** Stable UUID from the child's PublishedNode envelope (for D-02 AAD binding). */
    childPubId: string;
    /** Node kind from the child's PublishedNode envelope (for D-02 AAD binding). */
    childPubKind: 'folder' | 'file';
  }> = [];

  // Helper: resolve an IPNS name → fetch the IPFS CID → parse PublishedNode envelope.
  // Used to obtain id/kind from the child's plaintext envelope before deriving its readKey.
  async function resolveAndFetch(ipnsName: string): Promise<PublishedNode | null> {
    const resolved = await resolveIpnsRecord(ipnsName, ctx);
    if (!resolved) return null;
    const raw = await fetchFromIpfs(ctx, resolved.cid);
    return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
  }

  // Set up parent tracking for root's children (D-02/D-09).
  if (rootResult.children.length > 0) {
    parentTracking.set(rootNodeIpnsName, {
      parentNewReadKey: rootResult.childReadKey,
      parentIpnsName: rootNodeIpnsName,
      parentIpnsPrivateKey: rootIpnsPrivateKey,
      parentIpnsPublicKey: rootIpnsPublicKey,
      parentNodeId: rootNodeId,
      parentNodeGeneration: rootResult.newGeneration,
      parentLastSeq: rootResult.newSequenceNumber,
      children: [...rootResult.children], // mutable copy for in-place SealedChildRef updates
      pendingChildCount: rootResult.children.length,
    });
  }

  // Enqueue root's children: derive each child's readKey from the root's OLD readKey.
  // rootReadKey is the root's own (pre-rotation) key and is NOT zeroed by rotateOne (D-09).
  for (const childRef of rootResult.children) {
    const childPub = await resolveAndFetch(childRef.ipnsName);
    if (!childPub) continue; // child IPNS missing — skip (data inconsistency)
    const childReadKey = await unsealChildReadKey(
      childRef.readKeySealed,
      rootReadKey, // root's OLD readKey (still valid; never zeroed — D-09)
      childPub.id,
      childPub.kind,
      childRef.generation // parent-mirror (§2.6 D-07 invariant 1)
    );
    // Thread per-node IPNS key from nodeKeySource (D-01 / Phase 64 seam).
    // Phase 65 derives keys from the write-body instead.
    const childKeys = nodeKeySource?.(childRef.ipnsName);
    queue.push({
      childRef,
      nodeReadKey: childReadKey, // child's own (pre-rotation) readKey
      parentIpnsName: rootNodeIpnsName,
      ipnsPrivateKey: childKeys?.privateKey,
      ipnsPublicKey: childKeys?.publicKey,
      childPubId: childPub.id,
      childPubKind: childPub.kind as 'folder' | 'file',
    });
  }

  // Process the frontier BFS.
  while (queue.length > 0) {
    const item = queue.shift()!;

    const result = await rotateOne({
      // nodeId is absent: it will be derived from the unsealed node's id inside rotateOne.
      nodeIpnsName: item.childRef.ipnsName,
      nodeIpnsPrivateKey: item.ipnsPrivateKey,
      nodeIpnsPublicKey: item.ipnsPublicKey,
      parentReadKey: item.nodeReadKey, // this node's own (pre-rotation) readKey
      parentIpnsName: item.parentIpnsName,
      parentCurrentSeq: 0n,
      jobRecord,
      ctx,
    });

    if (!result.skipped) {
      // Advisory checkpoint after per-node commit.
      if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);

      // D-02: re-seal the child's new readKey' under the PARENT's new readKey'.
      // The legacy sealChildReadKey call inside rotateOne seals under the child's own
      // old readKey — correct for the child's own identity binding but wrong for the
      // parent's SealedChildRef (which must be sealed under the parent's NEW readKey'
      // for `unsealChildReadKey` to authenticate). This out-of-band call is the fix.
      const parentState = parentTracking.get(item.parentIpnsName);
      if (parentState) {
        const updatedChildReadKeySealed = await sealChildReadKey(
          result.childReadKey, // child's freshly minted readKey'
          parentState.parentNewReadKey, // parent's new readKey' (from parent's rotateOne)
          item.childPubId, // child's stable UUID (AAD binding)
          item.childPubKind, // child's kind (AAD binding)
          result.newGeneration // child's new generation (AAD binding)
        );

        // Update the parent's mutable SealedChildRef copy.
        const childIdx = parentState.children.findIndex(
          (c) => c.ipnsName === item.childRef.ipnsName
        );
        if (childIdx !== -1) {
          parentState.children[childIdx] = {
            ...parentState.children[childIdx],
            readKeySealed: updatedChildReadKeySealed,
            generation: result.newGeneration,
          };
        }

        // D-09: decrement pending count; republish parent exactly once when all children done.
        parentState.pendingChildCount--;
        if (parentState.pendingChildCount === 0) {
          // Batched parent re-publish: advance the IPNS sequence counter once, carrying
          // the updated SealedChildRef array so unsealChildReadKey on next read succeeds.
          // nodeGeneration is the parent's generation from ITS rotateOne — NOT bumped again.
          await updateFolderMetadataAndPublish({
            ipnsName: parentState.parentIpnsName,
            // parentIpnsPrivateKey is non-null: the D-01 guard in rotateOne already
            // verified the parent had a key when it rotated.
            ipnsPrivateKey: parentState.parentIpnsPrivateKey!,
            ipnsPublicKey: parentState.parentIpnsPublicKey,
            sequenceNumber: parentState.parentLastSeq,
            readKey: parentState.parentNewReadKey,
            nodeId: parentState.parentNodeId,
            nodeGeneration: parentState.parentNodeGeneration,
            children: parentState.children,
            ctx,
          });
          parentTracking.delete(item.parentIpnsName);
        }
      }

      // Set up parent tracking for this node's children (recursive D-02/D-09).
      if (result.children.length > 0) {
        parentTracking.set(item.childRef.ipnsName, {
          parentNewReadKey: result.childReadKey,
          parentIpnsName: item.childRef.ipnsName,
          parentIpnsPrivateKey: item.ipnsPrivateKey,
          parentIpnsPublicKey: item.ipnsPublicKey,
          parentNodeId: item.childPubId,
          parentNodeGeneration: result.newGeneration,
          parentLastSeq: result.newSequenceNumber,
          children: [...result.children],
          pendingChildCount: result.children.length,
        });
      }

      // Enqueue this node's children using THIS node's pre-rotation readKey.
      // item.nodeReadKey is NOT zeroed by rotateOne (D-09) — still valid here.
      for (const childRef of result.children) {
        const childPub = await resolveAndFetch(childRef.ipnsName);
        if (!childPub) continue;
        const childReadKey = await unsealChildReadKey(
          childRef.readKeySealed,
          item.nodeReadKey, // THIS node's old readKey (seals its children's readKeys)
          childPub.id,
          childPub.kind,
          childRef.generation
        );
        // Thread per-node IPNS key from nodeKeySource (D-01 / Phase 64 seam).
        const grandchildKeys = nodeKeySource?.(childRef.ipnsName);
        queue.push({
          childRef,
          nodeReadKey: childReadKey, // grandchild's own readKey
          parentIpnsName: item.childRef.ipnsName,
          ipnsPrivateKey: grandchildKeys?.privateKey,
          ipnsPublicKey: grandchildKeys?.publicKey,
          childPubId: childPub.id,
          childPubKind: childPub.kind as 'folder' | 'file',
        });
      }
    }
  }

  jobRecord.status = 'complete';
}
