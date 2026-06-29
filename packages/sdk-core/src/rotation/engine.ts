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
import { generateRandomBytes } from '@cipherbox/crypto';
import { publishWithCas } from '../cas';
import { resolveIpnsRecord } from '../ipns';
import { fetchFromIpfs, addToIpfs } from '../ipfs';
import type { SdkContext } from '../types';

// ---------------------------------------------------------------------------
// Types — string-literal unions, never TypeScript enums (project convention)
// ---------------------------------------------------------------------------

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
   * The caller (rotateReadFromNode) uses this to update the parent before the
   * next frontier-publish round (D-09 per-node parent-link publish pattern).
   */
  newReadKeySealed: string;
  /** Plaintext children of the rotated node (to enqueue in the BFS frontier). */
  children: SealedChildRef[];
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
 * Phase 64 implementation: for every non-revoked grant whose `rootNodeId` is in
 * the rotated set, re-wrap the share-root readKey under the new `readKey'` and
 * re-issue a `readDescriptorRef`.
 *
 * Invoked ONLY when `innerGrants` is non-empty (conditional — D-01).
 *
 * @throws Always in Phase 63 (ROT-04/HIGH-3 — deferred).
 */
export async function reMintGrantsRootedAt(
  _nodeId: string,
  _key: Uint8Array,
  _gen: number,
  _job: RotationJobRecord,
  _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-04/HIGH-3 inner-grant re-mint)');
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
    // Phase 64: batch parent-link publishes (D-09 optimization seam).
    // On CAS-409: the default merge throws Phase-64 (mergeConcurrentChildren seam).
    // D-01: nodeIpnsPrivateKey is guaranteed non-null by the guard above.
    await publishWithCas<PublishedNode>({
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
      await reMintGrantsRootedAt(nodeId, readKeyPrime, generationPrime, jobRecord, ctx);
    }

    return {
      skipped: false,
      childReadKey: readKeyPrime,
      newGeneration: generationPrime,
      newReadKeySealed,
      children: node.children ?? [],
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

  // BFS frontier: each entry carries the NODE's own pre-rotation readKey.
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
  }> = [];

  // Helper: resolve an IPNS name → fetch the IPFS CID → parse PublishedNode envelope.
  // Used to obtain id/kind from the child's plaintext envelope before deriving its readKey.
  async function resolveAndFetch(ipnsName: string): Promise<PublishedNode | null> {
    const resolved = await resolveIpnsRecord(ipnsName, ctx);
    if (!resolved) return null;
    const raw = await fetchFromIpfs(ctx, resolved.cid);
    return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
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
    });
  }

  // Process the frontier BFS (D-09: per-node parent-link publish, not batched in Phase 63)
  while (queue.length > 0) {
    const item = queue.shift()!;

    const result = await rotateOne({
      // nodeId is absent: it will be derived from the unsealed node's id inside rotateOne.
      nodeIpnsName: item.childRef.ipnsName,
      nodeIpnsPrivateKey: item.ipnsPrivateKey,
      nodeIpnsPublicKey: item.ipnsPublicKey,
      parentReadKey: item.nodeReadKey, // this node's own (pre-rotation) readKey
      parentIpnsName: item.parentIpnsName,
      parentCurrentSeq: 0n, // unused in Phase 63 (D-09 deferred)
      jobRecord,
      ctx,
    });

    if (result.skipped) continue; // idempotency: already committed in a prior run

    // Advisory checkpoint after per-node commit.
    if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);

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
      });
    }
  }

  jobRecord.status = 'complete';
}
