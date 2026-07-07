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

import {
  sealNode,
  unsealNode,
  sealChildReadKey,
  unsealChildReadKey,
  sealChildWriteKey,
  unsealChildWriteKey,
} from '@cipherbox/core';
import type { Node, NodeKind, PublishedNode, SealedChildRef } from '@cipherbox/core';
import {
  generateRandomBytes,
  wrapKey,
  generateEd25519Keypair,
  deriveIpnsName,
} from '@cipherbox/crypto';
import { publishWithCas } from '../cas';
import { resolveIpnsRecord, createAndPublishIpnsRecord } from '../ipns';
import { fetchFromIpfs, addToIpfs } from '../ipfs';
import type { SdkContext } from '../types';
import { updateFolderMetadataAndPublish } from '../folder/registration';
import { mergeRotatedChildren } from './merge';

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

/**
 * Injectable callbacks for `rotateWriteFromNode` (D-02 transport seam / WRITE-02/03/04).
 *
 * All transport is injected so the write-revocation driver is host-agnostic.
 * Unit tests inject vi.fn() mocks; Phase 66 callers supply real API/DB implementations.
 *
 * Callback contract:
 *   - `queryWriteGrantsFn(nodeId)` — returns all write grants whose root is `nodeId`.
 *   - `writeDescriptorRefPersistFn(shareId, writeDescriptorRef)` — persists the
 *     re-wrapped ECIES descriptor for a surviving (non-revoked) co-writer.
 *   - `teeUnenrollFn(oldIpnsName)` — removes the old k51 name from the TEE republish
 *     batch (tombstone-intent — §5.5 / WRITE-04).
 *   - `deleteWriteGrantFn(shareId)` — drops the revoked recipient's grant row (WRITE-03).
 *
 * @security
 *   All callbacks are called AFTER the new IPNS name is first-published. Failures
 *   inside callbacks do NOT undo the IPNS publish; they surface as thrown errors.
 */
export type WriteRevocationCallbacks = {
  queryWriteGrantsFn: (
    nodeId: string
  ) => Promise<
    ReadonlyArray<{ shareId: string; recipientPublicKey: Uint8Array; isRevoked: boolean }>
  >;
  writeDescriptorRefPersistFn: (shareId: string, writeDescriptorRef: string) => Promise<void>;
  teeUnenrollFn: (oldIpnsName: string) => Promise<void>;
  deleteWriteGrantFn: (shareId: string) => Promise<void>;
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
  /**
   * Write key for this node's write-body (optional).
   *
   * When the node's published envelope has `writeSealed`, this key is required:
   *   - `unsealNode(published, parentReadKey, nodeWriteKey)` recovers the write-body.
   *   - `sealNode(updatedNode, readKeyPrime, nodeWriteKey)` re-seals it unchanged.
   * Fail-closed: if `published.writeSealed` is present and this key is absent or
   * all-zeros, `rotateOne` throws (RESEARCH Pitfall 2 / T-65-17).
   *
   * Read-rotation does NOT rotate the write plane (that is Plan-06's job).
   * The write-body is re-sealed under the SAME nodeWriteKey — ipnsPrivateKey
   * and writeChildren are preserved byte-for-byte (read/write planes are independent).
   *
   * NEVER zeroed by rotateOne — caller is terminal owner (D-09).
   */
  nodeWriteKey?: Uint8Array;
};

/**
 * Return shape for a successful (fresh, non-resume-skip) `rotateReadFromNode` run:
 * the ROOT node's post-rotation readKey/generation/sequenceNumber (ROT-07 Gap 2).
 *
 * Callers (e.g. `performScopeExitRotation`) use this to refresh their own
 * in-memory folder cache after a rotation so a same-session retry does not
 * operate on stale pre-rotation state.
 *
 * @security The `readKey` buffer is NOT zeroed by `rotateReadFromNode` — the
 * caller becomes the terminal owner (D-09).
 */
export type RotateReadResult = {
  /** The root's freshly minted readKey (readKeyPrime from the root's rotateOne call). */
  readKey: Uint8Array;
  /** The root's new generation number (node.generation + 1). */
  generation: number;
  /** The root's new IPNS sequence number after its rotation publish. */
  sequenceNumber: bigint;
};

/**
 * Thrown by `rotateReadFromNode`'s entry-gate root-unseal PROBE (Plan 70-06 / SC#3 /
 * RESEARCH Pitfall 4 / Open Question 1) when the caller-supplied `rootReadKey` cannot
 * unseal the CURRENTLY-published root record.
 *
 * This is the genuinely-unrecoverable crash window: the root was rotated by a lost
 * prior run (its readKey' was minted, published, and never durably persisted — the
 * durable floor (`rotation-high-water.ts` / `high_water.rs`) stores generation/
 * sequence NUMBERS only, never key material — D-09/T-68-83). There is NO
 * cryptographic recovery path client-side using only the stale key. Distinct from a
 * generic AEAD/unseal error so callers (e.g. `performScopeExitRotation`) can catch
 * this specific error and fall back to a full top-down `folderTree` re-navigation
 * from the vault root, instead of surfacing an opaque decryption failure.
 *
 * A MISSING root record is a different, unrelated scenario (data inconsistency, not
 * a stale key) and does NOT throw this error — see `rotateOne`'s own
 * "not found in IPNS" throw and `verifySubtreeClean`'s `isDirty: true` handling.
 */
export class RootKeyStaleError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RootKeyStaleError';
  }
}

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
  ) => { privateKey: Uint8Array; publicKey: Uint8Array; writeKey?: Uint8Array } | undefined;
  /**
   * Non-empty when the caller knows there are inner grants rooted at the ROOT node.
   * Threaded to EVERY `rotateOne` call site in the walk (Plan 70-06 / SC#4 / T-70-09)
   * so `reMintGrantsRootedAt` is reachable from the real (non-test) walk, not only via
   * direct `rotateOne` injection in unit tests. MUST be absent on the clean happy-path
   * (D-01 conditional invocation).
   *
   * Production note: Phase 66 will refine this to per-node granularity (querying which
   * nodes in the walk actually have grants rooted at them); this phase only wires the
   * plumbing so the seam is reachable end-to-end.
   */
  innerGrants?: ReadonlyArray<unknown>;
  /**
   * Optional injectable callbacks for the `reMintGrantsRootedAt` seam (D-04), threaded
   * to every `rotateOne` call site alongside `innerGrants` (Plan 70-06 / SC#4).
   */
  grantCallbacks?: GrantRemintCallbacks;
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
 * Invoked ONLY when `node.kind === 'file'` (conditional — D-01).
 *
 * Phase 64 mints a fresh `fileKey'` and places it on the node so the re-sealed body
 * carries it. The lazy `contentRekeyPending` marker + re-encrypt-on-next-write wiring
 * is deferred to Phase 65 (the `node/v3` schema is frozen this phase); minting
 * `fileKey'` onto the re-sealed body IS the Phase-64 CRIT-1 deliverable.
 *
 * Phase 64 implementation: mints `fileKey' = generateRandomBytes(32)` and assigns
 * it to `node.content.fileKey` so that `rotateOne`'s subsequent `sealNode` re-seals
 * the read-body carrying the new fileKey. A holder of the old readKey/fileKey cannot
 * decrypt the NEXT published version (CRIT-1 / ADR 0002).
 *
 * Nodes without content (folder nodes) are a no-op — no content field is added.
 *
 * @security
 *   Do NOT zero the NEW `node.content.fileKey` after assignment — `rotateOne` consumes it
 *   via `sealNode` (terminal owner rule, D-09). The OLD pre-rotation fileKey IS zeroed before
 *   the swap: `node` is a fresh `unsealNode` output (engine-owned, not a caller-reused buffer),
 *   so its decrypted content key is terminally owned here and wiping it is safe D-09 hygiene.
 *   Only zero the new minted key on your own failure paths (handled by the caller in rotateOne).
 */
export async function mintFileKeyOnRotate(node: Node, _job: RotationJobRecord): Promise<void> {
  if (!node.content) {
    // Folder node (or any node without content) — no-op.
    return;
  }
  // Zero the pre-rotation content key before discarding the reference (D-09 hygiene).
  if (node.content.fileKey instanceof Uint8Array) {
    node.content.fileKey.fill(0);
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
 * Re-seal a node after merging concurrently-added children on CAS-409.
 *
 * Phase 70 implementation (SC#1 site A / T-70-01): on a rotation CAS-409, the
 * remote winner may contain child refs added concurrently that are absent
 * from the local rotation result — AND the remote may still hold a stale
 * (pre-rotation) seal for a child rotation already re-sealed. This function:
 *   1. Unseals `basePub` under `oldReadKey` to recover the base children list.
 *   2. Unseals `remotePub` under `oldReadKey` to recover the remote children list.
 *   3. Three-way merges (base, local, remote) via `mergeRotatedChildren` —
 *      LOCAL WINS on conflict (preserves the rotation's own re-seal; never
 *      re-adopts a stale/remote seal), remote-only entries are concurrent
 *      adds (included), base-only entries are intentional deletes (dropped).
 *      NEVER use the generic remote-wins `mergeChildren` here — see
 *      `rotation/merge.ts`'s module doc for why this is a separate function.
 *   4. Re-seals the merged node under `newReadKey` (readKey-prime).
 *
 * Invoked ONLY from the `rotateOne` CAS-409 merge callback (conditional — D-01).
 *
 * @security
 *   - Does NOT zero `oldReadKey` or `newReadKey` — callers are terminal owners (D-09).
 *   - `localChildren` must come from the node's pre-rotation children (closure over
 *     the unsealed node), NOT from the sealed `localPub`. This avoids an extra
 *     unseal round-trip and an unnecessary dependency on `newReadKey` during merge.
 *
 * @returns `published` — the re-sealed merged node's PublishedNode envelope.
 *   `mergedChildren` — the plaintext merged children, so `rotateOne` can return
 *   the CAS-merged set (including any remote-added child) to the BFS caller
 *   instead of the pre-merge `node.children` snapshot (SC#3).
 */
export async function mergeConcurrentChildren(
  basePub: PublishedNode,
  remotePub: PublishedNode,
  oldReadKey: Uint8Array,
  localChildren: SealedChildRef[],
  newReadKey: Uint8Array,
  localNode: Node,
  generationPrime: number,
  writeKey: Uint8Array
): Promise<{ published: PublishedNode; mergedChildren: SealedChildRef[] }> {
  // 1. Unseal base snapshot under the old (pre-rotation) readKey.
  const baseNodeDecoded = await unsealNode(basePub, oldReadKey);

  // 2. Unseal remote node under the old readKey — it was sealed before rotation.
  const remoteNodeDecoded = await unsealNode(remotePub, oldReadKey);

  // 3. Rotation-only local-wins three-way merge (T-70-01): local's re-seal
  //    survives a conflict against a remote still holding the stale seal;
  //    remote-only concurrent adds are preserved; base-only deletes are dropped.
  const mergedChildren = mergeRotatedChildren(
    baseNodeDecoded.children ?? [],
    localChildren,
    remoteNodeDecoded.children ?? []
  );

  // 4. Re-seal merged node under readKey-prime (the rotation's new key).
  const mergedNode: Node = { ...localNode, generation: generationPrime, children: mergedChildren };
  const published = await sealNode(mergedNode, newReadKey, writeKey);
  return { published, mergedChildren };
}

/**
 * Shared key-chain-walk helper (RESEARCH.md Pitfall 3 / Anti-Patterns): resolve
 * an IPNS name, fetch its content-addressed CID from IPFS, and parse the
 * PublishedNode envelope. Used by BOTH `verifySubtreeClean`'s recursive
 * read-only walk and `rotateReadFromNode`'s mutating BFS so envelope
 * resolution has exactly ONE implementation.
 */
async function resolveAndFetchNode(
  ipnsName: string,
  ctx: SdkContext
): Promise<PublishedNode | null> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) return null;
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}

/**
 * Shared key-chain-walk helper (RESEARCH.md Pitfall 3 / Anti-Patterns): resolve
 * a child's published envelope AND derive its readKey from the PARENT's
 * readKey via `unsealChildReadKey` (AAD binds the child's id/kind and the
 * PARENT-MIRRORED generation — `childRef.generation`, not the child's own
 * published generation). Used by BOTH `verifySubtreeClean` (read-only) and
 * the main BFS (mutating) so this key-derivation logic has exactly ONE
 * implementation — recursing `verifySubtreeClean` without this shared helper
 * would duplicate the BFS's resolve+unseal logic with subtly different bugs.
 *
 * @returns `null` when the child's IPNS record cannot be resolved (missing —
 *   a non-root data inconsistency; callers treat this as "unreachable", not
 *   "dirty" — only a MISSING ROOT is surfaced as dirty, per SC#2/T-70-08).
 */
async function resolveChildKeyAndEnvelope(
  childRef: SealedChildRef,
  parentReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ childPub: PublishedNode; childReadKey: Uint8Array } | null> {
  const childPub = await resolveAndFetchNode(childRef.ipnsName, ctx);
  if (!childPub) return null;
  const childReadKey = await unsealChildReadKey(
    childRef.readKeySealed,
    parentReadKey,
    childPub.id,
    childPub.kind,
    childRef.generation
  );
  return { childPub, childReadKey };
}

/**
 * A dirty frontier node discovered by `verifySubtreeClean`'s recursive walk —
 * carries everything a BFS caller needs to seed its queue directly at this
 * node, at ANY depth (RESEARCH.md Pitfall 3): the consumer no longer needs to
 * re-derive keys assuming the dirty node is an immediate child of the root.
 */
export type DirtyFrontierItem = {
  ipnsName: string;
  nodeId: string;
  /** IPNS name of this node's actual parent (may be any depth below root). */
  parentIpnsName: string;
  /** This node's own pre-rotation readKey, engine-derived via the shared key-chain walk. */
  nodeReadKey: Uint8Array;
  childPubKind: 'folder' | 'file';
  /** Parent-mirror generation captured when this dirty edge was found. */
  enqueuedGeneration: number;
};

/**
 * SEAM: Verify the subtree is clean before a resume walk.
 *
 * Recurses the FULL subtree (not just the root's immediate children — SC#2 /
 * T-70-08): resolves every node's published IPNS record and compares each
 * parent-mirror generation (`SealedChildRef.generation`) against the child's
 * own published envelope generation to collect dirty frontier nodes at ANY
 * depth. A missing root record is treated as DIRTY/surfaced — never
 * short-circuited to "clean" — since a resume must never assume convergence
 * when it cannot even see the current published truth. The caller
 * (`rotateReadFromNode`'s dirty-resume block) re-resolves the root itself on
 * the `isDirty: true` path and throws a descriptive, actionable error when it
 * too finds the root missing.
 *
 * Recursion only descends below CLEAN edges: a dirty edge's derived readKey
 * is the child's STALE pre-rotation key (from the still-unrefreshed parent
 * mirror), which cannot unseal that child's CURRENT published body to
 * discover further descendants — there is no cryptographic recovery path for
 * a key genuinely lost to an interrupted prior run (RESEARCH.md Pitfall 4). A
 * dirty node is recorded in the frontier and left for the BFS's own
 * convergence-guard witness-refresh to resolve safely on resume.
 *
 * Invoked ONLY on resume (when the root is found already-committed at walk
 * start — conditional per D-01/D-10); never on a fresh run.
 */
export async function verifySubtreeClean(
  rootIpnsName: string,
  rootReadKey: Uint8Array,
  ctx: SdkContext
): Promise<{ isDirty: boolean; frontier: DirtyFrontierItem[] }> {
  // 1. Resolve root → fetch PublishedNode envelope. Missing root ⇒ dirty (SC#2).
  const rootPub = await resolveAndFetchNode(rootIpnsName, ctx);
  if (!rootPub) return { isDirty: true, frontier: [] };

  // 2. Unseal root to walk its SealedChildRef list.
  const rootNode = await unsealNode(rootPub, rootReadKey);

  // 3. Recurse the FULL subtree to collect dirty frontier nodes at ANY depth.
  const frontier: DirtyFrontierItem[] = [];
  await collectDirtyFrontier(rootIpnsName, rootNode.children ?? [], rootReadKey, ctx, frontier);

  return { isDirty: frontier.length > 0, frontier };
}

/**
 * Recursive full-subtree dirty-edge walk backing `verifySubtreeClean` (SC#2).
 * See `verifySubtreeClean`'s docstring for why recursion stops below a dirty
 * edge. Published IPNS records are the source of truth (D-10).
 */
async function collectDirtyFrontier(
  parentIpnsName: string,
  children: SealedChildRef[],
  parentReadKey: Uint8Array,
  ctx: SdkContext,
  frontier: DirtyFrontierItem[]
): Promise<void> {
  for (const childRef of children) {
    const resolved = await resolveChildKeyAndEnvelope(childRef, parentReadKey, ctx);
    if (!resolved) continue; // missing non-root child — data inconsistency, not root-dirty
    const { childPub, childReadKey } = resolved;

    // Dirty edge: parent's mirror generation lags the child's actual published state.
    if (childPub.generation > childRef.generation) {
      frontier.push({
        ipnsName: childRef.ipnsName,
        nodeId: childPub.id,
        parentIpnsName,
        nodeReadKey: childReadKey,
        childPubKind: childPub.kind as 'folder' | 'file',
        enqueuedGeneration: childRef.generation,
      });
      continue; // cannot recurse further below a dirty edge — see module docstring
    }

    // Clean edge: the derived key IS provably the child's current valid key
    // (parent mirror is up to date) — recurse into folder children to find
    // dirty edges deeper in the subtree.
    if (childPub.kind === 'folder') {
      const childNode = await unsealNode(childPub, childReadKey);
      await collectDirtyFrontier(
        childRef.ipnsName,
        childNode.children ?? [],
        childReadKey,
        ctx,
        frontier
      );
    }

    // D-09 (Plan 70-06): a CLEAN edge's derived key is scoped entirely to this
    // read-only verify walk — it is never returned to any caller (only a DIRTY
    // edge's key survives, pushed onto `frontier` above and explicitly NOT
    // zeroed here). This function derived it (via resolveChildKeyAndEnvelope);
    // it is the terminal owner once the edge is fully processed (leaf, or after
    // the recursive call above returns). Defensive instanceof guard: some unit
    // tests stub `unsealChildReadKey` without a return value.
    if (childReadKey instanceof Uint8Array) {
      childReadKey.fill(0);
    }
  }
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
    nodeWriteKey,
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

  // Fetch and unseal the node's read-body under parentReadKey.
  // When nodeWriteKey is provided, also recover the write-body in the same call so
  // it can be re-sealed unchanged on the reseal step (read/write planes are independent).
  // (parentReadKey is the key chained from the parent — for root nodes it is the
  //  root's own readKey, supplied by the rotation caller)
  const published = await fetchPublishedNode(resolved.cid, ctx);
  const node = await unsealNode(published, parentReadKey, nodeWriteKey);

  // Step 2 (continued): idempotency check with the derived nodeId from the unsealed node
  const nodeId = providedNodeId ?? node.id;
  if (jobRecord.completedNodeIds.has(nodeId)) {
    return { skipped: true, childReadKey: new Uint8Array(32), newGeneration: node.generation };
  }

  // D-01 fail-closed: require a real IPNS signing key for every frontier node.
  // Phase 64 threads keys via nodeKeySource in RotationParams; Phase 65 derives them
  // from the unsealed write-body. Never publish an IPNS record with a placeholder —
  // reject not just undefined but malformed/all-zero key material (the old placeholder
  // was `new Uint8Array(32)`). IPNS keys here are the 32-byte Ed25519 seed (derive-ipns.ts).
  if (
    !(nodeIpnsPrivateKey instanceof Uint8Array) ||
    nodeIpnsPrivateKey.length !== 32 ||
    nodeIpnsPrivateKey.every((byte) => byte === 0)
  ) {
    throw new Error(
      `rotateOne: no valid IPNS private key for ${nodeIpnsName} — ` +
        'provide via nodeKeySource (Phase 64) or write-body wiring (Phase 65)'
    );
  }

  // D-01 fail-closed: if the published envelope has a write-body, a real writeKey MUST be
  // threaded. A missing or all-zero writeKey would silently drop the write-plane on re-seal
  // (RESEARCH Pitfall 2 / T-65-17). Guard mirrors the IPNS-key guard above.
  if (published.writeSealed) {
    if (
      !(nodeWriteKey instanceof Uint8Array) ||
      nodeWriteKey.length !== 32 ||
      nodeWriteKey.every((byte) => byte === 0)
    ) {
      throw new Error(
        `rotateOne: writeSealed present for ${nodeIpnsName} but no valid writeKey threaded — ` +
          'provide via nodeKeySource.writeKey (Phase 65)'
      );
    }
  }

  // Step 4: Mint fresh readKey' (32 cryptographically random bytes) and generation'
  // Do NOT zero parentReadKey — caller is terminal owner (D-09).
  const readKeyPrime = crypto.getRandomValues(new Uint8Array(32));
  const generationPrime = node.generation + 1;

  // Track whether mintFileKeyOnRotate placed a minted key onto the node so the
  // failure path can zero it without touching the caller-owned old fileKey (D-09).
  let fileKeyMinted = false;

  // SC#3 (Plan 70-04): captures the plaintext CAS-merged children when the
  // publish's merge closure below actually ran (CAS-409). Mirrors
  // registration.ts's `currentWriteChildren` outer-scope-capture idiom. Used
  // by the final return below so a concurrent add surfaced by the merge is
  // handed back to the BFS caller instead of the pre-merge `node.children`.
  let mergedChildrenForReturn: SealedChildRef[] | undefined;

  try {
    // Step 5: SEAM — content-key rotation for file nodes (Phase 64 — ROT-03/CRIT-1)
    // Invoked CONDITIONALLY — clean happy-path (folder node) NEVER reaches this.
    if (node.kind === 'file') {
      await mintFileKeyOnRotate(node, jobRecord);
      fileKeyMinted = true;
    }

    // Step 6: Re-seal the read-body under readKey' with the new generation'.
    // When nodeWriteKey is provided, the write-body is re-sealed under the SAME key —
    // read-rotation does NOT rotate the write plane (read/write planes are independent).
    // If the node has no write-body, an empty writeKey is passed (sealNode ignores it).
    const updatedNode: Node = { ...node, generation: generationPrime };
    // Use the real writeKey when the node has a write-body; otherwise pass empty bytes
    // (sealNode only uses writeKey when node.writeBody is set — empty is safe here).
    const writeKeyForReseal: Uint8Array = node.writeBody ? nodeWriteKey! : new Uint8Array(0);
    const resealedPublished = await sealNode(updatedNode, readKeyPrime, writeKeyForReseal);

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
      merge: async (base, _local, remote) => {
        // ROT-05/HIGH-4: CAS-409 on rotation publish — merge concurrent child adds.
        // Re-unseal base + remote under the OLD readKey, three-way merge children,
        // then re-seal under readKeyPrime so the merged result is published atomically.
        //
        // `base` is always set here (baseData = published, the initial fetch), but
        // we guard against undefined for defensive correctness.
        if (!base) {
          // No base snapshot: treat local children as both base and local.
          // This path should not occur in practice (published is always set).
          const mergedNode: Node = { ...node, generation: generationPrime };
          return { merged: await sealNode(mergedNode, readKeyPrime, writeKeyForReseal) };
        }
        const mergedResult = await mergeConcurrentChildren(
          base,
          remote,
          parentReadKey, // OLD readKey — remote was sealed under this key
          node.children ?? [], // local children (from closure — no extra unseal needed)
          readKeyPrime, // NEW readKey — re-seal merged result under rotation key
          node,
          generationPrime,
          writeKeyForReseal
        );
        // SC#3: capture the plaintext merged children for the final return below.
        mergedChildrenForReturn = mergedResult.mergedChildren;
        return { merged: mergedResult.published };
      },
      localData: resealedPublished,
      baseData: published,
    });

    // Step 9 (continued): SEAM — re-mint inner grants only when supplied (D-01 conditional).
    // Clean happy-path (no inner grants) NEVER invokes this seam.
    // D-07: reMintGrantsRootedAt runs BEFORE completedNodeIds.add(nodeId) so that a
    // failure during re-mint does NOT silently skip the node on resume (the add must be
    // the last mutation — if reMint throws, the catch below zeros readKeyPrime and
    // re-throws, and nodeId is never written to completedNodeIds).
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

    // Step 9: Mark N done in the job record (D-07: AFTER reMintGrantsRootedAt succeeds).
    jobRecord.completedNodeIds.add(nodeId);

    return {
      skipped: false,
      childReadKey: readKeyPrime,
      newGeneration: generationPrime,
      newReadKeySealed,
      // SC#3: use the CAS-merged children (when a 409 merge ran) instead of the
      // pre-merge node.children snapshot, so a concurrently-added child gets
      // enqueued by the BFS caller rather than silently forgotten.
      children: mergedChildrenForReturn ?? node.children ?? [],
      newSequenceNumber: casResult.newSequenceNumber,
    };
  } catch (err) {
    // Zero readKeyPrime on failure — rotateOne minted it, so rotateOne is terminal owner.
    // DO NOT zero parentReadKey — caller is terminal owner (D-09).
    readKeyPrime.fill(0);
    // Zero the minted fileKey' on failure only if mintFileKeyOnRotate already ran (seal/publish
    // failed after minting). Do NOT zero if fileKeyMinted is false (old key is caller-owned,
    // D-09). Do NOT zero on the success path — sealNode is the terminal consumer there.
    if (fileKeyMinted && node.content?.fileKey) {
      node.content.fileKey.fill(0);
    }
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
 *
 * Plan 70-06 (SC#3): the entry gate no longer branches on `completedNodeIds.size`.
 * A read-only root-unseal PROBE runs first (throwing {@link RootKeyStaleError} on
 * failure), then a `verifySubtreeClean`-driven dirty-tail check runs UNCONDITIONALLY
 * — including on a genuinely FRESH record (`completedNodeIds` empty) — so a dirty
 * tail left by a lost prior run is recovered via safe double-rotation (design §4.5)
 * even when this job has no memory of that prior run.
 *
 * Host-agnostic (D-02): no FUSE / Tauri / web import.
 *
 * @security Does NOT zero `rootReadKey` — caller is terminal owner (D-09).
 *
 * @returns {@link RotateReadResult} — the root's readKey/generation/sequenceNumber
 * — either the root's freshly minted key (a fresh rotation occurred this run) or,
 * on the dirty-resume-republish path (root itself did not rotate this run, but a
 * dirty tail below it was recovered), a FRESH COPY of the caller-supplied
 * `rootReadKey` (never an alias — SC#6 / T-70-10). Returns `undefined` only when
 * NOTHING changed this run (root already done AND the subtree is fully clean).
 */
export async function rotateReadFromNode(
  params: RotationParams
): Promise<RotateReadResult | undefined> {
  const {
    rootNodeId,
    rootNodeIpnsName,
    rootReadKey,
    rootIpnsPrivateKey,
    rootIpnsPublicKey,
    jobRecord,
    ctx,
    nodeKeySource,
    innerGrants,
    grantCallbacks,
  } = params;

  jobRecord.status = 'in-progress';

  // ---------------------------------------------------------------------------
  // SC#3 (Plan 70-06 / RESEARCH Pitfall 4 / Open Question 1): restructured entry
  // gate. Probe root-unseal viability with the supplied rootReadKey BEFORE deciding
  // fresh rotateOne(root) vs dirty-tail-only recovery — regardless of
  // completedNodeIds.size. A MISSING root record is a distinct scenario (handled
  // downstream by rotateOne's own "not found in IPNS" throw); only an unseal
  // FAILURE against an EXISTING published root is the genuinely-unrecoverable
  // stale-key window (no cryptographic recovery from the durable floor — it stores
  // generation/sequence numbers only, never key material).
  const rootProbePub = await resolveAndFetchNode(rootNodeIpnsName, ctx);
  if (rootProbePub) {
    try {
      await unsealNode(rootProbePub, rootReadKey);
    } catch (probeErr) {
      throw new RootKeyStaleError(
        `rotateReadFromNode: rootReadKey cannot unseal the currently-published root ` +
          `${rootNodeIpnsName}. The root was likely rotated by a lost prior run — no ` +
          'cryptographic recovery is possible from the durable floor (it stores ' +
          'generation/sequence numbers only, never key material). Fall back to a ' +
          'top-down re-navigation from the vault root.',
        { cause: probeErr }
      );
    }
  }

  // SC#3: verifySubtreeClean-driven dirty-tail detection now runs UNCONDITIONALLY
  // (not gated on completedNodeIds.size) using the just-confirmed-valid rootReadKey,
  // BEFORE root itself rotates this run. rotateOne(root) does not mutate the
  // children mirror (only re-seals root's OWN body), so this frontier — derived via
  // 70-05's key-bearing recursive walk — remains valid for BOTH branches below.
  const preRotationDirtyFrontier: DirtyFrontierItem[] = rootProbePub
    ? (await verifySubtreeClean(rootNodeIpnsName, rootReadKey, ctx)).frontier
    : [];

  // §4.2: Rotate the scope-root FIRST.
  // This is the actual cut: once the root's readKey is rotated and published,
  // a revoked grantee can no longer derive any child key from their old grant.
  // Safe double-rotation (design §4.5): if the root was already rotated by a lost
  // prior run and the probe above confirmed rootReadKey is still current, this
  // mints ANOTHER new key — an extra rotation only strengthens revocation.
  const rootResult = await rotateOne({
    nodeId: rootNodeId,
    nodeIpnsName: rootNodeIpnsName,
    nodeIpnsPrivateKey: rootIpnsPrivateKey,
    nodeIpnsPublicKey: rootIpnsPublicKey,
    // Thread the root's writeKey from nodeKeySource if available (Phase 65).
    nodeWriteKey: nodeKeySource?.(rootNodeIpnsName)?.writeKey,
    parentReadKey: rootReadKey,
    parentIpnsName: rootNodeIpnsName, // root has no parent; parentIpnsName unused in Phase 63
    parentCurrentSeq: 0n, // unused in Phase 63 (parent-link publish deferred to Phase 64)
    jobRecord,
    ctx,
    // SC#4 (Plan 70-06): thread grantCallbacks/innerGrants so reMintGrantsRootedAt
    // is reachable from the real (non-test) walk.
    innerGrants,
    grantCallbacks,
  });

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
    /**
     * The parent's OLD (pre-rotation) readKey — an engine-owned COPY (never an
     * alias of a caller/BFS-item buffer that may be zeroed elsewhere before
     * this state is torn down). Needed by `createConcurrentAddResealingMerge`
     * (Phase 70 correction of the 70-04 over-reach) to unwrap a concurrently-
     * added child's `readKeySealed` — it was sealed by the concurrent writer
     * under the parent's key AS IT STOOD BEFORE this rotation, not the new
     * one. Zeroed by the engine (terminal owner of this copy) when the
     * tracking state is torn down in `decrementPendingAndMaybeRepublish`.
     */
    parentOldReadKey: Uint8Array;
    parentIpnsName: string;
    parentIpnsPrivateKey?: Uint8Array;
    parentIpnsPublicKey?: Uint8Array;
    parentNodeId: string;
    parentNodeGeneration: number;
    parentLastSeq: bigint;
    children: SealedChildRef[]; // mutable copy updated as children rotate
    /**
     * Snapshot of the parent's children captured at `parentTracking.set(...)`
     * time — BEFORE any child-driven mutation (D-02 re-seals). Passed as
     * `baseChildren` to `updateFolderMetadataAndPublish` at the D-09 batched
     * republish call sites so `mergeRotatedChildren`'s base-only-omission
     * check is computed against the true CAS base, not an empty default
     * (SC#1 site B / SC#3 coupling).
     */
    baseChildrenSnapshot: SealedChildRef[];
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
    /** Write key threaded from nodeKeySource for write-body re-seal (Phase 65). */
    nodeWriteKey?: Uint8Array;
    /** Stable UUID from the child's PublishedNode envelope (for D-02 AAD binding). */
    childPubId: string;
    /** Node kind from the child's PublishedNode envelope (for D-02 AAD binding). */
    childPubKind: 'folder' | 'file';
    /**
     * SealedChildRef.generation captured at enqueue time (parent mirror).
     * Plan 70-06: no longer used to gate a convergence-skip (design §4.5 safe
     * double-rotation removed the no-double-bump guard) — retained only as
     * D-02 AAD-binding metadata carried alongside each queue item.
     */
    enqueuedGeneration: number;
  }> = [];

  /**
   * Phase 70 correction of the 70-04 over-reach (SC#3 / ROT-05 / design
   * §3.7-§4.5 / RR-01): wraps `mergeRotatedChildren`'s three-way merge with an
   * out-of-band re-seal of any concurrently-added child's
   * `SealedChildRef.readKeySealed` under the parent's NEW readKey' — WITHOUT
   * enqueuing the child onto the BFS `queue` for its own `rotateOne` pass.
   *
   * ROT-05 only requires that a concurrent add survive the merge (never be
   * silently dropped); design §3.7/§4.5 + the RR-01 todo call for the
   * concurrent child to be "picked up" (merged into the parent AND re-sealed
   * under the new epoch), with a FULL RE-KEY of the child's own node
   * explicitly deferred as a follow-on concern. The prior implementation
   * over-reached in two ways: (1) it pushed the concurrent child onto `queue`
   * for a full `rotateOne` pass, which requires the child's IPNS PRIVATE
   * (write) key — a concurrently-writing DIFFERENT party's add gives the
   * rotating party no structural guarantee of holding that key; and (2) it
   * ran AFTER `parentTracking.delete(...)`, so even a successful re-seal never
   * reached the parent's own published `SealedChildRef.readKeySealed`
   * (orphaning navigation parent→child). This version fixes both: only the
   * WRAPPER (the parent's pointer to the child's UNCHANGED readKey) is
   * re-sealed, and it happens INSIDE the merge — before the (possibly
   * CAS-retried) publish that becomes the parent's canonical published body.
   *
   * A concurrent writer may have sealed the wrapper under EITHER the parent's
   * OLD (pre-rotation) key — unaware of the in-flight rotation — OR the
   * parent's already-current NEW key' — when their write raced the D-09
   * batched republish AFTER the parent's own rotateOne had already committed
   * (the common real race: reading+re-sealing the parent's CURRENT published
   * body necessarily uses whichever key is valid at that moment). Both are
   * tried (old first); a wrapper already under the new key is left as-is
   * (no-op, not an error).
   *
   * @param parentOldReadKey - the parent's readKey as it stood BEFORE this
   *   rotation.
   * @param parentNewReadKey - the parent's freshly minted readKey' (from the
   *   parent's own rotateOne result) — what the re-sealed wrapper must be
   *   readable under going forward.
   */
  function createConcurrentAddResealingMerge(
    parentOldReadKey: Uint8Array,
    parentNewReadKey: Uint8Array
  ): (
    base: SealedChildRef[],
    local: SealedChildRef[],
    remote: SealedChildRef[]
  ) => Promise<SealedChildRef[]> {
    return async (base, local, remote) => {
      const merged = mergeRotatedChildren(base, local, remote);
      const baseNames = new Set(base.map((c) => c.ipnsName));
      const localNames = new Set(local.map((c) => c.ipnsName));

      for (let i = 0; i < merged.length; i++) {
        const child = merged[i];
        // Only a REMOTE-only entry (present in neither base nor local) is a
        // concurrent add needing this re-seal: anything already in `local`
        // carries the walk's own D-02 re-seal (applied earlier for a normal
        // rotated child); anything in `base` was already sealed correctly
        // before this rotation began and local-wins/base-drop already handled
        // it inside mergeRotatedChildren.
        if (baseNames.has(child.ipnsName) || localNames.has(child.ipnsName)) continue;

        // A concurrent writer may have sealed this child's readKeySealed under
        // EITHER the parent's OLD (pre-rotation) key — unaware of the
        // in-flight rotation — OR the parent's NEW readKey' — when their own
        // write raced the D-09 batched republish AFTER the parent's own
        // rotateOne had already committed (reading+re-sealing the parent's
        // CURRENT published body necessarily uses whichever key is valid at
        // that moment). `unsealChildReadKey` AEAD-fails closed (throws) on the
        // wrong key — try old first (needs re-seal), fall back to new
        // (already correctly sealed — no-op, not an error).
        let resolved: Awaited<ReturnType<typeof resolveChildKeyAndEnvelope>> = null;
        let alreadySealedUnderNewKey = false;
        try {
          resolved = await resolveChildKeyAndEnvelope(child, parentOldReadKey, ctx);
        } catch {
          // Old-key unwrap AEAD-failed — fall through to the new-key attempt.
        }
        if (!resolved) {
          try {
            resolved = await resolveChildKeyAndEnvelope(child, parentNewReadKey, ctx);
            alreadySealedUnderNewKey = true;
          } catch {
            resolved = null;
          }
        }
        if (!resolved) continue; // neither key unwraps — data inconsistency, leave as-is (not fatal)
        if (alreadySealedUnderNewKey) {
          // Already sealed under the parent's current key — nothing to do.
          resolved.childReadKey.fill(0);
          continue;
        }
        const { childPub, childReadKey } = resolved;
        try {
          const reSealed = await sealChildReadKey(
            childReadKey, // the concurrent child's OWN readKey — unchanged, only re-wrapped
            parentNewReadKey,
            childPub.id,
            childPub.kind as 'folder' | 'file',
            child.generation
          );
          merged[i] = { ...child, readKeySealed: reSealed };
        } finally {
          // Transient copy this closure derived via unsealChildReadKey — zero
          // it, NOT the caller-owned parentOldReadKey/parentNewReadKey
          // buffers (D-09 terminal-owner rule).
          childReadKey.fill(0);
        }
      }

      return merged;
    };
  }

  /**
   * D-09 shared tail: decrement a parent's pending-child counter and, once it
   * reaches zero, perform the batched parent re-publish exactly once. Used both
   * for a NORMAL child completion and — Plan 70-06 / SC#3 / T-70-12 — for the
   * fail-closed accounting path below, so a missing child record still lets the
   * parent converge instead of leaving `pendingChildCount` stuck above zero
   * forever (a silent `continue` that desyncs the counter).
   */
  async function decrementPendingAndMaybeRepublish(
    parentState: ParentTrackingState,
    parentTrackingKey: string
  ): Promise<void> {
    parentState.pendingChildCount--;
    if (parentState.pendingChildCount === 0) {
      await updateFolderMetadataAndPublish({
        ipnsName: parentState.parentIpnsName,
        ipnsPrivateKey: parentState.parentIpnsPrivateKey!,
        ipnsPublicKey: parentState.parentIpnsPublicKey,
        sequenceNumber: parentState.parentLastSeq,
        readKey: parentState.parentNewReadKey,
        nodeId: parentState.parentNodeId,
        nodeGeneration: parentState.parentNodeGeneration,
        children: parentState.children,
        baseChildren: parentState.baseChildrenSnapshot,
        // Phase 70 correction (SC#3): re-seals any concurrently-added child's
        // readKeySealed under the parent's NEW readKey as part of the CAS-409
        // merge itself — see createConcurrentAddResealingMerge's docstring.
        mergeChildrenFn: createConcurrentAddResealingMerge(
          parentState.parentOldReadKey,
          parentState.parentNewReadKey
        ),
        ctx,
      });
      // Engine-owned copy (see ParentTrackingState.parentOldReadKey) — zero it
      // here as the terminal owner; never the caller-owned parentNewReadKey.
      parentState.parentOldReadKey.fill(0);
      parentTracking.delete(parentTrackingKey);
    }
  }

  /**
   * SC#3 (Plan 70-06): seed the BFS queue directly from a `DirtyFrontierItem`
   * discovered by `verifySubtreeClean`'s recursive walk (consuming plan 70-05's
   * key-bearing frontier shape). Builds a minimal `SealedChildRef` stub — only
   * `ipnsName`/`generation` are read by the BFS loop itself; `readKeySealed` is
   * never re-derived from this stub (the item already carries an engine-derived
   * `nodeReadKey`). Deduped by ipnsName against items already queued so a
   * depth-1 dirty edge (also covered by the normal children-enqueue loop) is not
   * double-processed.
   */
  function enqueueDirtyFrontierItem(item: DirtyFrontierItem): void {
    if (queue.some((q) => q.childRef.ipnsName === item.ipnsName)) {
      // Deduped against an item already queued (e.g. a depth-1 dirty edge also
      // covered by the normal children-enqueue loop) — this item is discarded
      // and its key is never referenced again. Zero it here as the terminal
      // owner (D-09); do NOT zero below after push, since in that (adopted)
      // path this same buffer reference becomes the queue item's nodeReadKey
      // and is zeroed exactly once by the BFS loop's own finally (line ~1629).
      item.nodeReadKey.fill(0);
      return;
    }
    const childKeys = nodeKeySource?.(item.ipnsName);
    queue.push({
      childRef: {
        name: item.ipnsName,
        ipnsName: item.ipnsName,
        generation: item.enqueuedGeneration,
        versionFloor: 0n,
        readKeySealed: '',
      },
      nodeReadKey: item.nodeReadKey,
      parentIpnsName: item.parentIpnsName,
      ipnsPrivateKey: childKeys?.privateKey,
      ipnsPublicKey: childKeys?.publicKey,
      nodeWriteKey: childKeys?.writeKey,
      childPubId: item.nodeId,
      childPubKind: item.childPubKind,
      enqueuedGeneration: item.enqueuedGeneration,
    });
  }

  // SC#6 (Plan 70-06 / T-70-10): captures a fresh-copy result to hand back on the
  // dirty-resume-republish path (root itself did not rotate THIS run, but a dirty
  // tail below it WAS recovered) — never the caller-owned rootReadKey buffer.
  let dirtyResumeResult: RotateReadResult | undefined;

  if (rootResult.skipped) {
    // Resume path: root already committed (in completedNodeIds) — a same-session/
    // same-job resume. `preRotationDirtyFrontier` was already computed above
    // (BEFORE rotateOne(root) ran, which was a no-op on this branch since it
    // skipped) using the exact same rootReadKey — reuse it rather than re-running
    // verifySubtreeClean a second time (SC#3 / Plan 70-06).
    const frontier = preRotationDirtyFrontier;
    const isDirty = frontier.length > 0;
    if (!isDirty) {
      // Subtree fully converged — no dirty edges to process.
      jobRecord.status = 'complete';
      if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);
      // Resume/skip path: root did not rotate THIS run — no fresh key to return.
      return undefined;
    }

    // Dirty resume: re-fetch root's current state and seed BFS from dirty frontier nodes.
    const rootResolved = await resolveIpnsRecord(rootNodeIpnsName, ctx);
    if (!rootResolved) {
      throw new Error('rotateReadFromNode: root IPNS not found on dirty resume');
    }
    const rootRaw = await fetchFromIpfs(ctx, rootResolved.cid);
    const rootPub = JSON.parse(new TextDecoder().decode(rootRaw)) as PublishedNode;
    const rootNode = await unsealNode(rootPub, rootReadKey);

    if (frontier.length > 0) {
      // D-01 fail-closed: the dirty-resume path does NOT pass through rotateOne's
      // non-null key check (root was rotated in a prior run), so guard here before
      // seeding parentTracking. Otherwise `parentIpnsPrivateKey!` at the convergence-skip
      // republish (below) would force an `undefined` key into updateFolderMetadataAndPublish.
      if (!rootIpnsPrivateKey) {
        throw new Error(
          `rotateReadFromNode: no IPNS private key for dirty root republish ${rootNodeIpnsName} ` +
            '— provide via nodeKeySource (D-01 fail-closed)'
        );
      }
      // Set up parent tracking for root using rootReadKey as the readKey proxy.
      // (Root was rotated in a prior run; rootReadKey unseals the current sealed body as
      // confirmed by verifySubtreeClean's successful unseal.)
      const rootParentState: ParentTrackingState = {
        parentNewReadKey: rootReadKey,
        // Dirty-resume: root itself did NOT rotate this run (already committed
        // in the prior run) — its "old" and "current" readKey are the same
        // rootReadKey. A concurrent add reaching this parent was sealed under
        // this same (already-current) key, so old===new is the correct proxy.
        parentOldReadKey: new Uint8Array(rootReadKey),
        parentIpnsName: rootNodeIpnsName,
        parentIpnsPrivateKey: rootIpnsPrivateKey,
        parentIpnsPublicKey: rootIpnsPublicKey,
        parentNodeId: rootNode.id,
        parentNodeGeneration: rootNode.generation,
        parentLastSeq: rootResolved.sequenceNumber,
        children: [...(rootNode.children ?? [])],
        baseChildrenSnapshot: [...(rootNode.children ?? [])],
        pendingChildCount: frontier.length,
      };
      parentTracking.set(rootNodeIpnsName, rootParentState);

      for (const frontierItem of frontier) {
        try {
          const childRef = (rootNode.children ?? []).find(
            (c) => c.ipnsName === frontierItem.ipnsName
          );
          if (!childRef) {
            // SC#3 (Plan 70-06 / T-70-12): fail-closed accounting — a frontier item
            // whose IPNS name is no longer present in root's current children mirror
            // must not silently leave pendingChildCount stuck above zero forever.
            await decrementPendingAndMaybeRepublish(rootParentState, rootNodeIpnsName);
            continue;
          }
          const resolved = await resolveChildKeyAndEnvelope(childRef, rootReadKey, ctx);
          if (!resolved) {
            // SC#3 (Plan 70-06 / T-70-12): fail-closed accounting — see above.
            await decrementPendingAndMaybeRepublish(rootParentState, rootNodeIpnsName);
            continue;
          }
          const { childPub, childReadKey } = resolved;
          const childKeys = nodeKeySource?.(frontierItem.ipnsName);
          queue.push({
            childRef,
            nodeReadKey: childReadKey,
            parentIpnsName: rootNodeIpnsName,
            ipnsPrivateKey: childKeys?.privateKey,
            ipnsPublicKey: childKeys?.publicKey,
            nodeWriteKey: childKeys?.writeKey,
            childPubId: childPub.id,
            childPubKind: childPub.kind as 'folder' | 'file',
            enqueuedGeneration: childRef.generation,
          });
        } finally {
          // frontierItem.nodeReadKey (this dirty node's own pre-rotation key,
          // minted by verifySubtreeClean/collectDirtyFrontier) is NEVER adopted
          // into `queue` by this loop — the queue item's nodeReadKey above is
          // always the freshly re-derived childReadKey from
          // resolveChildKeyAndEnvelope(childRef, rootReadKey, ctx), a distinct
          // buffer. Zero the frontier item's buffer here as its terminal owner
          // on every exit path (not-found, resolve-failed, or queued).
          frontierItem.nodeReadKey.fill(0);
        }
      }

      // SC#6 (Plan 70-06 / T-70-10): a dirty-resume republish is about to happen
      // (or already fully happened via the fail-closed accounting above) — surface
      // a truthy result so the caller can refresh its own cache. `readKey` is
      // ALWAYS a fresh copy, never an alias of the caller-owned `rootReadKey`.
      dirtyResumeResult = {
        readKey: new Uint8Array(rootReadKey),
        generation: rootNode.generation,
        sequenceNumber: rootResolved.sequenceNumber,
      };
    }
    // Fall through to BFS loop.
  } else {
    // Normal path: root just committed in this run.

    // Persist after root commit (the high-value early checkpoint).
    if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);

    // Set up parent tracking for root's children (D-02/D-09).
    let rootParentState: ParentTrackingState | undefined;
    if (rootResult.children.length > 0) {
      rootParentState = {
        parentNewReadKey: rootResult.childReadKey,
        // Root's OLD (pre-rotation) readKey — a defensive copy of the
        // caller-owned rootReadKey (never zeroed here; D-09), owned by this
        // tracking state so it can be safely zeroed on teardown below without
        // touching the caller's buffer.
        parentOldReadKey: new Uint8Array(rootReadKey),
        parentIpnsName: rootNodeIpnsName,
        parentIpnsPrivateKey: rootIpnsPrivateKey,
        parentIpnsPublicKey: rootIpnsPublicKey,
        parentNodeId: rootNodeId,
        parentNodeGeneration: rootResult.newGeneration,
        parentLastSeq: rootResult.newSequenceNumber,
        children: [...rootResult.children], // mutable copy for in-place SealedChildRef updates
        baseChildrenSnapshot: [...rootResult.children],
        pendingChildCount: rootResult.children.length,
      };
      parentTracking.set(rootNodeIpnsName, rootParentState);
    }

    // Enqueue root's children: derive each child's readKey from the root's OLD readKey.
    // rootReadKey is the root's own (pre-rotation) key and is NOT zeroed by rotateOne (D-09).
    for (const childRef of rootResult.children) {
      // root's OLD readKey (still valid; never zeroed — D-09); parent-mirror
      // generation (§2.6 D-07 invariant 1) is the AAD bound by resolveChildKeyAndEnvelope.
      const resolved = await resolveChildKeyAndEnvelope(childRef, rootReadKey, ctx);
      if (!resolved) {
        // SC#3 (Plan 70-06 / T-70-12): fail-closed accounting — a missing child
        // record must not silently leave pendingChildCount stuck above zero
        // forever (data inconsistency, but the parent must still be able to
        // converge for every OTHER child that DOES resolve).
        if (rootParentState) {
          await decrementPendingAndMaybeRepublish(rootParentState, rootNodeIpnsName);
        }
        continue;
      }
      const { childPub, childReadKey } = resolved;
      // Thread per-node IPNS key from nodeKeySource (D-01 / Phase 64 seam).
      // Phase 65 also threads writeKey via the same seam.
      const childKeys = nodeKeySource?.(childRef.ipnsName);
      queue.push({
        childRef,
        nodeReadKey: childReadKey, // child's own (pre-rotation) readKey
        parentIpnsName: rootNodeIpnsName,
        ipnsPrivateKey: childKeys?.privateKey,
        ipnsPublicKey: childKeys?.publicKey,
        nodeWriteKey: childKeys?.writeKey,
        childPubId: childPub.id,
        childPubKind: childPub.kind as 'folder' | 'file',
        enqueuedGeneration: childRef.generation,
      });
    }

    // SC#3 (Plan 70-06): merge in any dirty-tail items discovered by the
    // pre-rotation verifySubtreeClean probe — a dirty depth-1 edge is deduped
    // against the loop above; a dirty edge below a CLEAN depth-1 parent would
    // otherwise never be reachable (that parent's own children are only
    // discovered once IT rotates, which the normal walk still does since dirty
    // items are no longer convergence-skipped — see the BFS loop below).
    for (const dirtyItem of preRotationDirtyFrontier) {
      enqueueDirtyFrontierItem(dirtyItem);
    }
  }

  // Process the frontier BFS.
  while (queue.length > 0) {
    const item = queue.shift()!;

    try {
      // Plan 70-06 / SC#3: NO convergence-skip guard here anymore. Design §4.5's
      // crash-recovery model is safe DOUBLE-ROTATION — a node already rotated
      // (by a lost prior run OR discovered via the dirty-tail frontier merge
      // above) is rotated AGAIN via the normal rotateOne call below. An extra
      // rotation only strengthens revocation and costs one republish; rotateOne's
      // OWN completedNodeIds idempotency check already makes a genuinely-already-
      // handled-THIS-session node a cheap no-op (RotateOneSkipped). Do NOT
      // reintroduce a no-double-bump guard here (T-70-*/design §4.5).
      const result = await rotateOne({
        // nodeId is absent: it will be derived from the unsealed node's id inside rotateOne.
        nodeIpnsName: item.childRef.ipnsName,
        nodeIpnsPrivateKey: item.ipnsPrivateKey,
        nodeIpnsPublicKey: item.ipnsPublicKey,
        // Thread the write key sourced at enqueue time (Phase 65).
        nodeWriteKey: item.nodeWriteKey,
        parentReadKey: item.nodeReadKey, // this node's own (pre-rotation) readKey
        parentIpnsName: item.parentIpnsName,
        parentCurrentSeq: 0n,
        jobRecord,
        ctx,
        // SC#4 (Plan 70-06): thread grantCallbacks/innerGrants so reMintGrantsRootedAt
        // is reachable from the real (non-test) walk.
        innerGrants,
        grantCallbacks,
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
          await decrementPendingAndMaybeRepublish(parentState, item.parentIpnsName);
        }

        // Set up parent tracking for this node's children (recursive D-02/D-09).
        let thisNodeParentState: ParentTrackingState | undefined;
        if (result.children.length > 0) {
          thisNodeParentState = {
            parentNewReadKey: result.childReadKey,
            // This node's OLD (pre-rotation) readKey — a defensive copy of
            // item.nodeReadKey, which the `finally` below zeros at the end of
            // THIS queue-item's processing (this tracking state can outlive
            // that: its own decrementPendingAndMaybeRepublish only fires once
            // all of THIS node's children finish, potentially several BFS
            // iterations later).
            parentOldReadKey: new Uint8Array(item.nodeReadKey),
            parentIpnsName: item.childRef.ipnsName,
            parentIpnsPrivateKey: item.ipnsPrivateKey,
            parentIpnsPublicKey: item.ipnsPublicKey,
            parentNodeId: item.childPubId,
            parentNodeGeneration: result.newGeneration,
            parentLastSeq: result.newSequenceNumber,
            children: [...result.children],
            baseChildrenSnapshot: [...result.children],
            pendingChildCount: result.children.length,
          };
          parentTracking.set(item.childRef.ipnsName, thisNodeParentState);
        }

        // Enqueue this node's children using THIS node's pre-rotation readKey.
        // item.nodeReadKey is NOT zeroed by rotateOne (D-09) — still valid here.
        for (const childRef of result.children) {
          // THIS node's old readKey (seals its children's readKeys) — item.nodeReadKey
          // is NOT zeroed by rotateOne (D-09), still valid here.
          const resolved = await resolveChildKeyAndEnvelope(childRef, item.nodeReadKey, ctx);
          if (!resolved) {
            // SC#3 (Plan 70-06 / T-70-12): fail-closed accounting — see above.
            if (thisNodeParentState) {
              await decrementPendingAndMaybeRepublish(thisNodeParentState, item.childRef.ipnsName);
            }
            continue;
          }
          const { childPub, childReadKey } = resolved;
          // Thread per-node IPNS key from nodeKeySource (D-01 / Phase 64 seam).
          // Phase 65 also threads writeKey via the same seam.
          const grandchildKeys = nodeKeySource?.(childRef.ipnsName);
          queue.push({
            childRef,
            nodeReadKey: childReadKey, // grandchild's own readKey
            parentIpnsName: item.childRef.ipnsName,
            ipnsPrivateKey: grandchildKeys?.privateKey,
            ipnsPublicKey: grandchildKeys?.publicKey,
            nodeWriteKey: grandchildKeys?.writeKey,
            childPubId: childPub.id,
            childPubKind: childPub.kind as 'folder' | 'file',
            enqueuedGeneration: childRef.generation,
          });
        }
      }
    } finally {
      // D-09 queue-key zeroization: zero the queue-derived readKey on ALL exit paths
      // (success, convergence-skip via continue, result.skipped, or throw). Runs after
      // all grandchildren have been enqueued (unsealChildReadKey used item.nodeReadKey
      // above). This node's item.nodeReadKey was minted by the parent's unsealChildReadKey
      // — the engine is the terminal owner. Never zero caller-supplied rootReadKey (D-09).
      item.nodeReadKey.fill(0);
    }
  }

  // Terminal status: all nodes rotated (every queued item — fresh or dirty-tail —
  // now goes through rotateOne; safe double-rotation replaced the old convergence
  // guard's skip behavior — Plan 70-06 / design §4.5).
  // Persist the complete status so the host can safely discard the job record
  // (Pitfall 5: never mark complete without persisting — the resumable walk gate
  // in verifySubtreeClean relies on the persisted status being accurate).
  jobRecord.status = 'complete';
  if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);

  // ROT-07 Gap 2 / SC#3 / SC#6 (Plan 70-06): surface the root's post-rotation state
  // to the caller so it can refresh its own folder cache (e.g.
  // performScopeExitRotation → folderTree.set).
  //   - Root rotated fresh THIS run → its freshly minted readKey (unchanged contract).
  //   - Root was skipped this run but a dirty-resume republish occurred below it →
  //     `dirtyResumeResult`, a FRESH COPY of the caller-supplied rootReadKey (never
  //     an alias — SC#6 / T-70-10 / Anti-Patterns).
  //   - Root was skipped AND nothing below it needed recovery → undefined (nothing
  //     changed this run; no state to refresh).
  if (rootResult.skipped) {
    return dirtyResumeResult;
  }
  return {
    readKey: rootResult.childReadKey,
    generation: rootResult.newGeneration,
    sequenceNumber: rootResult.newSequenceNumber,
  };
}

// ---------------------------------------------------------------------------
// rotateWriteFromNode — full Ed25519 write-plane rotation (WRITE-02/03/04)
// ---------------------------------------------------------------------------

/**
 * Internal result produced after processing a single node's write rotation.
 * Used to re-point parent nodes to new child names and new child write keys.
 */
type WriteRotationResult = {
  /** Original IPNS name (now tombstoned). */
  oldIpnsName: string;
  /** Newly minted k51 IPNS name (first-published at sequenceNumber 1n). */
  newIpnsName: string;
  /** Freshly minted Ed25519 public key for the new k51 (used to derive newIpnsName). */
  newIpnsPublicKey: Uint8Array;
  /** Freshly minted 32-byte write key for this node. */
  newWriteKey: Uint8Array;
  /** Original stable UUID of this node (unchanged through rotation). */
  nodeId: string;
  /** Node kind (for AAD binding in parent's sealChildWriteKey call). */
  kind: NodeKind;
  /** Original generation (NOT bumped — write-revoke is independent of read rotation). */
  generation: number;
};

/**
 * Recursively rotate the write plane for a subtree rooted at `oldIpnsName`.
 *
 * Ordering: child-first (bottom-up). Leaves get new k51 names first; parents
 * re-point their SealedChildRef.ipnsName and WriteChildRef.writeKeySealed to the
 * new child data only AFTER the child is first-published. This guarantees that
 * any reader following the parent's updated pointer will find the new child record
 * already committed (design §4.6 / §5.3).
 *
 * @security
 *   - Zeros freshly minted writeKey' and Ed25519 seeds on failure paths only (D-09).
 *   - NEVER zeros caller-supplied readKey or writeKey — caller is terminal owner (D-09 / Pitfall 4).
 *   - Does NOT bump generation or mint a readKey (read plane invariant — D-06 / ADR 0001).
 */
async function rotateWriteSubtree(
  oldIpnsName: string,
  readKey: Uint8Array,
  writeKey: Uint8Array,
  ctx: SdkContext,
  callbacks: WriteRevocationCallbacks,
  pendingTombstones: string[]
): Promise<WriteRotationResult> {
  // Step 1: Resolve old IPNS name → fetch → parse published envelope.
  const resolved = await resolveIpnsRecord(oldIpnsName, ctx);
  if (!resolved) {
    throw new Error(`rotateWriteFromNode: IPNS not found for ${oldIpnsName}`);
  }
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  const pub = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;

  // Step 2: Unseal both read-body and write-body.
  // readKey is caller-supplied — NEVER zeroed here (D-09).
  // writeKey is caller-supplied — NEVER zeroed here (D-09).
  const node = await unsealNode(pub, readKey, writeKey);

  // Fail closed: refuse to rotate a node that has no recoverable write body.
  // Creating a fresh write body here would mint a new write-capable node from a
  // read-only or unrecoverable envelope without proving possession of the old write
  // key — a security violation. Throw if the envelope carries no writeSealed field,
  // if unsealNode returned no writeBody, or if the stored ipnsPrivateKey is absent
  // or all-zero (zeroed seed = unrecoverable).
  if (
    !pub.writeSealed ||
    !node.writeBody ||
    !(node.writeBody.ipnsPrivateKey instanceof Uint8Array) ||
    node.writeBody.ipnsPrivateKey.length !== 32 ||
    node.writeBody.ipnsPrivateKey.every((byte) => byte === 0)
  ) {
    throw new Error(
      `rotateWriteSubtree: node ${pub.id ?? oldIpnsName} has no recoverable write body — cannot rotate a read-only node`
    );
  }

  // Step 3: Process write children recursively FIRST (child-first / bottom-up).
  // For each write child, derive its readKey (from SealedChildRef) and writeKey
  // (from WriteChildRef) so we can unseal the child and recurse.
  //
  // Build lookup maps:
  //   oldChildIpns → childResult     (for updating SealedChildRef.ipnsName in read-body)
  //   childId      → childResult     (for rebuilding WriteChildRef.writeKeySealed in write-body)
  const ipnsToChildResult = new Map<string, WriteRotationResult>();
  const idToChildResult = new Map<string, WriteRotationResult>();

  for (const writeChildRef of node.writeBody?.writeChildren ?? []) {
    // Correlation: find the SealedChildRef whose resolved published envelope has
    // the matching id. For small subtrees this is O(n*m); Phase 68 can optimise.
    let matchedChildRef: SealedChildRef | undefined;
    let childPub: PublishedNode | undefined;

    for (const candidateRef of node.children ?? []) {
      const candidateResolved = await resolveIpnsRecord(candidateRef.ipnsName, ctx);
      if (!candidateResolved) continue;
      const candidateRaw = await fetchFromIpfs(ctx, candidateResolved.cid);
      const candidatePub = JSON.parse(new TextDecoder().decode(candidateRaw)) as PublishedNode;
      if (candidatePub.id === writeChildRef.childId) {
        matchedChildRef = candidateRef;
        childPub = candidatePub;
        break;
      }
    }

    if (!matchedChildRef || !childPub) {
      throw new Error(
        `rotateWriteFromNode: no SealedChildRef found for write child ${writeChildRef.childId}`
      );
    }

    // Derive child read and write keys; zero both in finally regardless of which step
    // throws. If unsealChildWriteKey throws, childReadKey is already derived and must
    // be zeroed (D-09 terminal ownership).
    let childResult: WriteRotationResult;
    let childReadKey: Uint8Array | undefined;
    let childWriteKey: Uint8Array | undefined;
    try {
      childReadKey = await unsealChildReadKey(
        matchedChildRef.readKeySealed,
        readKey,
        childPub.id,
        childPub.kind,
        matchedChildRef.generation
      );

      // Derive child write key (needed to unseal the child's write-body).
      childWriteKey = await unsealChildWriteKey(
        writeChildRef.writeKeySealed,
        writeKey,
        writeChildRef.childId,
        childPub.kind,
        matchedChildRef.generation
      );

      // Recurse into the child subtree BEFORE processing this node (child-first).
      childResult = await rotateWriteSubtree(
        matchedChildRef.ipnsName,
        childReadKey,
        childWriteKey,
        ctx,
        callbacks,
        pendingTombstones
      );
    } finally {
      // Zero derived child keys when this scope exits (success or failure).
      // These were derived by this function — it is their terminal owner (D-09).
      childReadKey?.fill(0);
      childWriteKey?.fill(0);
    }

    ipnsToChildResult.set(matchedChildRef.ipnsName, childResult);
    idToChildResult.set(writeChildRef.childId, childResult);
  }

  // Step 4: Mint new Ed25519 keypair for this node's new k51 name.
  // generateEd25519Keypair is synchronous (no async); it returns a new keypair each call.
  const newKeypair = generateEd25519Keypair();
  const newIpnsName = await deriveIpnsName(newKeypair.publicKey);

  // Step 5: Mint new write key (32 cryptographically random bytes).
  const newWriteKey = generateRandomBytes(32);

  try {
    // Step 6: Rebuild write-body with:
    //   - new ipnsPrivateKey (new k51 signing seed)
    //   - re-sealed writeChildren pointing to each child's NEW write key, sealed
    //     under THIS node's NEW write key with updated AAD (child-first: children
    //     already have their newWriteKey from the recursive calls above).
    //
    // Collect child results BEFORE the map so the defensive sweep below can zero
    // any surviving newWriteKey buffers (D-09 / #7 terminal-owner rule).
    const childResultsToZero = Array.from(new Set(idToChildResult.values()));
    const newWriteChildren = await Promise.all(
      node.writeBody.writeChildren.map(async (writeChildRef) => {
        const childResult = idToChildResult.get(writeChildRef.childId);
        if (!childResult) {
          throw new Error(
            `rotateWriteFromNode: missing rotation result for write child ${writeChildRef.childId}`
          );
        }
        const writeKeySealed = await sealChildWriteKey(
          childResult.newWriteKey,
          newWriteKey,
          writeChildRef.childId,
          childResult.kind,
          childResult.generation
        );
        // Zero child's minted writeKey immediately after sealing — this scope is
        // the terminal owner once sealChildWriteKey has consumed it (D-09 / #2).
        childResult.newWriteKey.fill(0);
        return { childId: writeChildRef.childId, writeKeySealed };
      })
    );
    // Defensive sweep: zero any child write keys that were not consumed above
    // (e.g. idToChildResult entries with no matching writeChildren ref). D-09 / #7.
    for (const cr of childResultsToZero) {
      cr.newWriteKey.fill(0);
    }

    // Step 7: Rebuild read-body children — update ipnsName for rotated children.
    // readKeySealed is NOT re-sealed (read plane invariant — D-06 / ADR 0001).
    // generation is NOT bumped (write-revoke does not bump the read-key epoch).
    const updatedChildren = (node.children ?? []).map((childRef) => {
      const childResult = ipnsToChildResult.get(childRef.ipnsName);
      if (!childResult) return childRef; // not in write chain — keep unchanged
      return { ...childRef, ipnsName: childResult.newIpnsName };
    });

    // Step 8: Build the updated node.
    // DO NOT bump generation — write-revoke is independent of the read-key epoch (D-06).
    const newNode: Node = {
      ...node,
      // generation stays the same (read-plane invariant)
      children: updatedChildren,
      writeBody: {
        ipnsPrivateKey: newKeypair.privateKey,
        writeChildren: newWriteChildren,
      },
    };

    // Step 9: Re-seal. readKey is caller-supplied (never zeroed — D-09).
    // newWriteKey is minted here — it is sealed into the write-body now and will be
    // zeroed on failure paths in this try/catch (D-09 terminal ownership).
    const sealedNode = await sealNode(newNode, readKey, newWriteKey);

    // Step 10: Upload to IPFS.
    const jsonBytes = new TextEncoder().encode(JSON.stringify(sealedNode));
    const { cid } = await addToIpfs(ctx, jsonBytes);

    // Step 11: First-publish to the NEW k51 name at sequenceNumber 1n.
    // Strict gate: new k51 names MUST be published at exactly 1n (project memory
    // ipns-first-publish-embed-seq-1; server rejects any other value).
    // Check the returned success flag — a non-throwing rejection still signals that
    // the record was not accepted; continuing to tombstone or rewrap grants under
    // an unpublished name would leave the write plane in an inconsistent state (#8).
    const publishResult = await createAndPublishIpnsRecord({
      ipnsPrivateKey: newKeypair.privateKey,
      ipnsPublicKey: newKeypair.publicKey,
      ipnsName: newIpnsName,
      metadataCid: cid,
      sequenceNumber: 1n,
      ctx,
    });
    if (!publishResult.success) {
      throw new Error(
        `rotateWriteSubtree: first-publish rejected for ${newIpnsName} (seq=${publishResult.sequenceNumber})`
      );
    }

    // Zero the Ed25519 private key immediately after publish — it has been both
    // sealed into the write-body (Step 9) and used to sign the IPNS record (Step 11).
    // It is no longer needed and is the terminal owner here (D-09).
    newKeypair.privateKey.fill(0);

    // Step 12: Deferred tombstone-intent — enqueue the old name for removal from
    // the TEE republish batch. The actual unenroll is fired by rotateWriteFromNode
    // AFTER the entire subtree is successfully published, so a failed ancestor
    // publish cannot leave the TEE with a unenrolled child it still references
    // via the old parent pointer (§5.5 ordering guarantee).
    pendingTombstones.push(oldIpnsName);

    return {
      oldIpnsName,
      newIpnsName,
      newIpnsPublicKey: newKeypair.publicKey,
      newWriteKey,
      nodeId: node.id,
      kind: node.kind,
      generation: node.generation,
    };
  } catch (err) {
    // Zero minted keys on failure — this function is their terminal owner (D-09).
    // DO NOT zero caller-supplied readKey or writeKey (D-09 / Pitfall 4).
    newWriteKey.fill(0);
    newKeypair.privateKey.fill(0);
    throw err;
  }
}

/**
 * Rotate the write plane for every node in the subtree rooted at `rootIpnsName`.
 *
 * Implements ADR-0001 (c): full Ed25519 rotation of the write plane, minting a new
 * k51 name + Ed25519 keypair + writeKey per node. Ordering is child-first (bottom-up)
 * so that parents can point to already-published new child names (design §4.6 / §5.3,
 * OQ-2 resolution).
 *
 * Read chain invariant (D-06 / ADR 0001): this driver does NOT mint any readKey and
 * does NOT bump any generation counter. Write-revoke is independent of read rotation.
 *
 * All transport (IPNS publish, IPFS add, DB persist, TEE enroll/unenroll) is injected
 * via `callbacks` so the engine remains host-agnostic (D-02). Unit tests inject vi.fn()
 * mocks; Phase 66 callers supply real API implementations.
 *
 * @security
 *   - Caller-supplied `rootReadKey` and `rootWriteKey` are NEVER zeroed (D-09).
 *   - Minted writeKey' / Ed25519 seeds are zeroed on failure paths only (D-09 / Pitfall 4).
 *   - Co-writer re-wrap: only non-revoked recipients receive wrapKey(newRootWriteKey) (WRITE-03).
 *   - Tombstone-intent: teeUnenrollFn removes old k51 from the TEE republish batch (WRITE-04).
 *   - Live publish-gate reject + resolve-410 are mock-asserted here; cut over live in Phase 66.
 */
export async function rotateWriteFromNode(params: {
  rootNodeId: string;
  rootIpnsName: string;
  rootReadKey: Uint8Array;
  rootWriteKey: Uint8Array;
  ctx: SdkContext;
  callbacks: WriteRevocationCallbacks;
}): Promise<{ newRootIpnsName: string }> {
  const { rootNodeId, rootIpnsName, rootReadKey, rootWriteKey, ctx, callbacks } = params;

  // Collect old IPNS names for deferred tombstone-intent. We fire teeUnenrollFn for
  // each name AFTER the entire subtree is published so a failed ancestor publish
  // cannot leave live parents pointing at already-unenrolled child names (§5.5).
  const pendingTombstones: string[] = [];

  // Perform the child-first recursive rotation for the entire subtree.
  // rootReadKey and rootWriteKey are caller-supplied — NEVER zeroed here (D-09).
  const rootResult = await rotateWriteSubtree(
    rootIpnsName,
    rootReadKey,
    rootWriteKey,
    ctx,
    callbacks,
    pendingTombstones
  );

  // Guard: verify the unsealed root's node.id matches the caller-supplied rootNodeId
  // before mutating grants. A mismatch would rewrap/delete grants for a different node
  // than the one whose write plane was actually rotated (WRITE-03 / #9).
  // Zero the minted root write key before throwing if the check fails (D-09).
  if (rootResult.nodeId !== rootNodeId) {
    rootResult.newWriteKey.fill(0);
    throw new Error(
      `rotateWriteFromNode: rootNodeId mismatch — expected ${rootNodeId}, got ${rootResult.nodeId}`
    );
  }

  // Wrap tombstones + grant mutations in try/finally so the minted root write key is
  // zeroed even when a callback throws (D-09 / #10). The key is the terminal owner here —
  // rotateWriteSubtree transferred ownership on success.
  try {
    // Fire deferred tombstones now that the entire subtree is successfully published.
    // Old names are removed from the TEE republish batch only once all new names are live.
    for (const oldName of pendingTombstones) {
      await callbacks.teeUnenrollFn(oldName);
    }

    // Re-wrap the new root write key for each surviving co-writer and drop revoked grants.
    // queryWriteGrantsFn is called AFTER the new root name is published so the new
    // writeKey is stable (no partial re-wrap if publish fails — WRITE-03).
    const grants = await callbacks.queryWriteGrantsFn(rootNodeId);
    for (const grant of grants) {
      if (grant.isRevoked) {
        // Revoked recipient: drop their grant row — do NOT re-wrap (WRITE-03).
        await callbacks.deleteWriteGrantFn(grant.shareId);
      } else {
        // Surviving co-writer: ECIES-wrap the new root write key under their public key.
        let wrapped: Uint8Array;
        try {
          wrapped = await wrapKey(rootResult.newWriteKey, grant.recipientPublicKey);
        } catch (err) {
          throw new Error('rotateWriteFromNode: wrapKey for co-writer failed', { cause: err });
        }
        const writeDescriptorRef = bytesToBase64(wrapped);
        await callbacks.writeDescriptorRefPersistFn(grant.shareId, writeDescriptorRef);
      }
    }
  } finally {
    // Zero the root's new write key regardless of whether callbacks succeeded or threw.
    // This key was minted by rotateWriteSubtree; rotateWriteFromNode is its terminal
    // owner (D-09). Zeroing twice is harmless — fill(0) on an already-zeroed buffer
    // is a no-op at the byte level.
    rootResult.newWriteKey.fill(0);
  }

  return { newRootIpnsName: rootResult.newIpnsName };
}
