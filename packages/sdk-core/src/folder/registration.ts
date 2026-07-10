/**
 * Folder registration operations — IPNS record build and publish.
 *
 * Phase 63 implementation: un-stubbed createSubfolder and updateFolderMetadataAndPublish
 * using the Phase-62 node/v3 codec (sealNode) and the CAS-retry helper (publishWithCas).
 *
 * Security invariants:
 *   - createSubfolder mints new Ed25519 keypair + readKey/writeKey and does NOT zero them
 *     before returning — caller is the terminal owner (D-09).
 *   - updateFolderMetadataAndPublish does NOT zero readKey or ipnsPrivateKey — callers are
 *     terminal owners (D-09).
 *   - mergeChildren is a Phase-64 stub; conflict path throws until phase 64 wires the merge.
 */

import { sealNode, unsealNode } from '@cipherbox/core';
import type { Node, PublishedNode, SealedChildRef, WriteChildRef } from '@cipherbox/core';
import { generateEd25519Keypair, generateRandomBytes, deriveIpnsName } from '@cipherbox/crypto';
import type { SdkContext, TeeKeys } from '../types';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import { createAndPublishIpnsRecord } from '../ipns';
import { publishWithCas } from '../cas';
import { mergeChildren } from './merge';
import { wrapIpnsKeyForTee } from '../tee/wrap';

/**
 * Create a new subfolder with generated keys.
 *
 * Generates a fresh Ed25519 IPNS keypair, derives the k51 IPNS name, generates a
 * 32-byte readKey and writeKey, builds and seals the initial empty folder Node,
 * uploads to IPFS, and publishes the first IPNS record with sequenceNumber 1n
 * (required by the Phase-60 strict CAS gate — a first publish with embedded seq != 1
 * is rejected with 400).
 *
 * @param params.name - Display name of the new subfolder (stored in parent metadata only)
 * @param params.ctx  - SDK context for IPFS + IPNS access
 * @param params.userPublicKey - Optional: user's public key for future grant fan-out (phase 65)
 * @param params.teeKeys       - Optional: TEE keys for IPNS republishing (phase 65)
 * @returns Fresh node, IPNS private key, readKey and writeKey (caller is terminal owner — D-09)
 */
export async function createSubfolder(params: {
  name: string;
  ctx: SdkContext;
  userPublicKey?: Uint8Array;
  teeKeys?: TeeKeys;
}): Promise<{
  node: Node;
  ipnsPrivateKey: Uint8Array;
  rootReadKey: Uint8Array;
  rootWriteKey: Uint8Array;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}> {
  // 1. Generate IPNS keypair
  const { publicKey: ipnsPublicKey, privateKey: ipnsPrivateKey } = await generateEd25519Keypair();

  // 2. Derive the k51 IPNS name from the public key
  const ipnsName = await deriveIpnsName(ipnsPublicKey);

  // 3. Generate 32-byte readKey and writeKey
  const readKey = generateRandomBytes(32);
  const writeKey = generateRandomBytes(32);

  // 4. Build the initial empty folder Node
  const node: Node = {
    schema: 'node/v3',
    kind: 'folder',
    id: crypto.randomUUID(),
    generation: 0,
    createdAt: Date.now(),
    modifiedAt: Date.now(),
    children: [],
  };

  // 5. Compute TEE enrollment fields (if teeKeys supplied) BEFORE any IPFS upload —
  //    fail closed on incomplete config so a malformed teeKeys short-circuits before
  //    the seal/upload side effects and never leaves an orphaned blob behind.
  let encryptedIpnsPrivateKey: string | undefined;
  let keyEpoch: number | undefined;
  if (params.teeKeys) {
    const { currentPublicKey, currentEpoch } = params.teeKeys;
    if (!currentPublicKey) {
      throw new Error(
        'createSubfolder: teeKeys.currentPublicKey is missing or empty — refusing to publish un-enrolled subfolder'
      );
    }
    if (!Number.isInteger(currentEpoch) || currentEpoch < 1) {
      throw new Error(
        'createSubfolder: teeKeys.currentEpoch must be a positive integer (>= 1) — refusing to publish un-enrolled subfolder'
      );
    }
    // ECIES-wrap the generated IPNS private key under the TEE public key.
    // Do NOT zero ipnsPrivateKey here — wrapIpnsKeyForTee borrows the buffer, it
    // does not consume it; the caller is the terminal owner (D-09).
    encryptedIpnsPrivateKey = await wrapIpnsKeyForTee(ipnsPrivateKey, currentPublicKey);
    keyEpoch = currentEpoch;
  }

  // 6. Seal the Node with the generated keys
  const publishedNode = await sealNode(node, readKey, writeKey);

  // 7. Upload sealed Node to IPFS
  const { cid } = await addToIpfs(
    params.ctx,
    new TextEncoder().encode(JSON.stringify(publishedNode))
  );

  // 8. Publish first IPNS record — sequenceNumber MUST be 1n (Phase-60 strict gate)
  await createAndPublishIpnsRecord({
    ipnsPrivateKey,
    ipnsName,
    metadataCid: cid,
    sequenceNumber: 1n,
    ctx: params.ctx,
    encryptedIpnsPrivateKey,
    keyEpoch,
  });

  // 9. Return keys to caller — do NOT zero (caller is terminal owner, D-09)
  return {
    node,
    ipnsPrivateKey,
    rootReadKey: readKey,
    rootWriteKey: writeKey,
    encryptedIpnsPrivateKey,
    keyEpoch,
  };
}

/**
 * Update folder metadata and publish to IPNS via CAS-retry.
 *
 * Seals the updated SealedChildRef children list into a new folder Node and publishes
 * via the generic CAS-retry helper. On 409 conflict, delegates three-way merge to
 * mergeChildren (Phase-64 stub — throws until phase 64 wires the merge logic).
 *
 * @param params.children       - Updated SealedChildRef array (new local state)
 * @param params.baseChildren   - Base snapshot for three-way merge on conflict
 * @param params.readKey        - 32-byte AES-256 readKey (canonical; phase 63+)
 * @param params.folderKey      - 32-byte AES-256 readKey (backward-compat alias for readKey)
 * @param params.writeKey       - Optional 32-byte AES-256 writeKey. When supplied, the sealed
 *   Node carries a real write-body (`{ ipnsPrivateKey, writeChildren }`) sealed under this key
 *   (D-03). When omitted, no write-body is attached (legacy read-only-write compatibility) and
 *   sealing falls back to an unused zero-filled writeKey (no writeSealed field is produced,
 *   since sealNode only seals a write-body when node.writeBody is set).
 * @param params.writeChildren  - Write-chain entries to persist inside the write-body (preserved
 *   verbatim, order-stable). Defaults to an empty array. Only meaningful when writeKey is supplied.
 * @param params.ipnsPrivateKey - Ed25519 private key for IPNS signing
 * @param params.ipnsName       - IPNS k51 name of the folder
 * @param params.sequenceNumber - Current sequence number (CAS guard: next will be +1)
 * @param params.ctx            - SDK context for IPFS + IPNS access
 *
 * @security Does NOT zero readKey, writeKey, or ipnsPrivateKey — callers are terminal owners (D-09).
 */
export async function updateFolderMetadataAndPublish(params: {
  children: SealedChildRef[];
  baseChildren?: SealedChildRef[];
  /**
   * Base write-body snapshot (pre-mutation `writeChildren`), keyed by
   * `childId` (UUID) — the write-plane analog of `baseChildren`. When
   * supplied, the CAS-409 write-body merge becomes base-aware: a childId
   * present in `baseWriteChildren` but ABSENT from `writeChildren` (this
   * call's own local state) is treated as an intentional delete this
   * transaction already committed to, and is pruned even if a racing
   * writer's stale remote snapshot still carries it (SC#1 Critical Finding
   * 2 / T-72-03-01). When omitted, the merge falls back to the legacy naive
   * union (back-compat for callers that have not threaded this through yet).
   */
  baseWriteChildren?: WriteChildRef[];
  /**
   * Optional injectable conflict-resolution policy for the CAS-409 merge
   * closure below. Defaults to `mergeChildren` (remote-wins) — every
   * non-rotation caller (add/move/rename) is byte-unchanged. The rotation
   * engine's two D-09 batched-republish call sites pass `mergeRotatedChildren`
   * (local-wins) explicitly (SC#1 site B / T-70-01). NEVER change the default
   * — see `rotation/merge.ts`'s module doc for why local-wins must stay
   * syntactically opt-in, not the generic policy.
   *
   * May return a `Promise` — the D-09 site wraps `mergeRotatedChildren` in an
   * async closure that also re-seals any concurrently-added child's
   * `readKeySealed` under the parent's NEW readKey (Phase 70 correction of the
   * 70-04 over-reach — see `rotation/engine.ts`'s
   * `createConcurrentAddResealingMerge`). Sync returns remain fully supported.
   */
  mergeChildrenFn?: (
    base: SealedChildRef[],
    local: SealedChildRef[],
    remote: SealedChildRef[]
  ) => SealedChildRef[] | Promise<SealedChildRef[]>;
  /** Canonical readKey name (phase 63). */
  readKey?: Uint8Array;
  /** @deprecated Backward-compat alias — use readKey. client.ts callers still pass folderKey. */
  folderKey?: Uint8Array;
  /** Optional writeKey — when supplied, seals a real write-body (D-03). */
  writeKey?: Uint8Array;
  /** Write-chain entries to persist in the write-body (preserved verbatim). Defaults to []. */
  writeChildren?: WriteChildRef[];
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  /**
   * UUID of the underlying folder Node. REQUIRED (D-06): must be the stable id of
   * the folder's Node — never omit to mint a fresh UUID. Omitting breaks
   * buildNodeAad AAD stability and the rotation convergence witness.
   */
  nodeId: string;
  /**
   * Generation of the underlying folder Node. REQUIRED (D-06): must be the current
   * rotation counter — never reset to 0. Omitting corrupts the convergence witness
   * that rotateReadFromNode relies on.
   */
  nodeGeneration: number;
}): Promise<{
  cid: string;
  newSequenceNumber: bigint;
  publishedChildren: SealedChildRef[];
  /**
   * The write-body children actually sealed into the published record — equals
   * the input `writeChildren` on a clean publish, or the CAS-merged union of
   * local + remote write links after a 409. Callers MUST adopt THIS (not their
   * pre-publish local snapshot) into the in-memory write-body mirror, or the
   * next publish reseals a stale chain and re-drops a concurrent writer's ref.
   * Undefined for read-only (no-writeKey) publishes.
   */
  publishedWriteChildren?: WriteChildRef[];
}> {
  const key = params.readKey ?? params.folderKey;
  if (!key) throw new Error('updateFolderMetadataAndPublish: readKey or folderKey is required');
  // Only used to seal when node.writeBody is absent (sealNode never produces a
  // writeSealed field in that case), so the zero fallback is inert — it exists
  // purely so sealNode's required writeKey parameter has a value (D-03).
  const writeKeyForSeal = params.writeKey ?? new Uint8Array(32);

  // Write-plane CAS state. The generic publishWithCas TData only carries the
  // read-body (SealedChildRef[]); the write-body (WriteChildRef[], keyed by
  // childId) must be merged separately on a 409 or the retry reseals a STALE
  // write chain and DROPS any WriteChildRef a concurrent writer added — the
  // exact write-plane clobber phase 68.1 exists to prevent. `currentWriteChildren`
  // is what encodeAndUpload seals; decodeRemote captures the remote write-body.
  // merge() applies a BASE-AWARE prune (SC#1 Critical Finding 2 / T-72-03-01):
  // a childId present in `baseWriteChildren` but absent from the caller's local
  // `writeChildren` is an intentional delete this transaction already committed
  // to, and is pruned even when a racing writer's stale remote snapshot still
  // carries it — a plain union would silently resurrect it. A childId absent
  // from base but present in remote is a genuine concurrent add and is always
  // kept. Only meaningful when a real writeKey is supplied.
  let currentWriteChildren: WriteChildRef[] = params.writeChildren ?? [];
  let remoteWriteChildren: WriteChildRef[] = [];

  const result = await publishWithCas<SealedChildRef[]>({
    ipnsName: params.ipnsName,
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsPublicKey: params.ipnsPublicKey,
    sequenceNumber: params.sequenceNumber,
    ctx: params.ctx,
    encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
    keyEpoch: params.keyEpoch,
    maxAttempts: 3,
    backoff: true,

    encodeAndUpload: async (localChildren: SealedChildRef[]): Promise<string> => {
      // D-06: nodeId and nodeGeneration are required — no fallbacks.
      // A fresh UUID per call breaks buildNodeAad AAD stability; generation=0 after
      // any rotation breaks the parent.SealedChildRef[N].generation convergence test.
      if (!params.nodeId) {
        throw new Error(
          'nodeId is required — do not omit (D-06): a fresh UUID per call breaks AAD binding'
        );
      }
      if (params.nodeGeneration === undefined || params.nodeGeneration === null) {
        throw new Error(
          'nodeGeneration is required — do not reset to 0 (D-06): rotation relies on monotonic generation'
        );
      }
      if (
        typeof params.nodeGeneration !== 'number' ||
        !Number.isFinite(params.nodeGeneration) ||
        params.nodeGeneration < 0 ||
        !Number.isInteger(params.nodeGeneration)
      ) {
        throw new Error(
          'nodeGeneration must be a finite non-negative integer (D-06): got ' +
            String(params.nodeGeneration)
        );
      }
      const node: Node = {
        schema: 'node/v3',
        kind: 'folder',
        id: params.nodeId,
        generation: params.nodeGeneration,
        createdAt: Date.now(),
        modifiedAt: Date.now(),
        children: localChildren,
        // D-03: attach a real write-body only when the caller supplies a writeKey.
        // Omitting writeKey preserves legacy read-only-write compatibility (no
        // writeSealed field is produced by sealNode when writeBody is absent).
        // Seal `currentWriteChildren` (not params.writeChildren) so a CAS-merged
        // write chain survives a retry instead of being clobbered back to the
        // stale local snapshot.
        ...(params.writeKey
          ? {
              writeBody: {
                ipnsPrivateKey: params.ipnsPrivateKey,
                writeChildren: currentWriteChildren,
              },
            }
          : {}),
      };
      const publishedNode: PublishedNode = await sealNode(node, key, writeKeyForSeal);
      const { cid } = await addToIpfs(
        params.ctx,
        new TextEncoder().encode(JSON.stringify(publishedNode))
      );
      return cid;
    },

    decodeRemote: async (cid: string): Promise<SealedChildRef[]> => {
      const raw = await fetchFromIpfs(params.ctx, cid);
      const publishedNode = JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
      // Pass writeKey (when present) so the remote write-body is unsealed too and
      // its writeChildren can be merged — not dropped — on conflict. A present
      // remote write-body sealed under a wrong writeKey fails GCM auth closed
      // here (fail-closed, matching the read-body's own auth contract).
      const node = await unsealNode(publishedNode, key, params.writeKey);
      remoteWriteChildren = node.writeBody?.writeChildren ?? [];
      return node.children ?? [];
    },

    merge: async (
      base: SealedChildRef[] | undefined,
      local: SealedChildRef[],
      remote: SealedChildRef[]
    ) => {
      // Merge the remote writer's write-body entries into the local chain,
      // keyed by childId. Only when a real writeKey is in play — otherwise no
      // write-body is sealed at all.
      if (params.writeKey) {
        if (params.baseWriteChildren) {
          // Base-aware 3-way prune (SC#1 Critical Finding 2, extended by the
          // F5 remote-delete fix): a childId present in base is kept ONLY if
          // it is STILL present on BOTH sides (local and remote) — if EITHER
          // side dropped it since base, that deletion is honored and the
          // entry is never resurrected, regardless of which side raced
          // ahead. This is symmetric: a childId present in base but absent
          // from local is never resurrected by a racing writer's stale
          // remote snapshot that still carries it (Test C); a childId
          // present in base and untouched in local but concurrently DELETED
          // by the remote writer is likewise dropped, not carried forward
          // just because local's stale copy still has it (F5 — the prior
          // version only protected local's own deletes, not remote's).
          // A childId absent from base (a genuinely concurrent add, from
          // either side) is always kept — neither side can have "deleted"
          // something it never knew existed (Test B).
          const baseIds = new Set(params.baseWriteChildren.map((wc) => wc.childId));
          const localIds = new Set(currentWriteChildren.map((wc) => wc.childId));
          const mergedMap = new Map<string, WriteChildRef>();
          for (const wc of currentWriteChildren) {
            if (!baseIds.has(wc.childId)) mergedMap.set(wc.childId, wc);
          }
          for (const wc of remoteWriteChildren) {
            if (!baseIds.has(wc.childId) || localIds.has(wc.childId)) {
              // Either a genuinely concurrent remote add, or present in base
              // and still present on both sides — remote wins on a
              // conflicting value for an existing entry (matches prior
              // behavior). Otherwise (present in base, absent from local):
              // fall through and drop it — one side deleted it.
              mergedMap.set(wc.childId, wc);
            }
          }
          currentWriteChildren = Array.from(mergedMap.values());
        } else {
          // No base snapshot supplied — legacy naive union (back-compat for
          // callers that have not threaded baseWriteChildren through yet).
          const byChildId = new Map<string, WriteChildRef>();
          for (const wc of currentWriteChildren) byChildId.set(wc.childId, wc);
          for (const wc of remoteWriteChildren) byChildId.set(wc.childId, wc);
          currentWriteChildren = Array.from(byChildId.values());
        }
      }
      // SC#1 site B / T-70-01: defaults to the generic remote-wins mergeChildren
      // for every non-rotation caller; the rotation engine opts in explicitly
      // via mergeChildrenFn. params.baseChildren is the caller's captured base
      // snapshot (falls back to the CAS base argument, then []).
      // `await` supports both sync mergeChildren/mergeRotatedChildren and the
      // async concurrent-add-resealing wrapper the rotation engine's D-09 site
      // passes (publishWithCas's own `merge` already supports an async return).
      const mergeFn = params.mergeChildrenFn ?? mergeChildren;
      return { merged: await mergeFn(params.baseChildren ?? base ?? [], local, remote) };
    },

    localData: params.children,
    baseData: params.baseChildren,
  });

  return {
    cid: result.cid,
    newSequenceNumber: result.newSequenceNumber,
    publishedChildren: result.publishedData,
    publishedWriteChildren: params.writeKey ? currentWriteChildren : undefined,
  };
}
