/**
 * @cipherbox/sdk — Owner-reconcile driver (D-10/D-11, mirrors Phase 65 D-01/Q3)
 *
 * When a write-recipient C independently unlinks+bins a node that the owner
 * had sub-shared to D, D's grant row goes dangling. The owner's reconcile pass
 * re-derives those grants by driving sdk-core's `reMintGrantsRootedAt` (built
 * + mock-tested in Phase 65) with callbacks assembled from an injected
 * `OwnerReconcileTransport`.
 *
 * This module is the TESTABLE tier (per docs/TESTING.md): all transport is
 * injected, so it is unit-tested here with a `vi.fn()` transport. The
 * `apps/web` counterpart (`owner-reconcile.service.ts`) is a thin, untested
 * wrapper that supplies the concrete api-client transport.
 *
 * @security
 *   No recipient advisory is emitted (D-11 / ADR 0002) — this driver has no
 *   notification surface. Revoked grants are deleted, never re-minted
 *   (T-64-04b, enforced inside sdk-core's `reMintGrantsRootedAt`).
 */

import { reMintGrantsRootedAt } from '@cipherbox/sdk-core';
import type { RotationJobRecord, SdkContext } from '@cipherbox/sdk-core';

/**
 * The `reMintGrantsRootedAt` callbacks shape, extracted structurally from
 * sdk-core's exported function signature (`GrantRemintCallbacks` is not part
 * of the sdk-core public barrel — only the `.` export path is published, so
 * we derive the type rather than adding a new sdk-core export surface).
 */
type GrantRemintCallbacks = NonNullable<Parameters<typeof reMintGrantsRootedAt>[5]>;

/**
 * A sent-grant row as returned by the injected transport, pre-decode into the
 * shape `reMintGrantsRootedAt` expects (see queryGrantsFn mapping below).
 */
export type GrantRow = {
  shareId: string;
  recipientPublicKey: Uint8Array;
  isRevoked: boolean;
  rootNodeId: string;
};

/**
 * Injected transport for the owner-reconcile driver. `apps/web` implements
 * this with the real api-client (sharesControllerGetSentShares /
 * sharesControllerUpdateGrant / sharesControllerRevokeShare); unit tests
 * inject `vi.fn()` mocks.
 */
export type OwnerReconcileTransport = {
  /** Returns every grant the current user (owner) has sent. */
  listSentGrants: () => Promise<GrantRow[]>;
  /** Persists the re-minted ECIES-wrapped encrypted key for a surviving recipient. */
  updateGrant: (shareId: string, encryptedReadKey: string, generation: number) => Promise<void>;
  /** Removes a revoked recipient's grant row. */
  deleteGrant: (shareId: string) => Promise<void>;
};

/**
 * Build `GrantRemintCallbacks` for `reMintGrantsRootedAt` from an injected
 * `OwnerReconcileTransport`.
 *
 * `queryGrantsFn(nodeId)` client-side-filters `transport.listSentGrants()` by
 * `rootNodeId === nodeId` (RESEARCH A3 — acceptable v1) and maps each row to
 * the `{ shareId, recipientPublicKey, isRevoked }` shape sdk-core expects.
 */
export function buildGrantRemintCallbacks(
  transport: OwnerReconcileTransport
): GrantRemintCallbacks {
  // D-02 (TS mirror): memoize the sent-grants fetch for the lifetime of this
  // callbacks bundle (one runOwnerReconcile pass). `queryGrantsFn(nodeId)` is
  // invoked once per rotated node, so an un-cached `listSentGrants()` fans out
  // to O(nodes × shares) relay fetches. The memo is closure-scoped (NOT
  // global/static) so it never leaks state across reconcile passes; the
  // per-node `rootNodeId` filter stays applied on each call.
  let cachedGrants: Promise<GrantRow[]> | undefined;
  return {
    queryGrantsFn: async (nodeId: string) => {
      cachedGrants ??= transport.listSentGrants();
      const grants = await cachedGrants;
      return grants
        .filter((grant) => grant.rootNodeId === nodeId)
        .map((grant) => ({
          shareId: grant.shareId,
          recipientPublicKey: grant.recipientPublicKey,
          isRevoked: grant.isRevoked,
        }));
    },
    updateGrantFn: (shareId, encryptedReadKey, newGeneration) =>
      transport.updateGrant(shareId, encryptedReadKey, newGeneration),
    deleteGrantFn: (shareId) => transport.deleteGrant(shareId),
  };
}

/**
 * Drive the owner-reconcile pass for a rotated subtree rooted at `rootNodeId`:
 * re-mints surviving sent grants under `newReadKey`/`newGeneration` and
 * deletes revoked ones. Thin pass-through to sdk-core's
 * `reMintGrantsRootedAt` with callbacks assembled from `transport`.
 *
 * @security Does NOT zero `newReadKey` — caller is the terminal owner (D-09).
 */
export async function runOwnerReconcile(
  rootNodeId: string,
  newReadKey: Uint8Array,
  newGeneration: number,
  job: RotationJobRecord,
  ctx: SdkContext,
  transport: OwnerReconcileTransport
): Promise<void> {
  const callbacks = buildGrantRemintCallbacks(transport);
  await reMintGrantsRootedAt(rootNodeId, newReadKey, newGeneration, job, ctx, callbacks);
}
