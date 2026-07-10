/**
 * Owner-reconcile transport wrapper (D-10/D-11)
 *
 * THIN, UNTESTED wrapper (per docs/TESTING.md doctrine): the driver logic
 * (revoked -> delete, surviving -> re-mint, rootNodeId filter) is unit-tested
 * in `packages/sdk/src/share/owner-reconcile.ts`. This file only supplies the
 * concrete api-client transport (GET sent shares / PATCH grant / DELETE
 * share) + DTO decode, and triggers the SDK driver eagerly on login/app-open.
 *
 * Cadence (D-11): eager on login/app-open (this file) + opportunistically
 * after the owner's own mutations (wired in 68-08, using the freshly-rotated
 * readKey from the mutation-complete event). No advisory is emitted to the
 * recipient (ADR 0002).
 */

import {
  sharesControllerGetSentShares,
  sharesControllerUpdateGrant,
  sharesControllerRevokeShare,
} from '@cipherbox/api-client';
import { hexToBytes } from '@cipherbox/crypto';
import { runOwnerReconcile, type OwnerReconcileTransport, type GrantRow } from '@cipherbox/sdk';
import type { RotationJobRecord, SdkContext } from '@cipherbox/sdk-core';
import { apiAxios, apiUrl } from '../lib/api-config';
import { useAuthStore } from '../stores/auth.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';

/** A decoded sent-share row, enriched with `shareRootIpnsName` for the FolderTree lookup below. */
type DecodedSentGrant = GrantRow & { shareRootIpnsName: string };

/**
 * Fetch + decode every share the owner has sent.
 *
 * `recipientPublicKey` is hex-encoded on the wire (0x04...); decoded to
 * `Uint8Array` here for the ECIES re-wrap inside the SDK driver.
 *
 * `isRevoked` is always `false`: this project's shares table uses hard-delete
 * revocation (D-11 forward-only revocation, project convention -- revoke =
 * DELETE, never a soft `revoked_at` flag), so a revoked grant row is removed
 * from the table entirely and never appears in `GET /shares/sent`. Every row
 * returned here is therefore an active (non-revoked) grant.
 */
async function decodeSentGrants(): Promise<DecodedSentGrant[]> {
  const decoded: DecodedSentGrant[] = [];
  // Paginate through ALL sent shares (the API caps limit at 100 per page) --
  // a first-page-only read would leave grants beyond page 1 unreconciled.
  const pageSize = 100;
  let offset = 0;
  for (;;) {
    const { shares, total } = await sharesControllerGetSentShares({ limit: pageSize, offset });
    for (const share of shares) {
      try {
        // Wire format is bare hex, but normalize a 0x prefix defensively --
        // hexToBytes would otherwise choke and one bad row must not abort the
        // whole reconcile sweep.
        const bareHex = share.recipientPublicKey.startsWith('0x')
          ? share.recipientPublicKey.slice(2)
          : share.recipientPublicKey;
        decoded.push({
          shareId: share.shareId,
          recipientPublicKey: hexToBytes(bareHex),
          isRevoked: false,
          rootNodeId: share.rootNodeId,
          shareRootIpnsName: share.shareRootIpnsName,
        });
      } catch (error) {
        logger.error(
          `[owner-reconcile] Skipping sent grant ${share.shareId}: recipientPublicKey decode failed:`,
          safeError(error)
        );
      }
    }
    offset += shares.length;
    if (offset >= total || shares.length === 0) break;
  }
  return decoded;
}

async function listSentGrants(): Promise<GrantRow[]> {
  const decoded = await decodeSentGrants();
  return decoded.map(({ shareId, recipientPublicKey, isRevoked, rootNodeId }) => ({
    shareId,
    recipientPublicKey,
    isRevoked,
    rootNodeId,
  }));
}

async function updateGrant(
  shareId: string,
  encryptedReadKey: string,
  generation: number
): Promise<void> {
  await sharesControllerUpdateGrant(shareId, {
    encryptedReadKey,
    rootGeneration: String(generation),
  });
}

async function deleteGrant(shareId: string): Promise<void> {
  await sharesControllerRevokeShare(shareId);
}

const webOwnerReconcileTransport: OwnerReconcileTransport = {
  listSentGrants,
  updateGrant,
  deleteGrant,
};

/**
 * Reduce a caught error to name+message before logging: raw Axios/SDK errors
 * carry request config (auth headers) and crypto-path details that must not
 * reach the log sink.
 */
function safeError(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

function buildReconcileCtx(): SdkContext {
  return {
    apiUrl,
    getAccessToken: async () => useAuthStore.getState().accessToken || '',
    axiosInstance: apiAxios,
  };
}

function makeReconcileJob(rootNodeId: string): RotationJobRecord {
  return {
    rootNodeId,
    status: 'in-progress',
    completedNodeIds: new Set(),
    frontier: [],
  };
}

/**
 * Eager owner-reconcile sweep (D-11): run once per login/app-open.
 *
 * For every distinct `rootNodeId` among the owner's sent grants, look up the
 * node's CURRENT `folderKey`/`nodeGeneration` from the SDK's in-memory
 * `FolderTree` (populated as folders are loaded) and drive the SDK
 * owner-reconcile driver so any grant left dangling by a write-recipient's
 * independent unlink+bin (while this session was offline) gets re-minted or
 * deleted.
 *
 * Best-effort: a root whose folder is not currently loaded in the
 * `FolderTree` is skipped -- there is no in-memory readKey to re-mint with
 * for it yet. The opportunistic post-mutation trigger (68-08) covers the
 * live case where a fresh readKey is available immediately after the
 * owner's own rotation. Fire-and-forget; errors are captured and logged,
 * never thrown to the caller (must not block the login return path).
 */
export async function triggerOwnerReconcileOnLogin(): Promise<void> {
  if (!hasSdkClient()) return;

  let decoded: DecodedSentGrant[];
  try {
    decoded = await decodeSentGrants();
  } catch (error) {
    logger.error(
      '[owner-reconcile] Failed to fetch sent grants for eager login sweep:',
      safeError(error)
    );
    return;
  }

  // The client can be torn down (logout) while the fetch above was in flight.
  if (!hasSdkClient()) return;

  const distinctRoots = new Map<string, string>(); // rootNodeId -> shareRootIpnsName
  for (const grant of decoded) {
    if (!distinctRoots.has(grant.rootNodeId)) {
      distinctRoots.set(grant.rootNodeId, grant.shareRootIpnsName);
    }
  }

  const client = getSdkClient();
  const folderTree = client.getFolderTree();

  for (const [rootNodeId, shareRootIpnsName] of distinctRoots) {
    const folderState = folderTree.get(shareRootIpnsName);
    if (!folderState) {
      // Not loaded in-memory yet -- best-effort skip (see doc comment above).
      continue;
    }
    try {
      await runOwnerReconcile(
        rootNodeId,
        folderState.folderKey,
        folderState.nodeGeneration,
        makeReconcileJob(rootNodeId),
        buildReconcileCtx(),
        webOwnerReconcileTransport
      );
    } catch (error) {
      logger.error(
        `[owner-reconcile] Eager login reconcile failed for root ${rootNodeId}:`,
        safeError(error)
      );
    }
  }
}

/**
 * Opportunistic post-mutation owner-reconcile trigger (D-11), scoped to a
 * SINGLE root -- the folder the client just mutated -- rather than the full
 * login sweep above. Wired from `useAuth.ts` after the client's
 * `folder:updated` event so a re-mint/delete of any sent grant rooted at
 * this folder happens immediately after the owner's own scope-exit
 * rotation, without waiting for the next login sweep.
 *
 * Sourced the same way as the eager login sweep: the CURRENT
 * `folderKey`/`nodeGeneration` from the SDK's in-memory `FolderTree`.
 * Best-effort: skipped when `shareRootIpnsName` is not a known sent-grant root,
 * or when the folder isn't currently loaded in-memory. Fire-and-forget;
 * errors are captured and logged, never thrown to the caller.
 */
export async function runOwnerReconcileForFolder(shareRootIpnsName: string): Promise<void> {
  if (!hasSdkClient()) return;

  let decoded: DecodedSentGrant[];
  try {
    decoded = await decodeSentGrants();
  } catch (error) {
    logger.error(
      `[owner-reconcile] Failed to fetch sent grants for opportunistic reconcile of ${shareRootIpnsName}:`,
      safeError(error)
    );
    return;
  }

  // The client can be torn down (logout) while the fetch above was in flight.
  if (!hasSdkClient()) return;

  const grant = decoded.find((candidate) => candidate.shareRootIpnsName === shareRootIpnsName);
  if (!grant) return; // not a grant root -- nothing to reconcile

  const client = getSdkClient();
  const folderState = client.getFolderTree().get(shareRootIpnsName);
  if (!folderState) return; // best-effort skip, same as the eager login sweep

  try {
    await runOwnerReconcile(
      grant.rootNodeId,
      folderState.folderKey,
      folderState.nodeGeneration,
      makeReconcileJob(grant.rootNodeId),
      buildReconcileCtx(),
      webOwnerReconcileTransport
    );
  } catch (error) {
    logger.error(
      `[owner-reconcile] Opportunistic reconcile failed for root ${grant.rootNodeId}:`,
      safeError(error)
    );
  }
}
