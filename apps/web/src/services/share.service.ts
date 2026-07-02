// DEPRECATED: Use @cipherbox/sdk instead. Will be removed in 19.1-06.
// Hooks now delegate to CipherBoxClient SDK methods for share operations.
/**
 * Share Service - API integration for user-to-user sharing
 *
 * Wraps the generated Orval API client for share endpoints.
 * All sharing operations flow through these functions.
 *
 * Security: The server never sees plaintext keys. All keys are
 * ECIES-wrapped for the recipient before being sent to the API.
 */

import {
  sharesControllerLookupUser,
  sharesControllerRevokeShare,
  sharesControllerHideShare,
  sharesControllerUpdateShareItemName,
  sharesControllerGetReceivedShares,
  sharesControllerGetSentShares,
  type ShareKeyEntryDtoKeyType,
  type ReceivedShareResponseDto,
  type SentShareResponseDto,
} from '@cipherbox/api-client';

import { wrapKey, unwrapKey, bytesToHex, hexToBytes } from '@cipherbox/crypto';
import type { ReceivedShare, SentShare } from '../stores/share.store';
import { useShareStore } from '../stores/share.store';
import { useAuthStore } from '../stores/auth.store';
import { logger } from '../lib/logger';

// ---------------------------------------------------------------------------
// REQ-4 — share itemName ECIES at-rest (Phase-14 M1 closure)
//
// itemName is wrapped with the RECIPIENT's secp256k1 public key (the same key
// already used for encryptedKey) before leaving the browser. Recipients decrypt
// itemNameEncrypted with their vault private key for display; the owner's
// sent-share list keeps the plaintext projection it had at create time and
// falls back to any legacy plaintext itemName when ciphertext is present but
// not decryptable (the name was wrapped for the recipient, not the owner).
//
// Security: never log itemName or itemNameEncrypted; zero transient unwrapped
// bytes after use (CLAUDE.md rule 9).
// ---------------------------------------------------------------------------

/** Minimal projection of a share/invite row carrying the itemName fields. */
export type ItemNameBearingRow = {
  itemName: string;
  itemNameEncrypted?: string | null;
};

/**
 * Decrypt a share/invite display name for rendering.
 *
 * When `itemNameEncrypted` (hex ECIES ciphertext) is present, unwrap it with the
 * vault private key and return the UTF-8 name. When absent (legacy plaintext
 * row), fall back to the plaintext `itemName`.
 *
 * @param row - Row carrying itemName + optional itemNameEncrypted (hex)
 * @param vaultPrivateKey - The viewer's secp256k1 vault private key
 */
export async function decryptItemName(
  row: ItemNameBearingRow,
  vaultPrivateKey: Uint8Array
): Promise<string> {
  if (!row.itemNameEncrypted) {
    return row.itemName;
  }

  const unwrapped = await unwrapKey(hexToBytes(row.itemNameEncrypted), vaultPrivateKey);
  try {
    return new TextDecoder().decode(unwrapped);
  } finally {
    unwrapped.fill(0);
  }
}

/**
 * Lazy-backfill decision predicate (decision A2).
 *
 * Returns true only when a key-holding client (one that holds the recipient
 * pubkey to re-wrap with) sees a legacy plaintext-only row: plaintext present,
 * ciphertext absent. Idempotent — returns false once ciphertext exists, so a
 * backfilled row is never re-backfilled.
 *
 * @param row - Row carrying itemName + optional itemNameEncrypted
 * @param hasRecipientPubKey - Whether the caller holds the recipient pubkey
 */
export function shouldBackfill(row: ItemNameBearingRow, hasRecipientPubKey: boolean): boolean {
  if (!hasRecipientPubKey) return false;
  if (row.itemNameEncrypted) return false;
  return Boolean(row.itemName);
}

/**
 * Parse a grant's `rootGeneration` (numeric string from the DTO) into a number.
 *
 * Fail-closed (V5, T-68-21): a non-numeric or absent value is treated as
 * absent (`undefined`), never coerced to `NaN`/`0` — the durable rotation
 * floor downstream must never seed from a forged/garbled low generation.
 */
function parseRootGeneration(value: string | undefined | null): number | undefined {
  // Strict digits-only: Number('') / Number(' ') coerce to 0, and negative or
  // fractional strings pass isFinite — all of which would seed a forged floor.
  if (value === undefined || value === null || !/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

/** Reshape a received-share grant DTO row into the web store's ReceivedShare shape. */
function toReceivedShare(dto: ReceivedShareResponseDto): ReceivedShare {
  return {
    shareId: dto.shareId,
    sharerPublicKey: dto.sharerPublicKey,
    ipnsName: dto.rootIpnsName,
    itemName: '',
    itemNameEncrypted: dto.itemNameEncrypted,
    permission: dto.writeDescriptorRef !== null ? 'write' : 'read',
    createdAt: dto.createdAt,
    readDescriptorRef: dto.readDescriptorRef,
    rootGeneration: parseRootGeneration(dto.rootGeneration),
    rootNodeId: dto.rootNodeId,
  };
}

/** Reshape a sent-share grant DTO row into the web store's SentShare shape. */
function toSentShare(dto: SentShareResponseDto): SentShare {
  return {
    shareId: dto.shareId,
    recipientPublicKey: dto.recipientPublicKey,
    ipnsName: dto.rootIpnsName,
    itemName: '',
    itemNameEncrypted: dto.itemNameEncrypted,
    permission: dto.writeDescriptorRef !== null ? 'write' : 'read',
    createdAt: dto.createdAt,
    readDescriptorRef: dto.readDescriptorRef,
    rootGeneration: parseRootGeneration(dto.rootGeneration),
    rootNodeId: dto.rootNodeId,
  };
}

/**
 * Fetch active, non-hidden shares received by the current user (paginated).
 *
 * Real grant rows (readDescriptorRef/rootGeneration/rootNodeId) — the data
 * path D-07 seeds the durable rotation-floor from (ROT-07).
 */
export async function fetchReceivedShares(
  limit = 50,
  offset = 0
): Promise<{ shares: ReceivedShare[]; total: number }> {
  const result = await sharesControllerGetReceivedShares({ limit, offset });
  return { shares: result.shares.map(toReceivedShare), total: result.total };
}

/**
 * Fetch active shares sent by the current user (paginated).
 *
 * Real grant rows (readDescriptorRef/rootGeneration/rootNodeId) — the data
 * path D-07 seeds the durable rotation-floor from (ROT-07).
 */
export async function fetchSentShares(
  limit = 50,
  offset = 0
): Promise<{ shares: SentShare[]; total: number }> {
  const result = await sharesControllerGetSentShares({ limit, offset });
  return { shares: result.shares.map(toSentShare), total: result.total };
}

/**
 * Lazy backfill of itemNameEncrypted for legacy plaintext sent shares (decision A2).
 *
 * The owner holds the recipient pubkey on each sent-share row, so it can re-wrap
 * the plaintext display name for the recipient and re-persist the ciphertext.
 * Best-effort and idempotent: rows already carrying ciphertext are skipped via
 * shouldBackfill, so a backfilled row is never re-wrapped. Failures are logged
 * (never throwing) so the share-list load is never blocked.
 *
 * Persists via `PATCH /shares/:id/item-name`, which only the sharer may call
 * and which stores the client-supplied ciphertext as-is (server never encrypts).
 *
 * @returns Count of rows successfully backfilled (re-wrapped and persisted).
 */
export async function backfillSentShareItemNames(shares: SentShare[]): Promise<number> {
  const vaultKeypair = useAuthStore.getState().vaultKeypair;
  if (!vaultKeypair) return 0;

  let backfilled = 0;

  for (const share of shares) {
    // Owner always holds the recipient pubkey on the row → key-holder = true.
    if (!shouldBackfill(share, true)) continue;

    try {
      const recipientPubKey = hexToBytes(
        share.recipientPublicKey.startsWith('0x')
          ? share.recipientPublicKey.slice(2)
          : share.recipientPublicKey
      );
      const plaintextNameBytes = new TextEncoder().encode(share.itemName);
      let wrapped: Uint8Array | null = null;
      try {
        wrapped = await wrapKey(plaintextNameBytes, recipientPubKey);
        const itemNameEncrypted = bytesToHex(wrapped);

        // Persist the re-wrapped ciphertext for this legacy row. Only the sharer
        // may update it; the server stores the ciphertext as-is.
        await sharesControllerUpdateShareItemName(share.shareId, { itemNameEncrypted });
        backfilled += 1;
      } finally {
        // Clear the transient plaintext display name from memory after wrapping.
        plaintextNameBytes.fill(0);
        wrapped?.fill(0);
      }
    } catch (err) {
      // Never log the plaintext/ciphertext name; only the failure marker.
      logger.warn('[share] itemName backfill re-wrap failed for share', share.shareId, err);
    }
  }

  return backfilled;
}

/**
 * Check if a CipherBox user exists with the given secp256k1 public key.
 *
 * @param publicKeyHex - Uncompressed secp256k1 public key (0x04... format)
 */
export async function lookupUser(publicKeyHex: string): Promise<boolean> {
  const result = await sharesControllerLookupUser({ publicKey: publicKeyHex });
  return result.exists;
}

/**
 * DEPRECATED no-op (68.1-20): the descriptor-ref grant model (`POST /shares`
 * with `readDescriptorRef`/`writeDescriptorRef`) superseded this pre-node/v3
 * shape entirely — no caller remains anywhere in the app (real share creation
 * goes through `sharesControllerCreateShare` directly, see `ShareDialog.tsx`).
 * Fails closed as a no-op rather than throwing so any stray/future import does
 * not crash a live user flow; the descriptor-ref path never routes through here.
 *
 * Retained only until a follow-up plan deletes this file's dead pre-node/v3
 * surface entirely.
 */
export async function updateSharePermission(
  _shareId: string,
  _permission: 'read' | 'write',
  _encryptedIpnsKey?: string
): Promise<void> {
  // No-op (fail-closed, not throwing). `ShareDialog.handleUpgrade`/
  // `handleDowngradeConfirm` are being migrated to `sharesControllerUpdateGrant`
  // (PATCH /shares/:id/grant, see 68.1-19) — there is no
  // `PATCH /shares/:id/permission`-style endpoint this function could route to.
}

/**
 * Revoke a share (soft-delete). Only the sharer can revoke.
 * Keys are kept for lazy rotation.
 */
export async function revokeShare(shareId: string): Promise<void> {
  await sharesControllerRevokeShare(shareId);
}

/**
 * Hide a share from the recipient's view. Only the recipient can hide.
 */
export async function hideShare(shareId: string): Promise<void> {
  await sharesControllerHideShare(shareId);
}

/**
 * Fail-closed (68.1-20): there is NO per-child `share_keys` fan-out endpoint
 * under the descriptor-ref grant model — `sharesControllerGetShareKeys` does
 * not exist server-side. A grant carries exactly one wrapped
 * `readDescriptorRef` (and optionally `writeDescriptorRef`) for the shared
 * item's OWN root; every descendant key is recovered on demand via the
 * read/write-chain walk (`navigateReadChain`, `resolveShareWriteDescriptor`),
 * never via a pre-fetched per-child key list.
 *
 * Always returns an empty array so every caller's existing empty-array/null
 * fallback path is exercised (never throws) — see `useSharedNavigation.ts`,
 * `useSharedWriteOps.ts`, `SharedMoveDialog.tsx`, `TextEditorDialog.tsx`.
 */
export async function fetchShareKeys(_shareId: string): Promise<
  Array<{
    keyType: ShareKeyEntryDtoKeyType;
    itemId: string;
    encryptedKey: string;
  }>
> {
  return [];
}

// ---------------------------------------------------------------------------
// Post-upload / post-create share key propagation
// ---------------------------------------------------------------------------

/**
 * Ensure sent shares cache is fresh (fetched within last 30s).
 * Returns the current sent shares array.
 */
async function ensureFreshSentShares(): Promise<SentShare[]> {
  const store = useShareStore.getState();
  if (store.lastSentFetchedAt && Date.now() - store.lastSentFetchedAt < 30_000) {
    return store.sentShares;
  }
  // Re-wrapping needs the full set — paginate through all pages
  const allShares = await fetchAllSentShares();
  useShareStore.getState().setSentShares(allShares);
  return allShares;
}

/**
 * Fetch ALL sent shares by paginating through the API.
 * The API enforces a max limit of 100 per page.
 */
async function fetchAllSentShares(): Promise<SentShare[]> {
  const pageSize = 100;
  let offset = 0;
  const allShares: SentShare[] = [];

  while (true) {
    const { shares, total } = await fetchSentShares(pageSize, offset);
    allShares.push(...shares);
    offset += shares.length;
    if (offset >= total || shares.length === 0) break;
  }

  // Lazy backfill (decision A2): re-wrap and persist itemNameEncrypted for any
  // legacy plaintext rows. Best-effort and idempotent (shouldBackfill skips rows
  // already carrying ciphertext), fire-and-forget so the list load never blocks.
  void backfillSentShareItemNames(allShares).catch((err) =>
    logger.warn('[share] itemName backfill pass failed', err)
  );

  return allShares;
}

/**
 * Check if a folder (by IPNS name) has any active shares.
 * Used to decide whether post-upload re-wrapping is needed.
 */
export async function hasActiveShares(folderIpnsName: string): Promise<boolean> {
  const shares = await ensureFreshSentShares();
  return shares.some((s) => s.ipnsName === folderIpnsName);
}

// ---------------------------------------------------------------------------
// Lazy key rotation after revocation
// ---------------------------------------------------------------------------

/** A revoked share pending key rotation. */
export type PendingRotation = {
  shareId: string;
  recipientPublicKey: string;
  itemType: 'folder' | 'file';
  ipnsName: string;
  itemName: string;
  revokedAt: string;
};

/**
 * Fail-closed (68.1-20): no live `GET /shares/pending-rotations`-style
 * endpoint exists (`sharesControllerRevokeShare` hard-deletes; there is no
 * server-side lazy-rotation-pending list under the descriptor-ref grant
 * model). Always returns an empty array so `checkPendingRotation` reports
 * `false` (non-throwing) rather than blocking any caller.
 */
export async function fetchPendingRotations(): Promise<PendingRotation[]> {
  return [];
}

/**
 * Check if a folder has pending rotations (revoked shares awaiting key rotation).
 * Called before any folder modification.
 *
 * @param folderIpnsName - IPNS name of the folder being modified
 * @returns true if there are revoked shares for this folder that need rotation
 */
export async function checkPendingRotation(folderIpnsName: string): Promise<boolean> {
  const pendingRotations = await fetchPendingRotations();
  return pendingRotations.some((r) => r.ipnsName === folderIpnsName);
}
