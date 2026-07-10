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
  sharesControllerGetReceivedShares,
  sharesControllerGetSentShares,
  type ShareKeyEntryDtoKeyType,
  type ReceivedShareResponseDto,
  type SentShareResponseDto,
} from '@cipherbox/api-client';

import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import type { ReceivedShare, SentShare } from '../stores/share.store';
import { useShareStore } from '../stores/share.store';

// ---------------------------------------------------------------------------
// REQ-4 — share itemName ECIES at-rest (Phase-14 M1 closure; GAP-6 backfill
// removal, 68.1-24)
//
// itemName is wrapped with the RECIPIENT's secp256k1 public key (the same key
// already used for encryptedKey) before leaving the browser. Recipients decrypt
// itemNameEncrypted with their vault private key for display. There is no
// plaintext item_name column server-side (dropped in the Phase 66 schema
// cutover) — the lazy plaintext-backfill path (shouldBackfill /
// backfillSentShareItemNames / PATCH /shares/:id/item-name) was permanently
// unreachable dead code and has been removed. The owner-side sent-share
// display uses the create-time plaintext projection held in the share store
// (ShareDialog seeds it) since the owner cannot decrypt a ciphertext wrapped
// for the recipient's key.
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
 * Parse a grant's `rootGeneration` (numeric string from the DTO) into a number.
 *
 * Fail-closed (V5, T-68-21): a non-numeric or absent value is treated as
 * absent (`undefined`), never coerced to `NaN`/`0` — the durable rotation
 * floor downstream must never seed from a forged/garbled low generation.
 */
export function parseRootGeneration(value: string | undefined | null): number | undefined {
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
    ipnsName: dto.shareRootIpnsName,
    itemName: '',
    itemNameEncrypted: dto.itemNameEncrypted,
    permission: dto.encryptedWriteKey != null ? 'write' : 'read',
    createdAt: dto.createdAt,
    encryptedReadKey: dto.encryptedReadKey,
    encryptedWriteKey: dto.encryptedWriteKey,
    rootGeneration: parseRootGeneration(dto.rootGeneration),
    rootNodeId: dto.rootNodeId,
  };
}

/** Reshape a sent-share grant DTO row into the web store's SentShare shape. */
export function toSentShare(dto: SentShareResponseDto): SentShare {
  return {
    shareId: dto.shareId,
    recipientPublicKey: dto.recipientPublicKey,
    ipnsName: dto.shareRootIpnsName,
    itemName: '',
    itemNameEncrypted: dto.itemNameEncrypted,
    permission: dto.encryptedWriteKey != null ? 'write' : 'read',
    createdAt: dto.createdAt,
    encryptedReadKey: dto.encryptedReadKey,
    rootGeneration: parseRootGeneration(dto.rootGeneration),
    rootNodeId: dto.rootNodeId,
  };
}

/**
 * Fetch active, non-hidden shares received by the current user (paginated).
 *
 * Real grant rows (encryptedReadKey/rootGeneration/rootNodeId) — the data
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
 * Real grant rows (encryptedReadKey/rootGeneration/rootNodeId) — the data
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
 * Check if a CipherBox user exists with the given secp256k1 public key.
 *
 * @param publicKeyHex - Uncompressed secp256k1 public key (0x04... format)
 */
export async function lookupUser(publicKeyHex: string): Promise<boolean> {
  const result = await sharesControllerLookupUser({ publicKey: publicKeyHex });
  return result.exists;
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
 * under the encrypted-key grant model — `sharesControllerGetShareKeys` does
 * not exist server-side. A grant carries exactly one wrapped
 * `encryptedReadKey` (and optionally `encryptedWriteKey`) for the shared
 * item's OWN root; every descendant key is recovered on demand via the
 * read/write-chain walk (`navigateReadChain`, `resolveShareEncryptedWriteKey`),
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
export async function fetchAllSentShares(): Promise<SentShare[]> {
  const pageSize = 100;
  let offset = 0;
  const allShares: SentShare[] = [];

  while (true) {
    const { shares, total } = await fetchSentShares(pageSize, offset);
    allShares.push(...shares);
    offset += shares.length;
    if (offset >= total || shares.length === 0) break;
  }

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
