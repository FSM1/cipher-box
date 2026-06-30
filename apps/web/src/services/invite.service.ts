/**
 * Invite Service - Frontend invite link creation and claim with ephemeral key bridge
 *
 * Core security pattern: The sharer generates an ephemeral secp256k1 keypair,
 * wraps the item key with the ephemeral public key, and puts the ephemeral
 * PRIVATE key in the URL fragment (never sent to server). The recipient
 * unwraps with the ephemeral private key and re-wraps with their own public key.
 *
 * All ephemeral and plaintext key material is zeroed in finally blocks.
 */

import type { SealedChildRef } from '@cipherbox/core';
import {
  invitesControllerGetInviteStatus,
  shareInvitesControllerRevokeInvite,
} from '@cipherbox/api-client';
// collectChildKeys stubbed — phase 65 (write-chain key distribution)
// resolveFileMetadata stubbed — phase 63 (Node read-chain)
// resolveIpnsRecord, fetchFromIpfs, decryptFolderMetadata — retired (phase 63+)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Info about an active invite link */
export type InviteInfo = {
  id: string;
  token: string;
  status: string;
  itemType: string;
  ipnsName: string;
  itemName: string;
  expiresAt: string;
  createdAt: string;
};

// ---------------------------------------------------------------------------
// Ephemeral keypair generation
// ---------------------------------------------------------------------------

// TODO(phase 65): restore generateEphemeralKeypair when createInviteLink is implemented

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

/**
 * Build an invite URL with the ephemeral private key in the hash fragment.
 *
 * Format: `${origin}${pathname}#/invite/${token}?key=${ephemeralPrivKeyHex}`
 *
 * The entire path after # is the hash fragment -- never sent to server.
 * React Router's HashRouter parses the route, and useSearchParams()
 * provides access to the key parameter.
 */
export function buildInviteUrl(token: string, ephemeralPrivKeyHex: string): string {
  const base = window.location.origin + window.location.pathname;
  return `${base}#/invite/${token}?key=${ephemeralPrivKeyHex}`;
}

// ---------------------------------------------------------------------------
// Create invite link
// ---------------------------------------------------------------------------

/**
 * Create an invite link for a file or folder.
 *
 * 1. Generates ephemeral secp256k1 keypair
 * 2. Wraps item key with ephemeral public key
 * 3. Collects and wraps child keys (for folders)
 * 4. Creates invite record on server
 * 5. Builds URL with ephemeral private key in fragment
 * 6. Zeros ephemeral private key from memory
 *
 * @returns The invite URL and token
 */
/**
 * Create an invite link for a file or folder.
 *
 * @stub phase 65 — invite creation requires Node read-chain (to resolve NodeContent
 * for key collection) and write-chain (SealedChildRef has no folderKeyEncrypted or
 * fileMetaIpnsName — those are inside the sealed Node bodies).
 */
export async function createInviteLink(_params: {
  item: SealedChildRef;
  folderKey: Uint8Array;
  ipnsName: string;
  parentFolderId: string;
}): Promise<{ url: string; token: string }> {
  throw new Error(
    'not implemented — phase 65 (invite creation requires Node read-chain + write-chain)'
  );
}

// ---------------------------------------------------------------------------
// Claim invite
// ---------------------------------------------------------------------------

/**
 * Claim an invite link by unwrapping with ephemeral key and re-wrapping with own key.
 *
 * 1. Fetch full invite data from authenticated endpoint
 * 2. Unwrap item key with ephemeral private key
 * 3. Re-wrap with recipient's own public key
 * 4. Repeat for all child keys
 * 5. Zero all sensitive key material
 * 6. POST claim with re-wrapped keys
 *
 * @returns The share ID of the created share
 */
export async function claimInvite(
  _token: string,
  _ephemeralPrivKeyHex: string
): Promise<{ shareId: string }> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

// ---------------------------------------------------------------------------
// Invite status check
// ---------------------------------------------------------------------------

/**
 * Check the status of an invite link (public, no auth required).
 * The server returns only 'active' or 404 (to prevent token-existence
 * oracle attacks). Any non-active state maps to 'expired' on the client.
 */
export async function checkInviteStatus(token: string): Promise<'active' | 'expired'> {
  try {
    const result = await invitesControllerGetInviteStatus(token);
    return result.status === 'active' ? 'active' : 'expired';
  } catch {
    return 'expired';
  }
}

// ---------------------------------------------------------------------------
// Invite management
// ---------------------------------------------------------------------------

/**
 * Fetch all active invites for a specific item.
 * Uses the authenticated ShareInvitesController endpoint.
 */
export async function fetchInvitesForItem(_ipnsName: string): Promise<InviteInfo[]> {
  throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
}

/**
 * Revoke an active invite link.
 * Only the original sharer can revoke. Already-claimed shares persist.
 */
export async function revokeInvite(inviteId: string): Promise<void> {
  await shareInvitesControllerRevokeInvite(inviteId);
}
