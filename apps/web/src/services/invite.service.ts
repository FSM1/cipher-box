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
  invitesControllerGetInviteData,
  invitesControllerClaimInvite,
  shareInvitesControllerCreateInvite,
  shareInvitesControllerListInvites,
  shareInvitesControllerRevokeInvite,
} from '@cipherbox/api-client';
import { getPublicKey, utils as secp256k1Utils } from '@noble/secp256k1';
import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { resolveChildNodeIdentity } from '../lib/crypto/key-wrapping';
import { getSdkClient } from '../lib/sdk-provider';
import { useAuthStore } from '../stores/auth.store';
import { useVaultStore } from '../stores/vault.store';
import { logger } from '../lib/logger';

// ---------------------------------------------------------------------------
// Parent IPNS name resolution (68.1-18)
// ---------------------------------------------------------------------------

/**
 * Resolve the client-side `'root'` folder-navigation sentinel to the real root
 * IPNS name the SDK client's `FolderTree` is keyed by.
 *
 * `parentFolderId` (as threaded through `ShareDialog`/`InviteLinkTab`) is
 * `useFolderNavigation`'s `currentFolderId`, which uses the literal string
 * `'root'` for the vault root instead of a real IPNS name --
 * `resolveShareEncryptedWriteKey`'s `parentIpnsName` argument must be a real
 * IPNS name the SDK client can `requireFolder()` against (68.1-11's
 * documented write-key gap; SHARE-WRITE-KEY foundation).
 */
export function resolveParentIpnsName(parentFolderId: string): string {
  if (parentFolderId !== 'root') return parentFolderId;
  const rootIpnsName = useVaultStore.getState().rootIpnsName;
  if (!rootIpnsName) {
    throw new Error('resolveParentIpnsName: root IPNS name not available (vault not loaded)');
  }
  return rootIpnsName;
}

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

/**
 * Generate a fresh ephemeral secp256k1 keypair for the invite bridge.
 *
 * The private key lives ONLY in memory + the URL fragment (never sent to the
 * server, never persisted) -- it is the one-time bridge the sharer uses to
 * wrap the item key, and the sole decryption key for the recipient's claim.
 */
function generateEphemeralKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = secp256k1Utils.randomSecretKey();
  const publicKey = getPublicKey(privateKey, false); // uncompressed, 65 bytes (0x04...)
  return { privateKey, publicKey };
}

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
 * Mints an ephemeral secp256k1 keypair, wraps the item's own readKey (derived
 * from `item`'s read-chain hop via `resolveChildNodeIdentity`) and display
 * name for the ephemeral public key, creates the invite row on the server,
 * and builds the URL with the ephemeral PRIVATE key in the fragment (never
 * sent to the server).
 *
 * When `params.permission === 'write'`, additionally resolves the item's own
 * writeKey from the owned write-chain (`resolveShareEncryptedWriteKey`, 68.1-18)
 * and ECIES-wraps it for the SAME ephemeral public key used for the readKey --
 * the recipient claims both from one ephemeral bridge. No caller currently
 * requests `permission: 'write'` (the invite UI has no read/write toggle yet,
 * 68.1-11's documented gap) -- this is the owner-side SDK/service wiring only;
 * recipient-side write-claim + UI toggle are out of this plan's scope (68.1-19).
 *
 * @security The ephemeral private key and the item's readKey are zeroed in
 *   `finally` on every exit path (T-68.1-11-01/03). `resolveShareEncryptedWriteKey`
 *   zeroes the derived item writeKey internally before returning (D-09) --
 *   raw writeKey material never reaches this function.
 */
export async function createInviteLink(params: {
  item: SealedChildRef;
  folderKey: Uint8Array;
  ipnsName: string;
  parentFolderId: string;
  permission?: 'read' | 'write';
}): Promise<{ url: string; token: string }> {
  let ephemeralPrivateKey: Uint8Array | null = null;
  let itemReadKey: Uint8Array | null = null;

  try {
    const ephemeral = generateEphemeralKeypair();
    ephemeralPrivateKey = ephemeral.privateKey;

    const identity = await resolveChildNodeIdentity(params.item, params.folderKey);
    itemReadKey = identity.readKey;

    const encryptedReadKey = bytesToHex(await wrapKey(itemReadKey, ephemeral.publicKey));

    let encryptedWriteKey: string | undefined;
    if (params.permission === 'write') {
      const parentIpnsName = resolveParentIpnsName(params.parentFolderId);
      encryptedWriteKey = await getSdkClient().resolveShareEncryptedWriteKey(
        parentIpnsName,
        params.item.ipnsName,
        ephemeral.publicKey
      );
    }

    let itemNameEncrypted: string | undefined;
    let nameBytes: Uint8Array | null = null;
    try {
      nameBytes = new TextEncoder().encode(params.item.name);
      itemNameEncrypted = bytesToHex(await wrapKey(nameBytes, ephemeral.publicKey));
    } catch (err) {
      logger.warn('[Invite] Failed to wrap item name, continuing without it:', err);
    } finally {
      // Clear the cleartext name buffer on every path (mirrors claimInvite).
      nameBytes?.fill(0);
    }

    const invite = await shareInvitesControllerCreateInvite({
      shareRootIpnsName: params.item.ipnsName,
      rootNodeId: identity.nodeId,
      rootGeneration: String(identity.generation),
      encryptedReadKey,
      encryptedWriteKey,
      itemNameEncrypted,
    });

    const url = buildInviteUrl(invite.token, bytesToHex(ephemeralPrivateKey));
    return { url, token: invite.token };
  } finally {
    ephemeralPrivateKey?.fill(0);
    itemReadKey?.fill(0);
  }
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
  token: string,
  ephemeralPrivKeyHex: string
): Promise<{ shareId: string }> {
  const vaultKeypair = useAuthStore.getState().vaultKeypair;
  if (!vaultKeypair) {
    throw new Error('claimInvite: not authenticated (no vault keypair)');
  }

  let ephemeralPrivateKey: Uint8Array | null = null;
  let rootReadKey: Uint8Array | null = null;

  try {
    ephemeralPrivateKey = hexToBytes(ephemeralPrivKeyHex);

    const inviteData = await invitesControllerGetInviteData(token);

    rootReadKey = await unwrapKey(hexToBytes(inviteData.encryptedReadKey), ephemeralPrivateKey);
    const encryptedReadKey = bytesToHex(await wrapKey(rootReadKey, vaultKeypair.publicKey));

    let itemNameEncrypted: string | undefined;
    if (inviteData.itemNameEncrypted) {
      let nameBytes: Uint8Array | null = null;
      try {
        nameBytes = await unwrapKey(hexToBytes(inviteData.itemNameEncrypted), ephemeralPrivateKey);
        itemNameEncrypted = bytesToHex(await wrapKey(nameBytes, vaultKeypair.publicKey));
      } catch (err) {
        logger.warn(
          '[Invite] Failed to re-wrap item name during claim, continuing without it:',
          err
        );
      } finally {
        nameBytes?.fill(0);
      }
    }

    const result = await invitesControllerClaimInvite(token, {
      encryptedReadKey,
      itemNameEncrypted,
    });

    return { shareId: result.shareId };
  } finally {
    ephemeralPrivateKey?.fill(0);
    rootReadKey?.fill(0);
  }
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
export async function fetchInvitesForItem(ipnsName: string): Promise<InviteInfo[]> {
  const invites = await shareInvitesControllerListInvites({ shareRootIpnsName: ipnsName });
  return invites.map((invite) => ({
    id: invite.id,
    token: invite.token,
    status: invite.status,
    // TODO(phase 63): SealedChildRef has no .type; itemType has no source at the invite layer.
    itemType: 'folder',
    ipnsName: invite.shareRootIpnsName,
    // itemNameEncrypted (if present) is wrapped for the EPHEMERAL public key, which the
    // sharer never retains after creation (T-68.1-11-01) -- there is no plaintext name
    // the sharer can recover for their own invite list.
    itemName: '',
    expiresAt: invite.expiresAt,
    createdAt: invite.createdAt,
  }));
}

/**
 * Revoke an active invite link.
 * Only the original sharer can revoke. Already-claimed shares persist.
 */
export async function revokeInvite(inviteId: string): Promise<void> {
  await shareInvitesControllerRevokeInvite(inviteId);
}
