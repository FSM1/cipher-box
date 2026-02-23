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

import * as secp256k1 from '@noble/secp256k1';
import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/crypto';
import { useAuthStore } from '../stores/auth.store';
import {
  invitesControllerGetInviteStatus,
  invitesControllerGetInviteData,
  invitesControllerClaimInvite,
} from '../api/invites/invites';
import {
  shareInvitesControllerCreateInvite,
  shareInvitesControllerListInvites,
  shareInvitesControllerRevokeInvite,
} from '../api/share-invites/share-invites';
import { collectChildKeys } from '../lib/crypto/key-wrapping';
import { resolveFileMetadata } from './file-metadata.service';
import { resolveIpnsRecord } from './ipns.service';
import { fetchFromIpfs } from '../lib/api/ipfs';
import { decryptFolderMetadata } from '@cipherbox/crypto';

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
 * Generate an ephemeral secp256k1 keypair for invite link creation.
 * The private key goes in the URL fragment (never sent to server).
 * The public key wraps the item key (stored on server as ciphertext).
 */
function generateEphemeralKeypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privateKeyHex: string;
} {
  const keypair = secp256k1.keygen();
  return {
    privateKey: keypair.secretKey,
    publicKey: secp256k1.getPublicKey(keypair.secretKey, false), // uncompressed 65-byte key for ECIES
    privateKeyHex: bytesToHex(keypair.secretKey),
  };
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
 * 1. Generates ephemeral secp256k1 keypair
 * 2. Wraps item key with ephemeral public key
 * 3. Collects and wraps child keys (for folders)
 * 4. Creates invite record on server
 * 5. Builds URL with ephemeral private key in fragment
 * 6. Zeros ephemeral private key from memory
 *
 * @returns The invite URL and token
 */
export async function createInviteLink(params: {
  item: FolderChild;
  folderKey: Uint8Array;
  ipnsName: string;
  parentFolderId: string;
}): Promise<{ url: string; token: string }> {
  const { item, folderKey, ipnsName } = params;
  const ephemeralKeypair = generateEphemeralKeypair();

  try {
    const vaultKeypair = useAuthStore.getState().vaultKeypair;
    if (!vaultKeypair) {
      throw new Error('Vault keypair not available');
    }

    const ownerPrivateKey = vaultKeypair.privateKey;
    let encryptedKey: string;
    let encryptedChildKeys:
      | Array<{ keyType: 'file' | 'folder'; itemId: string; encryptedKey: string }>
      | undefined;

    if (item.type === 'folder') {
      const folderEntry = item as FolderEntry;

      // Unwrap the folder's own key from its ECIES-encrypted form
      const itemFolderKey = await unwrapKey(
        hexToBytes(folderEntry.folderKeyEncrypted),
        ownerPrivateKey
      );

      try {
        // Wrap the folder key with ephemeral public key
        const wrappedForEphemeral = await wrapKey(itemFolderKey, ephemeralKeypair.publicKey);
        encryptedKey = bytesToHex(wrappedForEphemeral);

        // Resolve folder metadata and collect child keys
        const resolved = await resolveIpnsRecord(folderEntry.ipnsName);
        if (resolved) {
          const encryptedBytes = await fetchFromIpfs(resolved.cid);
          const encryptedJson = new TextDecoder().decode(encryptedBytes);
          const encrypted = JSON.parse(encryptedJson);
          const metadata = await decryptFolderMetadata(encrypted, itemFolderKey);

          encryptedChildKeys = await collectChildKeys(
            metadata.children,
            itemFolderKey,
            ownerPrivateKey,
            ephemeralKeypair.publicKey,
            () => {} // No progress UI for invite creation
          );
        }
      } finally {
        itemFolderKey.fill(0);
      }
    } else {
      // File sharing: wrap parent folder key with ephemeral key
      // (recipient needs parent folder key to decrypt file metadata)
      const filePointer = item as FilePointer;

      const wrappedFolderKey = await wrapKey(folderKey, ephemeralKeypair.publicKey);
      encryptedKey = bytesToHex(wrappedFolderKey);

      // Resolve file metadata and wrap the file key as a child key
      const { metadata: fileMeta } = await resolveFileMetadata(
        filePointer.fileMetaIpnsName,
        folderKey
      );
      const fileKeyPlain = await unwrapKey(hexToBytes(fileMeta.fileKeyEncrypted), ownerPrivateKey);
      try {
        const wrappedFileKey = await wrapKey(fileKeyPlain, ephemeralKeypair.publicKey);
        encryptedChildKeys = [
          {
            keyType: 'file' as const,
            itemId: filePointer.id,
            encryptedKey: bytesToHex(wrappedFileKey),
          },
        ];
      } finally {
        fileKeyPlain.fill(0);
      }
    }

    // Create invite on server
    const result = await shareInvitesControllerCreateInvite({
      itemType: item.type === 'folder' ? 'folder' : 'file',
      ipnsName,
      itemName: item.name,
      encryptedKey,
      encryptedChildKeys,
    });

    // Build URL with ephemeral private key in hash fragment
    const url = buildInviteUrl(result.token, ephemeralKeypair.privateKeyHex);

    return { url, token: result.token };
  } finally {
    // Zero ephemeral private key from memory
    ephemeralKeypair.privateKey.fill(0);
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
  const ephemeralPrivKey = hexToBytes(ephemeralPrivKeyHex);

  try {
    // Fetch full invite data (authenticated endpoint)
    const inviteData = await invitesControllerGetInviteData(token);

    // Get recipient's own vault keypair
    const vaultKeypair = useAuthStore.getState().vaultKeypair;
    if (!vaultKeypair) {
      throw new Error('Vault keypair not available');
    }

    // Unwrap item key with ephemeral private key
    const plaintextKey = await unwrapKey(hexToBytes(inviteData.encryptedKey), ephemeralPrivKey);

    let reWrappedKey: string;
    try {
      // Re-wrap with recipient's own public key
      const wrapped = await wrapKey(plaintextKey, vaultKeypair.publicKey);
      reWrappedKey = bytesToHex(wrapped);
    } finally {
      plaintextKey.fill(0);
    }

    // Re-wrap child keys
    const childKeys: Array<{
      keyType: 'file' | 'folder';
      itemId: string;
      encryptedKey: string;
    }> = [];

    const rawChildKeys = inviteData.encryptedChildKeys;

    if (rawChildKeys && rawChildKeys.length > 0) {
      for (const ck of rawChildKeys) {
        const plainChildKey = await unwrapKey(hexToBytes(ck.encryptedKey), ephemeralPrivKey);
        try {
          const wrappedChild = await wrapKey(plainChildKey, vaultKeypair.publicKey);
          childKeys.push({
            keyType: ck.keyType,
            itemId: ck.itemId,
            encryptedKey: bytesToHex(wrappedChild),
          });
        } finally {
          plainChildKey.fill(0);
        }
      }
    }

    // POST claim with re-wrapped keys
    const result = await invitesControllerClaimInvite(token, {
      encryptedKey: reWrappedKey,
      childKeys,
    });

    return { shareId: result.shareId };
  } finally {
    // Zero ephemeral private key
    ephemeralPrivKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Invite status check
// ---------------------------------------------------------------------------

/**
 * Check the status of an invite link (public, no auth required).
 * Returns the invite status or 'expired' on error/404.
 */
export async function checkInviteStatus(
  token: string
): Promise<'active' | 'expired' | 'claimed' | 'revoked'> {
  try {
    const result = await invitesControllerGetInviteStatus(token);
    return result.status as 'active' | 'expired' | 'claimed' | 'revoked';
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
  const response = await shareInvitesControllerListInvites({ ipnsName });
  return response.map((inv) => ({
    id: inv.id,
    token: inv.token,
    status: inv.status,
    itemType: inv.itemType,
    ipnsName: inv.ipnsName,
    itemName: inv.itemName,
    expiresAt: String(inv.expiresAt),
    createdAt: String(inv.createdAt),
  }));
}

/**
 * Revoke an active invite link.
 * Only the original sharer can revoke. Already-claimed shares persist.
 */
export async function revokeInvite(inviteId: string): Promise<void> {
  await shareInvitesControllerRevokeInvite(inviteId);
}
