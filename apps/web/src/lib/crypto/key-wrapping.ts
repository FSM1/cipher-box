/**
 * Shared key-wrapping utilities for ECIES re-wrapping operations.
 *
 * Extracted from ShareDialog to be shared between direct sharing (Phase 14)
 * and invite link sharing (Phase 15). Both flows need to traverse folder
 * metadata and re-wrap descendant keys for a target public key.
 *
 * Security: All plaintext key material is zeroed after use via .fill(0)
 * in finally blocks.
 */

import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import { decryptFolderMetadata } from '@cipherbox/core';
import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchFromIpfs } from '../api/ipfs';
import type { ChildKeyDto } from '@cipherbox/api-client';

/**
 * Collect all descendant keys from a folder for sharing.
 * Traverses subfolders depth-first, re-wrapping each file and subfolder key
 * for the target public key.
 *
 * Works for both direct share (recipientPubKey) and invite link (ephemeralPubKey)
 * since the target key is parameterized.
 *
 * @param children - Children of the current folder
 * @param folderKey - Decrypted AES key of the current folder (for resolving file metadata)
 * @param ownerPrivateKey - Owner's secp256k1 private key for unwrapping ECIES keys
 * @param targetPubKeyBytes - Target uncompressed secp256k1 public key (recipient or ephemeral)
 * @param onProgress - Callback for progress tracking
 */
export async function collectChildKeys(
  children: FolderChild[],
  folderKey: Uint8Array,
  ownerPrivateKey: Uint8Array,
  targetPubKeyBytes: Uint8Array,
  onProgress: (wrapped: number) => void
): Promise<ChildKeyDto[]> {
  const childKeys: ChildKeyDto[] = [];
  let wrapped = 0;

  for (const child of children) {
    if (child.type === 'file') {
      const fp = child as FilePointer;
      // Resolve file metadata to get fileKeyEncrypted, then re-wrap for target
      try {
        const { metadata: fileMeta } = await resolveFileMetadata(fp.fileMetaIpnsName, folderKey);
        const reWrappedFileKey = await reWrapEncryptedKey(
          fileMeta.fileKeyEncrypted,
          ownerPrivateKey,
          targetPubKeyBytes
        );
        childKeys.push({
          keyType: 'file' as ChildKeyDto['keyType'],
          itemId: fp.id,
          encryptedKey: reWrappedFileKey,
        });
        wrapped++;
        onProgress(wrapped);
      } catch (err) {
        console.error(`Failed to re-wrap file key for ${fp.name}:`, err);
        // Continue with other children
      }
    } else {
      const folder = child as FolderEntry;
      // Re-wrap the subfolder's folderKey for the target
      try {
        const folderKeyRewrapped = await reWrapEncryptedKey(
          folder.folderKeyEncrypted,
          ownerPrivateKey,
          targetPubKeyBytes
        );
        childKeys.push({
          keyType: 'folder' as ChildKeyDto['keyType'],
          itemId: folder.id,
          encryptedKey: folderKeyRewrapped,
        });
        wrapped++;
        onProgress(wrapped);

        // Recurse into subfolder: resolve its metadata and collect its children
        const resolved = await resolveIpnsRecord(folder.ipnsName);
        if (resolved) {
          const folderKeyBytes = await unwrapKey(
            hexToBytes(folder.folderKeyEncrypted),
            ownerPrivateKey
          );
          try {
            const encryptedBytes = await fetchFromIpfs(resolved.cid);
            const encryptedJson = new TextDecoder().decode(encryptedBytes);
            const encrypted = JSON.parse(encryptedJson);
            const metadata = await decryptFolderMetadata(encrypted, folderKeyBytes);

            const subKeys = await collectChildKeys(
              metadata.children,
              folderKeyBytes,
              ownerPrivateKey,
              targetPubKeyBytes,
              (subWrapped) => {
                onProgress(wrapped + subWrapped);
              }
            );
            wrapped += subKeys.length;
            childKeys.push(...subKeys);
          } finally {
            folderKeyBytes.fill(0);
          }
        }
      } catch (err) {
        console.error(`Failed to re-wrap folder key for ${folder.name}:`, err);
        // Continue with other children
      }
    }
  }

  return childKeys;
}

/**
 * Re-wrap an ECIES-encrypted hex key from owner to target.
 *
 * Unwraps with ownerPrivateKey, then wraps for targetPubKey.
 * Plaintext key is zeroed after use.
 */
export async function reWrapEncryptedKey(
  encryptedKeyHex: string,
  ownerPrivateKey: Uint8Array,
  targetPubKey: Uint8Array
): Promise<string> {
  const plainKey = await unwrapKey(hexToBytes(encryptedKeyHex), ownerPrivateKey);
  try {
    const rewrapped = await wrapKey(plainKey, targetPubKey);
    return bytesToHex(rewrapped);
  } finally {
    plainKey.fill(0);
  }
}
