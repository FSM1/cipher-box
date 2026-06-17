/**
 * @cipherbox/core - Recycle Bin Metadata Types
 *
 * Type definitions for the encrypted recycle bin metadata stored on IPFS/IPNS.
 * The bin tracks soft-deleted files and folders with time-limited retention,
 * enabling recovery to the original vault location.
 */

import type { FilePointer } from '../file/types';
import type { FolderEntry } from '../folder/types';

/**
 * Individual bin entry representing a soft-deleted item.
 *
 * Each entry preserves the full FolderChild (FilePointer or FolderEntry)
 * that was removed from the parent folder's metadata, enabling restore
 * by re-inserting it into the original parent.
 */
export type BinEntry = {
  /** Unique ID for this bin entry (UUID) */
  id: string;
  /** Original item type */
  itemType: 'file' | 'folder';
  /** Display name at time of deletion */
  name: string;
  /** IPNS name of the original parent folder (for restore path resolution) */
  originalParentIpnsName: string;
  /** Full breadcrumb path at deletion time (e.g., "My Vault / Documents / Reports") */
  originalPath: string;
  /** When item was deleted (Unix ms) */
  deletedAt: number;
  /** File/folder size in bytes (0 for folders with unknown size) */
  size: number;
  /** MIME type (empty string for folders) */
  mimeType: string;
  /** IPFS CID of the encrypted file content (captured at soft-delete time for unpin on permanent delete) */
  contentCid?: string;
  /** Original file size in bytes (captured at soft-delete time for quota reclaim on permanent delete) */
  contentSize?: number;
  /** Version CIDs and sizes (captured at soft-delete time for unpin on permanent delete) */
  versionCids?: Array<{ cid: string; size: number }>;

  // --- Item reference data (needed for restore and permanent delete) ---

  /** For files: the preserved FilePointer from parent folder metadata */
  filePointer?: FilePointer;
  /** For folders: the preserved FolderEntry from parent folder metadata */
  folderEntry?: FolderEntry;
  /**
   * For files: the original parent folder's folderKey, ECIES-wrapped for the
   * vault public key, captured at soft-delete time. A file's FileMetadata is
   * AES-256-GCM encrypted with this key; restoring to a folder with a different
   * folderKey must re-encrypt the record (otherwise it becomes undecryptable).
   * Captured here so restore can re-encrypt to ANY destination without needing
   * the original parent to still exist in the folder tree. Hex-encoded.
   * Optional for backward compatibility: entries created before this field
   * fall back to resolving the original parent's key from the live folder tree.
   */
  originalFolderKeyEncrypted?: string;
};

/**
 * The full recycle bin metadata.
 *
 * Encrypted as a single JSON blob with the user's publicKey via ECIES,
 * then stored on IPFS and referenced by a dedicated IPNS name.
 * Follows the same pattern as DeviceRegistry.
 */
export type RecycleBinMetadata = {
  /** Schema version for future migrations */
  version: 'v1';
  /** Monotonically increasing update counter */
  sequenceNumber: number;
  /** Array of all bin entries */
  entries: BinEntry[];
};
