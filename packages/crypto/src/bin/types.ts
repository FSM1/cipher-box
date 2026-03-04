/**
 * @cipherbox/crypto - Recycle Bin Metadata Types
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

  // --- Item reference data (needed for restore and permanent delete) ---

  /** For files: the preserved FilePointer from parent folder metadata */
  filePointer?: FilePointer;
  /** For folders: the preserved FolderEntry from parent folder metadata */
  folderEntry?: FolderEntry;
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
