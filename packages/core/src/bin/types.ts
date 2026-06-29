/**
 * @cipherbox/core - Recycle Bin Metadata Types
 *
 * Type definitions for the encrypted recycle bin metadata stored on IPFS/IPNS.
 * The bin tracks soft-deleted files and folders with time-limited retention,
 * enabling recovery to the original vault location.
 */

import type { Node } from '../node/types';

/**
 * Individual bin entry representing a soft-deleted item.
 *
 * Each entry preserves a reference to the deleted node (via nodeRef),
 * enabling restore as a pure re-link under the destination readKey (Phase 65).
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
  /**
   * For folder entries: every content + version CID of the WHOLE deleted subtree,
   * flattened (each descendant file's current content CID plus all of its version
   * CIDs). Captured at soft-delete time by walking the subtree so that emptying the
   * bin / permanently deleting a folder unpins all descendant content, not just the
   * folder's own (non-existent) content. Undefined for file entries (their CIDs live
   * in contentCid / versionCids). Per-file capture is best-effort: a file whose
   * metadata cannot be read is skipped here (its shares are still revoked).
   */
  descendantCids?: Array<{ cid: string; size: number }>;

  // --- Item reference data (needed for restore and permanent delete) ---

  /**
   * Reference to the deleted node (file or folder).
   * Phase 65 implements bin restore as a pure re-link under the destination readKey.
   * TODO(phase 65): bin restore is a pure re-link under destination readKey
   */
  nodeRef?: Node;
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
