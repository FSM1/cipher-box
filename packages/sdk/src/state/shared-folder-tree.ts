/**
 * @cipherbox/sdk - Internal shared-folder tree state manager
 *
 * Tracks loaded SHARED folders, keyed by `shareId` (NOT by `ipnsName`).
 *
 * This is a SIBLING to {@link FolderTree}: shared folders carry a distinct
 * SharedWriteContext (owner + recipient pubkeys, IPNS private key, shareId,
 * addShareKeys callback) and two different shares can collide on the same
 * `ipnsName`. Keying by `shareId` keeps each share's state and key material
 * isolated — no cross-share bleed (D REQ-3, decision A4; research Pattern 2).
 *
 * Security: delete()/clear() fill all key material (folderKey + ipnsPrivateKey)
 * with zeros before removing references (CLAUDE.md rule 9). set() clones key
 * buffers so caller buffers are never zeroed by our cleanup.
 */

import type { SharedFolderState } from '../types';

/**
 * Internal shared-folder tree state. Tracks loaded shared folders by `shareId`.
 *
 * Mirrors {@link FolderTree}'s shape (get/set/has/delete/clear/getAll) with
 * per-share key-zeroing.
 */
export class SharedFolderTree {
  private shares = new Map<string, SharedFolderState>();

  /** Get a shared folder's state by shareId */
  get(shareId: string): SharedFolderState | undefined {
    return this.shares.get(shareId);
  }

  /** Set or update a shared folder's state, cloning key material to avoid zeroing caller buffers */
  set(shareId: string, state: SharedFolderState): void {
    this.shares.set(shareId, {
      ...state,
      folderKey: new Uint8Array(state.folderKey),
      ipnsPrivateKey: new Uint8Array(state.ipnsPrivateKey),
    });
  }

  /** Remove a shared folder from the tree, zeroing only that entry's key material */
  delete(shareId: string): void {
    const state = this.shares.get(shareId);
    if (state) {
      if (state.folderKey) state.folderKey.fill(0);
      if (state.ipnsPrivateKey) state.ipnsPrivateKey.fill(0);
    }
    this.shares.delete(shareId);
  }

  /** Check if a shared folder has been loaded */
  has(shareId: string): boolean {
    return this.shares.has(shareId);
  }

  /**
   * Clear all shared-folder state, zeroing all sensitive key material.
   * Called during client destroy().
   */
  clear(): void {
    for (const state of this.shares.values()) {
      if (state.folderKey) state.folderKey.fill(0);
      if (state.ipnsPrivateKey) state.ipnsPrivateKey.fill(0);
    }
    this.shares.clear();
  }

  /** Get a snapshot of all loaded shared folders (for iteration) */
  getAll(): Map<string, SharedFolderState> {
    return new Map(this.shares);
  }
}
