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

  /**
   * Monotonic per-share "active-depth seed generation" (D-08 item 11).
   *
   * Every navigation that changes the active depth (descend / navigateUp /
   * breadcrumb / share-enter / unload) bumps this counter via
   * {@link nextSeedGeneration}. A seed carrying a stale generation — e.g. a
   * subfolder descent whose async resolve lands AFTER a navigateUp already
   * superseded it — is rejected by the client's `loadSharedFolder` guard so it
   * cannot repoint the active writeKey/depth to the wrong (superseded) target.
   *
   * Deliberately NOT reset by delete()/clear(): monotonicity must survive an
   * unload so an in-flight seed racing the unload is still recognised as stale.
   */
  private seedGenerations = new Map<string, number>();

  /** Get a shared folder's state by shareId */
  get(shareId: string): SharedFolderState | undefined {
    return this.shares.get(shareId);
  }

  /**
   * Bump and return the next monotonic active-depth seed generation for a
   * share (D-08 item 11). Callers capture the returned value at the START of an
   * async navigation and pass it back into `loadSharedFolder` so a superseded
   * seed is discarded.
   */
  nextSeedGeneration(shareId: string): number {
    const next = (this.seedGenerations.get(shareId) ?? 0) + 1;
    this.seedGenerations.set(shareId, next);
    return next;
  }

  /** Current active-depth seed generation for a share (0 if never bumped). */
  currentSeedGeneration(shareId: string): number {
    return this.seedGenerations.get(shareId) ?? 0;
  }

  /** Set or update a shared folder's state, cloning key material to avoid zeroing caller buffers */
  set(shareId: string, state: SharedFolderState): void {
    // Zero the previous entry's key material before overwriting so stale keys
    // don't linger in memory across re-seeds. Guard on reference identity: the
    // adopt path spreads the LIVE entry, so its folderKey/ipnsPrivateKey are the
    // same buffers we're about to clone — zeroing them would corrupt the clone.
    const prev = this.shares.get(shareId);
    if (prev) {
      if (prev.folderKey && prev.folderKey !== state.folderKey) prev.folderKey.fill(0);
      if (prev.ipnsPrivateKey && prev.ipnsPrivateKey !== state.ipnsPrivateKey)
        prev.ipnsPrivateKey.fill(0);
      if (prev.writeKey && prev.writeKey !== state.writeKey) prev.writeKey.fill(0);
    }
    this.shares.set(shareId, {
      ...state,
      folderKey: new Uint8Array(state.folderKey),
      ipnsPrivateKey: new Uint8Array(state.ipnsPrivateKey),
      // 68.1-29: writeKey must be cloned like the other key buffers — the web
      // seeding caller zeroes its own writeKey buffer right after seeding
      // (D-09 terminal ownership), so storing the caller's reference left the
      // tree holding an all-zero writeKey. That silently downgraded every
      // write share to read-only: uploadToSharedFolder failed GCM auth on the
      // parent write-body ("Decryption failed", writable-shares 3.2) and
      // enumerateSharedSubtree's zero-key detection marked every destination
      // read-only (shared-folder-move 3.3).
      writeKey: new Uint8Array(state.writeKey),
    });
  }

  /** Remove a shared folder from the tree, zeroing only that entry's key material */
  delete(shareId: string): void {
    const state = this.shares.get(shareId);
    if (state) {
      if (state.folderKey) state.folderKey.fill(0);
      if (state.ipnsPrivateKey) state.ipnsPrivateKey.fill(0);
      if (state.writeKey) state.writeKey.fill(0);
    }
    this.shares.delete(shareId);
    // D-08 item 11: bump the seed generation so a descent still in flight when
    // this unload lands cannot re-create the entry with a stale seed.
    this.seedGenerations.set(shareId, (this.seedGenerations.get(shareId) ?? 0) + 1);
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
    for (const [shareId, state] of this.shares) {
      if (state.folderKey) state.folderKey.fill(0);
      if (state.ipnsPrivateKey) state.ipnsPrivateKey.fill(0);
      if (state.writeKey) state.writeKey.fill(0);
      // D-08 item 11: bump the seed generation for every cleared share (parity
      // with delete()) so a descent still in flight when this clear lands
      // cannot re-create the entry with a now-stale seed and re-insert key
      // material after teardown.
      this.seedGenerations.set(shareId, (this.seedGenerations.get(shareId) ?? 0) + 1);
    }
    this.shares.clear();
  }

  /** Get a snapshot of all loaded shared folders (for iteration) */
  getAll(): Map<string, SharedFolderState> {
    return new Map(this.shares);
  }
}
