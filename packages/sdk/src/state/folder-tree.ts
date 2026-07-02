/**
 * @cipherbox/sdk - Internal folder tree state manager
 *
 * Tracks loaded folders, their decrypted keys, metadata, and IPNS state.
 * This is the SDK's internal state -- NOT exposed to consumers directly.
 * Consumers receive state changes via events.
 *
 * Security: clear() fills all key material with zeros before removing
 * references, following the memory-clearing principle from CLAUDE.md.
 */

import type { FolderState } from '../types';

/**
 * Internal folder tree state. Tracks loaded folders by IPNS name.
 *
 * Each folder's FolderState includes decrypted keys, children, and
 * IPNS sequence number -- everything needed to read and update the folder.
 */
export class FolderTree {
  private folders = new Map<string, FolderState>();

  /** Get a folder's state by IPNS name */
  get(ipnsName: string): FolderState | undefined {
    return this.folders.get(ipnsName);
  }

  /** Set or update a folder's state, cloning key material to avoid zeroing caller buffers */
  set(ipnsName: string, state: FolderState): void {
    this.folders.set(ipnsName, {
      ...state,
      folderKey: new Uint8Array(state.folderKey),
      writeKey: new Uint8Array(state.writeKey),
      ipnsKeypair: {
        publicKey: new Uint8Array(state.ipnsKeypair.publicKey),
        privateKey: new Uint8Array(state.ipnsKeypair.privateKey),
      },
    });
  }

  /** Remove a folder from the tree */
  delete(ipnsName: string): void {
    const state = this.folders.get(ipnsName);
    if (state) {
      // Clear sensitive key material before removing
      if (state.folderKey) state.folderKey.fill(0);
      if (state.writeKey) state.writeKey.fill(0);
      if (state.ipnsKeypair?.privateKey) state.ipnsKeypair.privateKey.fill(0);
    }
    this.folders.delete(ipnsName);
  }

  /** Check if a folder has been loaded */
  has(ipnsName: string): boolean {
    return this.folders.has(ipnsName);
  }

  /**
   * Clear all folder state, zeroing all sensitive key material.
   * Called during client destroy().
   */
  clear(): void {
    for (const state of this.folders.values()) {
      if (state.folderKey) state.folderKey.fill(0);
      if (state.writeKey) state.writeKey.fill(0);
      if (state.ipnsKeypair?.privateKey) state.ipnsKeypair.privateKey.fill(0);
    }
    this.folders.clear();
  }

  /** Get a snapshot of all loaded folders (for iteration) */
  getAll(): Map<string, FolderState> {
    return new Map(this.folders);
  }
}
