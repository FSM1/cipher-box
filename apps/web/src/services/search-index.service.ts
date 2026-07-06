/**
 * Search Index Service
 *
 * Manages a client-side search index for file and folder names using MiniSearch.
 * The index is encrypted with AES-256-GCM (key derived via HKDF from the user's
 * vault private key) before persisting to IndexedDB for zero-knowledge on-disk storage.
 *
 * This is a pure TypeScript service with no React dependencies.
 */

import MiniSearch from 'minisearch';
import type { FolderNode } from '../stores/folder.store';
import { logger } from '../lib/logger';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A document stored in the MiniSearch index. */
type SearchDocument = {
  /** Unique key: `${folderId}:${childId}` (avoids collisions across folders) */
  id: string;
  /** File or folder name (what users search for) */
  name: string;
  /** Whether this is a file or folder */
  type: 'file' | 'folder';
  /** Breadcrumb path like "My Vault / Documents / Reports" */
  parentPath: string;
  /** Folder ID for navigation on result click */
  parentFolderId: string;
  /** Timestamp for display in results (Unix ms) */
  modifiedAt: number;
};

/** A search result returned by the service. */
export type SearchResult = {
  id: string;
  name: string;
  type: 'file' | 'folder';
  parentPath: string;
  parentFolderId: string;
  modifiedAt: number;
  /** MiniSearch relevance score (higher = better match) */
  score: number;
  /** Match info from MiniSearch, maps field name to matching terms */
  match: Record<string, string[]>;
};

// ---------------------------------------------------------------------------
// MiniSearch options (shared between constructor and loadJSON)
// ---------------------------------------------------------------------------

const MINISEARCH_OPTIONS = {
  fields: ['name'],
  storeFields: ['name', 'type', 'parentPath', 'parentFolderId', 'modifiedAt'],
  searchOptions: {
    fuzzy: 0.2,
    prefix: true,
    boost: { name: 1 },
  },
};

// ---------------------------------------------------------------------------
// IndexedDB constants
// ---------------------------------------------------------------------------

const IDB_NAME = 'cipherbox-search';
const IDB_VERSION = 1;
const IDB_STORE = 'index';
const IDB_KEY = 'encrypted-index';

// ---------------------------------------------------------------------------
// HKDF constants
// ---------------------------------------------------------------------------

const HKDF_INFO = 'cipherbox-search-index-v1';

// ---------------------------------------------------------------------------
// IndexedDB helpers (follows pattern from device/identity.ts)
// ---------------------------------------------------------------------------

function openSearchDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(IDB_NAME, IDB_VERSION);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(IDB_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// ---------------------------------------------------------------------------
// SearchIndexService
// ---------------------------------------------------------------------------

export class SearchIndexService {
  private miniSearch: MiniSearch<SearchDocument>;
  private indexVersion: number = 0;

  constructor() {
    this.miniSearch = new MiniSearch<SearchDocument>(MINISEARCH_OPTIONS);
  }

  /**
   * Build the full index from the folder store's folder tree.
   * Walks all loaded FolderNodes and indexes their children (files and folders).
   *
   * @param folders - Record<string, FolderNode> from folder store
   */
  buildFromFolderTree(folders: Record<string, FolderNode>): void {
    this.miniSearch.removeAll();

    const documents: SearchDocument[] = [];

    for (const folder of Object.values(folders)) {
      const parentPath = this.buildPath(folder.id, folders);

      // Index each child (files and subfolders). `folder.children` is the
      // SDK-resolved `ResolvedChild[]` projection (68.2-09) -- `modifiedAt`
      // AND `kind` are sourced from the child's own resolved listing entry,
      // not the (now-reverted) SealedChildRef display mirror (D-08/68.2-12).
      for (const child of folder.children) {
        documents.push({
          id: `${folder.id}:${child.ipnsName}`,
          name: child.name,
          // Discriminate by the resolved kind so subfolders index as 'folder'
          // (not silently as 'file'); a folder's own self-entry above wins
          // dedup via its distinct id.
          type: child.kind === 'file' ? 'file' : 'folder',
          parentPath,
          parentFolderId: folder.id,
          modifiedAt: child.modifiedAt,
        });
      }
    }

    // Also index folders themselves (except root) as searchable items.
    // A folder's parent is its parentId, so it appears in search under
    // the parent folder's path.
    for (const folder of Object.values(folders)) {
      if (!folder.parentId) continue; // skip root
      const parentFolder = folders[folder.parentId];
      if (!parentFolder) continue;

      const parentPath = this.buildPath(folder.parentId, folders);

      // Use the folder's own id with a "self:" prefix to avoid collision
      // with the same folder appearing as a child entry
      documents.push({
        id: `${folder.parentId}:${folder.id}`,
        name: folder.name,
        type: 'folder',
        parentPath,
        parentFolderId: folder.parentId,
        modifiedAt: 0, // folders don't have a top-level modifiedAt
      });
    }

    // Deduplicate: children already include subfolder entries from parent.
    // The folder-self entries above may overlap with child entries.
    // Use a Map to keep only one document per id.
    const deduped = new Map<string, SearchDocument>();
    for (const doc of documents) {
      if (!deduped.has(doc.id)) {
        deduped.set(doc.id, doc);
      }
    }

    this.miniSearch.addAll(Array.from(deduped.values()));
    this.indexVersion++;
  }

  /**
   * Search the index with fuzzy matching.
   *
   * @param query - user's search string
   * @returns Array of SearchResult sorted by relevance score (descending)
   */
  search(query: string): SearchResult[] {
    if (!query.trim()) return [];

    const results = this.miniSearch.search(query);

    return results.map((result) => ({
      id: result.id as string,
      name: result.name as string,
      type: result.type as 'file' | 'folder',
      parentPath: result.parentPath as string,
      parentFolderId: result.parentFolderId as string,
      modifiedAt: result.modifiedAt as number,
      score: result.score,
      match: result.match,
    }));
  }

  /**
   * Persist the current index to IndexedDB, encrypted with a key derived
   * from the user's vault private key via HKDF.
   *
   * @param userPrivateKey - user's secp256k1 private key (32 bytes) for HKDF derivation
   */
  async persistEncrypted(userPrivateKey: Uint8Array): Promise<void> {
    try {
      const searchKey = await this.deriveSearchKey(userPrivateKey);
      const serialized = JSON.stringify(this.miniSearch.toJSON());
      const plaintext = new TextEncoder().encode(serialized);

      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, searchKey, plaintext);

      const db = await openSearchDB();
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const store = tx.objectStore(IDB_STORE);

      // Store as number[] for cross-browser IndexedDB compatibility
      store.put(
        {
          iv: Array.from(iv),
          data: Array.from(new Uint8Array(ciphertext)),
        },
        IDB_KEY
      );

      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (err) {
      logger.warn('[SearchIndex] Failed to persist encrypted index:', err);
    }
  }

  /**
   * Load the index from IndexedDB and decrypt.
   *
   * @param userPrivateKey - user's secp256k1 private key (32 bytes) for HKDF derivation
   * @returns true if index was loaded successfully, false if not found or decryption failed
   */
  async loadEncrypted(userPrivateKey: Uint8Array): Promise<boolean> {
    try {
      const db = await openSearchDB();
      const tx = db.transaction(IDB_STORE, 'readonly');
      const store = tx.objectStore(IDB_STORE);

      const stored = await new Promise<{
        iv: number[];
        data: number[];
      } | null>((resolve, reject) => {
        const request = store.get(IDB_KEY);
        request.onsuccess = () => resolve(request.result ?? null);
        request.onerror = () => reject(request.error);
      });

      if (!stored || !stored.iv || !stored.data) return false;

      const searchKey = await this.deriveSearchKey(userPrivateKey);
      const iv = new Uint8Array(stored.iv);
      const ciphertext = new Uint8Array(stored.data);

      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, searchKey, ciphertext);

      const serialized = new TextDecoder().decode(plaintext);
      const json = JSON.parse(serialized);

      this.miniSearch = MiniSearch.loadJSON(JSON.stringify(json), MINISEARCH_OPTIONS);
      return true;
    } catch (err) {
      logger.warn('[SearchIndex] Failed to load encrypted index:', err);
      return false;
    }
  }

  /**
   * Clear the in-memory index and remove the encrypted entry from IndexedDB.
   * Call on logout.
   */
  async clear(): Promise<void> {
    this.miniSearch.removeAll();

    try {
      const db = await openSearchDB();
      const tx = db.transaction(IDB_STORE, 'readwrite');
      const store = tx.objectStore(IDB_STORE);
      store.delete(IDB_KEY);

      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (err) {
      logger.warn('[SearchIndex] Failed to clear IndexedDB entry:', err);
    }
  }

  /** Returns whether the index has any documents */
  get isEmpty(): boolean {
    return this.miniSearch.documentCount === 0;
  }

  /** Returns the number of indexed documents */
  get size(): number {
    return this.miniSearch.documentCount;
  }

  /** Current index version (increments on each rebuild) */
  get version(): number {
    return this.indexVersion;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Build the breadcrumb path for a folder by walking up the parent chain.
   */
  private buildPath(folderId: string, folders: Record<string, FolderNode>): string {
    const parts: string[] = [];
    let currentId: string | null = folderId;
    while (currentId) {
      const node: FolderNode | undefined = folders[currentId];
      if (!node) break;
      parts.unshift(node.name);
      currentId = node.parentId;
    }
    return parts.join(' / ');
  }

  /**
   * Derive a dedicated AES-256-GCM key from the user's vault private key
   * using HKDF with domain-separated info string.
   */
  private async deriveSearchKey(userPrivateKey: Uint8Array): Promise<CryptoKey> {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      userPrivateKey as BufferSource,
      'HKDF',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode(HKDF_INFO),
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }
}

// ---------------------------------------------------------------------------
// Singleton instance
// ---------------------------------------------------------------------------

export const searchIndexService = new SearchIndexService();
