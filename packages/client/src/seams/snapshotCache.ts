/**
 * `SnapshotCache` — durable last-known-good cache over IndexedDB, ciphertext
 * only at rest (blueprint/web-client.md seam table).
 *
 * The engine only ever hands this store sealed bytes and unseals on read;
 * plaintext never lands in browser storage. The store treats values as opaque:
 * arbitrary, non-decodable bytes round-trip verbatim (it never parses, never
 * normalizes). Contents survive logout; an explicit "forget this device"
 * clears them via {@link IdbSnapshotCache.clear}.
 */

import { toHex } from './bytes.js';
import { openDatabase, requestResult, transactionDone } from './idb.js';
import type { SnapshotCacheSeam } from './types.js';

const STORE = 'entries';

export class IdbSnapshotCache implements SnapshotCacheSeam {
  private readonly dbName: string;
  private db: IDBDatabase | null = null;

  constructor(dbName = 'cipherbox-snapshot-cache') {
    this.dbName = dbName;
  }

  private async open(): Promise<IDBDatabase> {
    if (this.db) return this.db;
    this.db = await openDatabase(this.dbName, 1, (db) => {
      db.createObjectStore(STORE);
    });
    return this.db;
  }

  async put(cacheKey: Uint8Array, ciphertext: Uint8Array): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(STORE, 'readwrite');
    // Store a standalone copy: the value must be independent of any buffer the
    // caller may reuse, and round-trip byte-for-byte.
    tx.objectStore(STORE).put(ciphertext.slice(), toHex(cacheKey));
    await transactionDone(tx);
  }

  async get(cacheKey: Uint8Array): Promise<Uint8Array | null> {
    const db = await this.open();
    const tx = db.transaction(STORE, 'readonly');
    const value = await requestResult<Uint8Array | undefined>(
      tx.objectStore(STORE).get(toHex(cacheKey))
    );
    await transactionDone(tx);
    return value ?? null;
  }

  async remove(cacheKey: Uint8Array): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(toHex(cacheKey));
    await transactionDone(tx);
  }

  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    await transactionDone(tx);
  }
}
