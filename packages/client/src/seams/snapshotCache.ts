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
import { memoizedDatabase, requestResult, transactionDone } from './idb.js';
import type { SnapshotCacheSeam } from './types.js';

const STORE = 'entries';

export class IdbSnapshotCache implements SnapshotCacheSeam {
  private readonly open: () => Promise<IDBDatabase>;

  constructor(dbName = 'cipherbox-snapshot-cache') {
    this.open = memoizedDatabase(dbName, 1, (db) => {
      db.createObjectStore(STORE);
    });
  }

  async put(cacheKey: Uint8Array, ciphertext: Uint8Array): Promise<void> {
    // Encode the key and copy the value synchronously, before the first await:
    // both may be views into WASM linear memory that a concurrent task's
    // `Memory.grow()` can detach across the await — a detached key hexes to ''
    // (cross-key collision) and a detached value corrupts the stored bytes (#717).
    const storeKey = toHex(cacheKey);
    const value = ciphertext.slice();
    const db = await this.open();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(value, storeKey);
    await transactionDone(tx);
  }

  async get(cacheKey: Uint8Array): Promise<Uint8Array | null> {
    const storeKey = toHex(cacheKey);
    const db = await this.open();
    const tx = db.transaction(STORE, 'readonly');
    const value = await requestResult<Uint8Array | undefined>(tx.objectStore(STORE).get(storeKey));
    await transactionDone(tx);
    return value ?? null;
  }

  async remove(cacheKey: Uint8Array): Promise<void> {
    const storeKey = toHex(cacheKey);
    const db = await this.open();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(storeKey);
    await transactionDone(tx);
  }

  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    await transactionDone(tx);
  }
}
