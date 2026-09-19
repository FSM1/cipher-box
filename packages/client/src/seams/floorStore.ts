/**
 * `FloorStore` — durable monotonic-max floors over IndexedDB
 * (blueprint/web-client.md seam table).
 *
 * Durable across logout by design; IndexedDB is required (no in-memory
 * fallback tier). Epoch floors and sequence floors are independent object
 * stores, so identical key bytes in the two namespaces never collide. Each
 * `raise*` is a read-modify-write inside one `readwrite` transaction, so the
 * stored floor is structurally incapable of regression.
 */

import { toHex } from './bytes.js';
import { memoizedDatabase, requestResult, transactionDone } from './idb.js';
import type { FloorStoreSeam } from './types.js';

const EPOCH_STORE = 'epoch';
const SEQUENCE_STORE = 'sequence';

/**
 * A floor is a non-negative safe integer, so it crosses to the engine exactly.
 * Any other value is unreadable, never "no floor": that would let a replayed
 * older record past the adoption gate.
 */
function checkedFloor(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`FloorStore: ${what} is not a non-negative safe integer`);
  }
  return value;
}

export class IdbFloorStore implements FloorStoreSeam {
  private readonly open: () => Promise<IDBDatabase>;

  constructor(dbName = 'cipherbox-floors') {
    this.open = memoizedDatabase(dbName, 1, (db) => {
      db.createObjectStore(EPOCH_STORE);
      db.createObjectStore(SEQUENCE_STORE);
    });
  }

  private async floor(store: string, key: Uint8Array): Promise<number | null> {
    // Hex the key before the first await: `key` may be a view into WASM linear
    // memory that a concurrent `Memory.grow()` detaches across the await, and a
    // floor read under the wrong key answers "no floor".
    const floorKey = toHex(key);
    const db = await this.open();
    const tx = db.transaction(store, 'readonly');
    const value = await requestResult<unknown>(tx.objectStore(store).get(floorKey));
    await transactionDone(tx);
    return value === undefined ? null : checkedFloor(value, 'stored floor');
  }

  private async raise(store: string, key: Uint8Array, value: number): Promise<number> {
    checkedFloor(value, 'floor value');
    // Hex the key before the first await, as in `floor`.
    const hexKey = toHex(key);
    const db = await this.open();
    const tx = db.transaction(store, 'readwrite');
    const objectStore = tx.objectStore(store);
    const stored = await requestResult<unknown>(objectStore.get(hexKey));
    const raised =
      stored === undefined ? value : Math.max(checkedFloor(stored, 'stored floor'), value);
    objectStore.put(raised, hexKey);
    await transactionDone(tx);
    return raised;
  }

  epochFloor(scopeId: Uint8Array): Promise<number | null> {
    return this.floor(EPOCH_STORE, scopeId);
  }

  raiseEpochFloor(scopeId: Uint8Array, epoch: number): Promise<number> {
    return this.raise(EPOCH_STORE, scopeId, epoch);
  }

  sequenceFloor(ipnsName: Uint8Array): Promise<number | null> {
    return this.floor(SEQUENCE_STORE, ipnsName);
  }

  raiseSequenceFloor(ipnsName: Uint8Array, sequence: number): Promise<number> {
    return this.raise(SEQUENCE_STORE, ipnsName, sequence);
  }

  /** Both namespaces in one transaction, so no floor outlives the other's erase. */
  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction([EPOCH_STORE, SEQUENCE_STORE], 'readwrite');
    tx.objectStore(EPOCH_STORE).clear();
    tx.objectStore(SEQUENCE_STORE).clear();
    await transactionDone(tx);
  }
}
