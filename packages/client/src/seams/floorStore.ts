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
import { openDatabase, requestResult, transactionDone } from './idb.js';
import type { FloorStoreSeam } from './types.js';

const EPOCH_STORE = 'epoch';
const SEQUENCE_STORE = 'sequence';

export class IdbFloorStore implements FloorStoreSeam {
  private readonly dbName: string;
  private db: IDBDatabase | null = null;

  constructor(dbName = 'cipherbox-floors') {
    this.dbName = dbName;
  }

  private async open(): Promise<IDBDatabase> {
    if (this.db) return this.db;
    this.db = await openDatabase(this.dbName, 1, (db) => {
      db.createObjectStore(EPOCH_STORE);
      db.createObjectStore(SEQUENCE_STORE);
    });
    return this.db;
  }

  private async floor(store: string, key: Uint8Array): Promise<number | null> {
    const db = await this.open();
    const tx = db.transaction(store, 'readonly');
    const value = await requestResult<number | undefined>(tx.objectStore(store).get(toHex(key)));
    await transactionDone(tx);
    return value ?? null;
  }

  private async raise(store: string, key: Uint8Array, value: number): Promise<number> {
    const db = await this.open();
    const tx = db.transaction(store, 'readwrite');
    const objectStore = tx.objectStore(store);
    const hexKey = toHex(key);
    const current = await requestResult<number | undefined>(objectStore.get(hexKey));
    const raised = current === undefined ? value : Math.max(current, value);
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
}
