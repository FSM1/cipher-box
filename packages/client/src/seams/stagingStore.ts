/**
 * `StagingStore` — durable op queue in IndexedDB, staged upload bytes in OPFS
 * (blueprint/web-client.md seam table).
 *
 * The op queue is an IndexedDB object store with an auto-incrementing key
 * generator: ids are strictly increasing and never reused, even across removes
 * and reopens (the generator persists with the store), so enqueue order is
 * FIFO order. Staged bytes live one-file-per-key in an OPFS directory, written
 * and read through synchronous access handles in the worker realm.
 *
 * The engine owns op encoding, replay, and orphan GC; this seam only stores,
 * enumerates, and accounts.
 */

import { fromHex, toHex } from './bytes.js';
import { openDatabase, requestResult, transactionDone } from './idb.js';
import type { StagingStoreSeam } from './types.js';

const OPS_STORE = 'ops';

export class OpfsStagingStore implements StagingStoreSeam {
  private readonly dbName: string;
  private readonly dirName: string;
  private dbPromise: Promise<IDBDatabase> | null = null;

  constructor(name = 'cipherbox-staging') {
    this.dbName = name;
    this.dirName = `${name}-staged`;
  }

  private open(): Promise<IDBDatabase> {
    // Memoize the in-flight open, not just the resolved handle: concurrent
    // callers before the first open resolves must share one connection. A
    // failed open clears the memo so the next call can re-open.
    return (this.dbPromise ??= openDatabase(this.dbName, 1, (db) => {
      // Out-of-line auto-incrementing keys are the OpId source: strictly
      // increasing, never reused, durable across reopen.
      db.createObjectStore(OPS_STORE, { autoIncrement: true });
    }).catch((error: unknown) => {
      this.dbPromise = null;
      throw error;
    }));
  }

  private async stagedDir(): Promise<FileSystemDirectoryHandle> {
    const root = await navigator.storage.getDirectory();
    return root.getDirectoryHandle(this.dirName, { create: true });
  }

  async enqueueOp(op: Uint8Array): Promise<number> {
    const db = await this.open();
    const tx = db.transaction(OPS_STORE, 'readwrite');
    const key = await requestResult<IDBValidKey>(tx.objectStore(OPS_STORE).add(op.slice()));
    await transactionDone(tx);
    return Number(key);
  }

  async queuedOps(): Promise<Array<[number, Uint8Array]>> {
    const db = await this.open();
    const tx = db.transaction(OPS_STORE, 'readonly');
    const store = tx.objectStore(OPS_STORE);
    // getAllKeys and getAll both return in ascending-key (FIFO) order.
    const keys = await requestResult<IDBValidKey[]>(store.getAllKeys());
    const values = await requestResult<Uint8Array[]>(store.getAll());
    await transactionDone(tx);
    return keys.map((key, index) => [Number(key), values[index]] as [number, Uint8Array]);
  }

  async removeOp(opId: number): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(OPS_STORE, 'readwrite');
    tx.objectStore(OPS_STORE).delete(opId);
    await transactionDone(tx);
  }

  async putStagedBytes(stagingKey: Uint8Array, bytes: Uint8Array): Promise<void> {
    const dir = await this.stagedDir();
    const fileHandle = await dir.getFileHandle(toHex(stagingKey), { create: true });
    const handle = await fileHandle.createSyncAccessHandle();
    try {
      handle.truncate(0);
      handle.write(bytes, { at: 0 });
      handle.flush();
    } finally {
      handle.close();
    }
  }

  async stagedBytes(stagingKey: Uint8Array): Promise<Uint8Array | null> {
    const dir = await this.stagedDir();
    let fileHandle: FileSystemFileHandle;
    try {
      fileHandle = await dir.getFileHandle(toHex(stagingKey));
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') return null;
      throw error;
    }
    const handle = await fileHandle.createSyncAccessHandle();
    try {
      const size = handle.getSize();
      const out = new Uint8Array(size);
      handle.read(out, { at: 0 });
      return out;
    } finally {
      handle.close();
    }
  }

  async removeStagedBytes(stagingKey: Uint8Array): Promise<void> {
    const dir = await this.stagedDir();
    try {
      await dir.removeEntry(toHex(stagingKey));
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') return;
      throw error;
    }
  }

  async stagedKeys(): Promise<Uint8Array[]> {
    const dir = await this.stagedDir();
    const keys: Uint8Array[] = [];
    for await (const name of dir.keys()) {
      keys.push(fromHex(name));
    }
    return keys;
  }

  async stagedBytesTotal(): Promise<number> {
    const dir = await this.stagedDir();
    let total = 0;
    for await (const name of dir.keys()) {
      const fileHandle = await dir.getFileHandle(name);
      const file = await fileHandle.getFile();
      total += file.size;
    }
    return total;
  }
}
