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
import { memoizedDatabase, requestResult, transactionDone } from './idb.js';
import type { StagingStoreSeam } from './types.js';

const OPS_STORE = 'ops';

/**
 * A staged-byte read or write that did not move every requested byte. OPFS sync
 * access handles signal that either as a short count or as a thrown storage
 * error, so this is the seam's fail-closed signal for both, never a recoverable
 * partial result.
 */
export class StagingIoError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'StagingIoError';
  }
}

/** Removes `name` from `dir`, treating an already-absent entry as success. */
async function removeIfPresent(dir: FileSystemDirectoryHandle, name: string): Promise<void> {
  try {
    await dir.removeEntry(name);
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotFoundError') return;
    throw error;
  }
}

export class OpfsStagingStore implements StagingStoreSeam {
  private readonly dirName: string;
  private readonly open: () => Promise<IDBDatabase>;

  constructor(name = 'cipherbox-staging') {
    this.dirName = `${name}-staged`;
    this.open = memoizedDatabase(name, 1, (db) => {
      // Out-of-line auto-incrementing keys are the OpId source: strictly
      // increasing, never reused, durable across reopen.
      db.createObjectStore(OPS_STORE, { autoIncrement: true });
    });
  }

  private async stagedDir(): Promise<FileSystemDirectoryHandle> {
    const root = await navigator.storage.getDirectory();
    return root.getDirectoryHandle(this.dirName, { create: true });
  }

  async enqueueOp(op: Uint8Array): Promise<number> {
    // Copy before the first await: `op` may be a view into WASM linear memory
    // that a concurrent task's `Memory.grow()` can detach across the await (#717).
    const staged = op.slice();
    const db = await this.open();
    const tx = db.transaction(OPS_STORE, 'readwrite');
    const key = await requestResult<IDBValidKey>(tx.objectStore(OPS_STORE).add(staged));
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
    // Encode the key and copy the value before the first await: both may be
    // views into WASM linear memory that a concurrent task's `Memory.grow()`
    // can detach across the awaits below — a detached key hexes to '' and a
    // detached value truncates or throws on `handle.write` (#717).
    const fileName = toHex(stagingKey);
    const staged = bytes.slice();
    const dir = await this.stagedDir();
    const fileHandle = await dir.getFileHandle(fileName, { create: true });
    const handle = await fileHandle.createSyncAccessHandle();
    let failure: { message: string; cause?: unknown } | undefined;
    try {
      handle.truncate(0);
      const written = handle.write(staged, { at: 0 });
      handle.flush();
      if (written !== staged.byteLength) {
        failure = {
          message: `staged write truncated: wrote ${written} of ${staged.byteLength} bytes`,
        };
      }
    } catch (error) {
      failure = { message: 'staged write failed', cause: error };
    } finally {
      handle.close();
    }
    if (!failure) return;
    // A constrained write either returns a short count or throws (the spec names
    // QuotaExceededError). Either way `truncate(0)` has already landed, so a
    // partial file is on disk; staging a truncated block would later upload
    // bytes whose CID the engine's read path always rejects. Fail closed and
    // drop the file so a retry starts from empty rather than resuming it.
    const cleanupError = await removeIfPresent(dir, fileName).then(
      () => undefined,
      (error: unknown) => error
    );
    throw new StagingIoError(failure.message, { cause: failure.cause ?? cleanupError });
  }

  async stagedBytes(stagingKey: Uint8Array): Promise<Uint8Array | null> {
    // Hex the key before the first await: a WASM-backed view detached by a
    // concurrent `Memory.grow()` across the await would hex to '' (#717).
    const fileName = toHex(stagingKey);
    const dir = await this.stagedDir();
    let fileHandle: FileSystemFileHandle;
    try {
      fileHandle = await dir.getFileHandle(fileName);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') return null;
      throw error;
    }
    const handle = await fileHandle.createSyncAccessHandle();
    try {
      const size = handle.getSize();
      const out = new Uint8Array(size);
      const read = handle.read(out, { at: 0 });
      // A short read leaves the tail of `out` zeroed, indistinguishable from
      // staged data; reject rather than hand the engine a silently padded block.
      if (read !== size) {
        throw new StagingIoError(`staged read truncated: read ${read} of ${size} bytes`);
      }
      return out;
    } finally {
      handle.close();
    }
  }

  async removeStagedBytes(stagingKey: Uint8Array): Promise<void> {
    // Hex the key before the first await: a WASM-backed view detached by a
    // concurrent `Memory.grow()` across the await would hex to '' (#717).
    const fileName = toHex(stagingKey);
    const dir = await this.stagedDir();
    await removeIfPresent(dir, fileName);
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
