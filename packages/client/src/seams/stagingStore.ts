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

/** The op-queue object store, and the version its database is opened at. */
export const STAGING_OPS_STORE = 'ops';
export const STAGING_DB_VERSION = 1;

/**
 * Names an in-flight staged write. Staged records are named in hex, so no key
 * can collide with a temp, and enumeration skips temps: an unfinished write is
 * not a staged record, must not be charged to the staging budget, and must not
 * be handed to orphan GC as a key.
 */
const TEMP_PREFIX = '.cbtmp.';

/** The staged bytes sit in an OPFS directory named beside the op queue's database. */
export const STAGED_DIR_SUFFIX = '-staged';

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

/**
 * Every name directly in `dir`, collected before the caller removes any of
 * them: removing during the walk mutates what it iterates.
 */
async function namesIn(dir: FileSystemDirectoryHandle): Promise<string[]> {
  const names: string[] = [];
  for await (const name of dir.keys()) names.push(name);
  return names;
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
  private stagedDirectory: Promise<FileSystemDirectoryHandle> | undefined;

  constructor(name = 'cipherbox-staging') {
    this.dirName = `${name}${STAGED_DIR_SUFFIX}`;
    this.open = memoizedDatabase(name, STAGING_DB_VERSION, (db) => {
      // Out-of-line auto-incrementing keys are the OpId source: strictly
      // increasing, never reused, durable across reopen.
      db.createObjectStore(STAGING_OPS_STORE, { autoIncrement: true });
    });
  }

  private stagedDir(): Promise<FileSystemDirectoryHandle> {
    // A failed open must not poison the memo, or every later staged op on this
    // store fails with no retry path.
    this.stagedDirectory ??= this.openStagedDir().catch((error: unknown) => {
      this.stagedDirectory = undefined;
      throw error;
    });
    return this.stagedDirectory;
  }

  /** Opens the staged directory, once per store, sweeping the temps a killed
   * write left behind — enumeration skips them, so nothing else reclaims them. */
  private async openStagedDir(): Promise<FileSystemDirectoryHandle> {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(this.dirName, { create: true });
    const debris = (await namesIn(dir)).filter((name) => name.startsWith(TEMP_PREFIX));
    // Best-effort per entry, like the desktop sweep — a temp a killed writer
    // still holds open must not fail the open; the next one reclaims it.
    await Promise.all(debris.map((name) => removeIfPresent(dir, name).catch(() => undefined)));
    return dir;
  }

  /** The staged record names in `dir`; an in-flight temp is not a record. */
  private async *recordNames(dir: FileSystemDirectoryHandle): AsyncGenerator<string> {
    for await (const name of dir.keys()) {
      if (!name.startsWith(TEMP_PREFIX)) yield name;
    }
  }

  async enqueueOp(op: Uint8Array): Promise<number> {
    // Copy before the first await: `op` may be a view into WASM linear memory
    // that a concurrent task's `Memory.grow()` can detach across the await.
    const staged = op.slice();
    const db = await this.open();
    const tx = db.transaction(STAGING_OPS_STORE, 'readwrite');
    const key = await requestResult<IDBValidKey>(tx.objectStore(STAGING_OPS_STORE).add(staged));
    await transactionDone(tx);
    return Number(key);
  }

  async queuedOps(): Promise<Array<[number, Uint8Array]>> {
    const db = await this.open();
    const tx = db.transaction(STAGING_OPS_STORE, 'readonly');
    const store = tx.objectStore(STAGING_OPS_STORE);
    // getAllKeys and getAll both return in ascending-key (FIFO) order.
    const keys = await requestResult<IDBValidKey[]>(store.getAllKeys());
    const values = await requestResult<Uint8Array[]>(store.getAll());
    await transactionDone(tx);
    return keys.map((key, index) => [Number(key), values[index]] as [number, Uint8Array]);
  }

  async removeOp(opId: number): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(STAGING_OPS_STORE, 'readwrite');
    tx.objectStore(STAGING_OPS_STORE).delete(opId);
    await transactionDone(tx);
  }

  async putStagedBytes(stagingKey: Uint8Array, bytes: Uint8Array): Promise<void> {
    // Encode the key and copy the value before the first await: both may be
    // views into WASM linear memory that a concurrent task's `Memory.grow()`
    // can detach across the awaits below — a detached key hexes to '' and a
    // detached value truncates or throws on `handle.write`.
    const fileName = toHex(stagingKey);
    const staged = bytes.slice();
    const dir = await this.stagedDir();
    // Every byte lands in a temp the engine cannot see, and the rename is the
    // commit point: a constrained write (a short count, or the throw the spec
    // names QuotaExceededError) leaves the key's previous bytes untouched.
    const tempName = `${TEMP_PREFIX}${globalThis.crypto.randomUUID()}`;
    const tempHandle = await dir.getFileHandle(tempName, { create: true });
    const handle = await tempHandle.createSyncAccessHandle();
    let failure: { message: string; cause?: unknown } | undefined;
    try {
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
    if (!failure) {
      try {
        await tempHandle.move(fileName);
        return;
      } catch (error) {
        failure = { message: 'staged write commit failed', cause: error };
      }
    }
    const cleanupError = await removeIfPresent(dir, tempName).then(
      () => undefined,
      (error: unknown) => error
    );
    throw new StagingIoError(failure.message, { cause: failure.cause ?? cleanupError });
  }

  async stagedBytes(stagingKey: Uint8Array): Promise<Uint8Array | null> {
    // Hex the key before the first await: a WASM-backed view detached by a
    // concurrent `Memory.grow()` across the await would hex to ''.
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
    // concurrent `Memory.grow()` across the await would hex to ''.
    const fileName = toHex(stagingKey);
    const dir = await this.stagedDir();
    await removeIfPresent(dir, fileName);
  }

  async stagedKeys(): Promise<Uint8Array[]> {
    const dir = await this.stagedDir();
    const keys: Uint8Array[] = [];
    for await (const name of this.recordNames(dir)) {
      keys.push(fromHex(name));
    }
    return keys;
  }

  /**
   * Drops the queue and every staged record, in-flight temps included — a temp
   * holds the bytes a killed write was staging, so an erase that stepped over
   * it would leave that record behind. The queue goes first: the reverse order
   * would strand ops naming bytes that are already gone.
   *
   * IndexedDB resets a key generator only when its store is deleted, so
   * clearing leaves op ids strictly increasing and unreused.
   */
  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction(STAGING_OPS_STORE, 'readwrite');
    tx.objectStore(STAGING_OPS_STORE).clear();
    await transactionDone(tx);

    const dir = await this.stagedDir();
    await Promise.all((await namesIn(dir)).map((name) => removeIfPresent(dir, name)));
  }

  async stagedBytesTotal(): Promise<number> {
    const dir = await this.stagedDir();
    let total = 0;
    for await (const name of this.recordNames(dir)) {
      try {
        const fileHandle = await dir.getFileHandle(name);
        total += (await fileHandle.getFile()).size;
      } catch (error) {
        // A record removed between the walk and the stat contributes zero,
        // matching the desktop host rather than failing the budget read.
        if (error instanceof DOMException && error.name === 'NotFoundError') continue;
        throw error;
      }
    }
    return total;
  }
}
