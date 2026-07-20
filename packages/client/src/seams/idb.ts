/**
 * A minimal promise wrapper over IndexedDB.
 *
 * The browser durable seams (`FloorStore`, `SnapshotCache`, the `StagingStore`
 * op queue) persist opaque engine-chosen bytes in IndexedDB. This module is
 * the only place that talks to the raw `IDBRequest` event API; the seams above
 * it work in promises. IndexedDB is *required* on web — there is no in-memory
 * fallback tier (blueprint/web-client.md seam table), so a store that cannot
 * open is a hard error surfaced to the caller, never a silent degrade.
 */

/** Resolves a single `IDBRequest` to its result, or rejects on its error. */
export function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

/** Resolves when a transaction commits, or rejects if it aborts/errors. */
export function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
  });
}

/**
 * Opens (creating on first use) an IndexedDB database, running `onUpgrade` to
 * declare its object stores. Every call returns a fresh connection over the
 * same durable backing — which is exactly the conformance kits' "reopen"
 * factory contract.
 */
export function openDatabase(
  name: string,
  version: number,
  onUpgrade: (db: IDBDatabase) => void
): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    // No fallback tier by design: an unavailable IndexedDB is an
    // unsupported-browser hard error, not a degraded mode.
    return Promise.reject(new Error('IndexedDB is unavailable in this realm'));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = () => onUpgrade(request.result);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB open failed'));
    request.onblocked = () => reject(new Error(`IndexedDB open blocked for "${name}"`));
  });
}

/** Deletes an entire database — used by the browser suite to start each kit's backing empty. */
export function deleteDatabase(name: string): Promise<void> {
  if (typeof indexedDB === 'undefined') {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error('IndexedDB delete failed'));
    request.onblocked = () => reject(new Error(`IndexedDB delete blocked for "${name}"`));
  });
}
