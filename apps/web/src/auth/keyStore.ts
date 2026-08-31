/**
 * Where a WebCrypto key handle lives: one structured-cloneable record in its own
 * IndexedDB database. The handle survives a structured clone; the bytes of a
 * non-extractable key do not, which is the whole reason the handle is the thing
 * that is stored.
 */

/** A single record, read back only when it is still the shape that was written. */
export interface KeyRecordStore<T> {
  read(): Promise<T | null>;
  write(value: T): Promise<void>;
  clear(): Promise<void>;
}

/** Which database, store and key one record occupies. */
export interface KeyRecordLocation {
  database: string;
  version: number;
  store: string;
  id: string;
}

/**
 * `held` is what makes the read fail closed: anything else on that key — an
 * older shape, or a record another build wrote — reads as absent, and the
 * caller mints rather than using it.
 */
export function indexedDbRecord<T>(
  at: KeyRecordLocation,
  held: (value: unknown) => value is T
): KeyRecordStore<T> {
  return {
    read: async () => {
      const value: unknown = await transact(at, 'readonly', (store) => store.get(at.id));
      return held(value) ? value : null;
    },
    write: async (value) => {
      await transact(at, 'readwrite', (store) => store.put(value, at.id));
    },
    clear: async () => {
      await transact(at, 'readwrite', (store) => store.delete(at.id));
    },
  };
}

function openDatabase(at: KeyRecordLocation): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(at.database, at.version);
    request.onupgradeneeded = () => request.result.createObjectStore(at.store);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error(`${at.database} is shut`));
    // An open that neither succeeds nor errors would strand the lock its caller
    // holds, and every tab on the origin queues behind it at login.
    request.onblocked = () => reject(new Error(`${at.database} is held open`));
  });
}

/**
 * Settled on the commit rather than on the request, so a transaction that
 * aborts after its write succeeded is reported. A caller that erases a key is
 * told the truth about whether the durable state changed.
 */
async function transact<T>(
  at: KeyRecordLocation,
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> {
  const database = await openDatabase(at);
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(at.store, mode);
      const request = run(transaction.objectStore(at.store));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onabort = () =>
        reject(transaction.error ?? new Error(`${at.store} did not commit`));
      request.onerror = () => reject(request.error ?? new Error(`${at.store} refused`));
    });
  } finally {
    database.close();
  }
}
