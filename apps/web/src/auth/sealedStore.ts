/**
 * The Core Kit store, sealed at rest.
 *
 * What the SDK keeps under `corekit_store` is a secp256k1 scalar that both
 * addresses and decrypts the Web3Auth record holding the login secret — the
 * root of the hierarchy in `blueprint/core.md`, so no rotation demotes it. This
 * seals it under an AES-GCM key WebCrypto will not export.
 *
 * What that buys is narrow, and worth stating so nothing is relaxed on the
 * strength of it: it defeats a reader of `localStorage` alone — a scraping
 * extension, a partial backup, a grep over a disk image. `extractable: false`
 * bars export to script, not presence on disk, so a whole-profile copy carries
 * the IndexedDB key with it; and script on this origin can open that database
 * and call the handle without going through this module at all.
 */

import type { LockManagerLike } from '@cipherbox/client';

const DB_NAME = 'cipherbox-corekit';
const DB_VERSION = 1;
const KEY_STORE = 'wrapping-keys';
const KEY_ID = 'corekit-store';

/** Tabs cold-start together; the loser of an unserialised race would overwrite the key. */
const WRAPPING_KEY_LOCK = 'cipherbox-corekit-wrapping-key';

const IV_BYTES = 12;

/** Bumped when the envelope shape changes. An older one is dropped, never migrated. */
const ENVELOPE_VERSION = 1;

/** Where the wrapping key lives. Its handle is storable; its bytes are not. */
export interface WrappingKeyStore {
  read(): Promise<CryptoKey | null>;
  write(key: CryptoKey): Promise<void>;
  clear(): Promise<void>;
}

/**
 * `IAsyncStorage` for the Core Kit SDK, which awaits every store read and write.
 * A value it cannot open is dropped rather than surfaced, so an evicted key or a
 * store written before this wrapper costs one re-login, not a wedged app.
 */
export class SealedStore {
  private wrapping: Promise<CryptoKey> | null = null;

  constructor(
    private readonly storage: Storage,
    private readonly keys: WrappingKeyStore,
    private readonly locks: LockManagerLike
  ) {}

  async getItem(key: string): Promise<string | null> {
    const raw = this.storage.getItem(key);
    if (raw === null) return null;
    const envelope = decodeEnvelope(raw);
    if (envelope === null) {
      // A store written before this wrapper is a bearer capability sitting in
      // the clear, so reading it is also the chance to be rid of it.
      this.storage.removeItem(key);
      return null;
    }
    // Resolved before the decrypt, so a key store that is merely unreachable
    // fails the read rather than discarding a session it could still open.
    let opened = await this.unseal(key, envelope, await this.wrappingKey());
    if (opened === null) {
      // Another tab can have re-keyed the store since this one resolved its
      // key, so a memo is not evidence the value is unopenable.
      this.wrapping = null;
      opened = await this.unseal(key, envelope, await this.wrappingKey());
    }
    if (opened === null) this.storage.removeItem(key);
    return opened;
  }

  async setItem(key: string, value: string): Promise<void> {
    const wrapping = await this.wrappingKey();
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: context(key) },
      wrapping,
      new TextEncoder().encode(value)
    );
    this.storage.setItem(key, encodeEnvelope(iv, new Uint8Array(sealed)));
  }

  /** `null` for anything the key does not authenticate under this envelope. */
  private async unseal(
    key: string,
    envelope: Envelope,
    wrapping: CryptoKey
  ): Promise<string | null> {
    try {
      const opened = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: envelope.iv, additionalData: context(key) },
        wrapping,
        envelope.sealed
      );
      return new TextDecoder().decode(opened);
    } catch {
      return null;
    }
  }

  /**
   * Drops the sealed value and the key that opens it. The value goes first: once
   * it is gone the key opens nothing, so a key store that refuses still leaves
   * this device with no session to steal.
   */
  async purge(key: string): Promise<void> {
    this.storage.removeItem(key);
    this.wrapping = null;
    await this.keys.clear().catch(() => undefined);
  }

  private async wrappingKey(): Promise<CryptoKey> {
    const pending = (this.wrapping ??= this.loadOrMint());
    try {
      return await pending;
    } catch (failure) {
      // A rejected load must not be remembered, or every later read replays it.
      if (this.wrapping === pending) this.wrapping = null;
      throw failure;
    }
  }

  private async loadOrMint(): Promise<CryptoKey> {
    let key: CryptoKey | undefined;
    await this.locks.request(WRAPPING_KEY_LOCK, { mode: 'exclusive' }, async () => {
      key = (await this.keys.read()) ?? undefined;
      if (key !== undefined) return;
      const minted = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ]);
      await this.keys.write(minted);
      key = minted;
    });
    if (key === undefined) throw new Error('the Core Kit store has no wrapping key');
    return key;
  }
}

/** The wrapping key in IndexedDB: the handle survives a structured clone, the bytes do not. */
export function indexedDbWrappingKeys(): WrappingKeyStore {
  return {
    read: async () => {
      const held: unknown = await transact('readonly', (store) => store.get(KEY_ID));
      return held instanceof CryptoKey ? held : null;
    },
    write: async (key) => {
      await transact('readwrite', (store) => store.put(key, KEY_ID));
    },
    clear: async () => {
      await transact('readwrite', (store) => store.delete(KEY_ID));
    },
  };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => request.result.createObjectStore(KEY_STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('the wrapping-key database is shut'));
    // An open that neither succeeds nor errors would strand the wrapping-key
    // lock, and every tab on the origin queues behind it at login.
    request.onblocked = () => reject(new Error('the wrapping-key database is held open'));
  });
}

async function transact<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>
): Promise<T> {
  const database = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = run(database.transaction(KEY_STORE, mode).objectStore(KEY_STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error('the wrapping-key store refused'));
    });
  } finally {
    database.close();
  }
}

interface Envelope {
  iv: Uint8Array<ArrayBuffer>;
  sealed: Uint8Array<ArrayBuffer>;
}

/**
 * What the ciphertext is authenticated against. The version travels outside the
 * sealed bytes, so binding it here is what stops a v1 envelope relabelled `v2`
 * from opening under a future build's semantics; the storage key stops one slot's
 * ciphertext from being transplanted into another.
 */
function context(key: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`cipherbox:sealed-store:v${ENVELOPE_VERSION}:${key}`);
}

function encodeEnvelope(iv: Uint8Array, sealed: Uint8Array): string {
  return JSON.stringify({ v: ENVELOPE_VERSION, iv: toBase64(iv), ct: toBase64(sealed) });
}

/** `null` for anything this build does not recognise, which the caller drops. */
function decodeEnvelope(raw: string): Envelope | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) return null;
  const { v, iv, ct } = parsed as { v?: unknown; iv?: unknown; ct?: unknown };
  if (v !== ENVELOPE_VERSION || typeof iv !== 'string' || typeof ct !== 'string') return null;
  try {
    return { iv: fromBase64(iv), sealed: fromBase64(ct) };
  } catch {
    return null;
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (character) => character.charCodeAt(0));
}
