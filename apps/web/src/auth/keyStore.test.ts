/**
 * The only suite that drives a real IndexedDB. Every other custody test
 * substitutes the store, so the persistence both WebCrypto keys sit on is
 * covered here or nowhere.
 */

import { IDBDatabase, IDBFactory } from 'fake-indexeddb';
import { beforeEach, describe, expect, it } from 'vitest';
import { indexedDbRecord, type KeyRecordLocation } from './keyStore';

const AT: KeyRecordLocation = {
  database: 'cipherbox-test-keys',
  version: 1,
  store: 'test-keys',
  id: 'the-key',
};

const isKey = (value: unknown): value is CryptoKey => value instanceof CryptoKey;

const minted = (): Promise<CryptoKey> =>
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);

beforeEach(() => {
  // A fresh factory per test, so no database outlives the case that made it.
  globalThis.indexedDB = new IDBFactory();
});

describe('a WebCrypto key handle in IndexedDB', () => {
  it('reads back the handle it wrote, with its bytes still unexportable', async () => {
    const store = indexedDbRecord(AT, isKey);
    const key = await minted();

    await store.write(key);

    const held = await store.read();
    expect(held?.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', held as CryptoKey)).rejects.toThrow();
  });

  it('reads a record it does not recognise as absent, so the caller mints', async () => {
    const store = indexedDbRecord(AT, isKey);
    await indexedDbRecord<string>(AT, (value): value is string => typeof value === 'string').write(
      'not a key'
    );

    await expect(store.read()).resolves.toBeNull();
  });

  it('reads an empty store as absent', async () => {
    await expect(indexedDbRecord(AT, isKey).read()).resolves.toBeNull();
  });

  it('erases the handle, and the erase is durable', async () => {
    const store = indexedDbRecord(AT, isKey);
    await store.write(await minted());

    await store.clear();

    await expect(store.read()).resolves.toBeNull();
  });

  /**
   * A write settled on the request rather than the commit reports a durable
   * change a later abort never made. The erase path is told the truth or the
   * member is told this device was forgotten when it was not.
   */
  it('refuses a write whose transaction aborts after the request succeeded', async () => {
    const store = indexedDbRecord(AT, isKey);
    const key = await minted();
    const opened = IDBDatabase.prototype.transaction;
    IDBDatabase.prototype.transaction = function abortingTransaction(this: IDBDatabase, ...args) {
      const transaction = opened.apply(this, args as Parameters<typeof opened>);
      queueMicrotask(() => transaction.abort());
      return transaction;
    };

    try {
      await expect(store.write(key)).rejects.toThrow();
    } finally {
      IDBDatabase.prototype.transaction = opened;
    }

    await expect(indexedDbRecord(AT, isKey).read()).resolves.toBeNull();
  });
});
