import { beforeEach, describe, expect, it } from 'vitest';
import { MemoryKeys, SerialLocks, sealedTestStore as sealed } from '../test/storeFakes';

const KEY = 'corekit_store';

/** Stands in for what the SDK writes; nothing here is real key material. */
const STORE_VALUE = '{"sessionId":"not-a-real-session-id"}';

const rawEnvelope = (): { v: number; iv: string; ct: string } =>
  JSON.parse(window.localStorage.getItem(KEY) ?? 'null') as { v: number; iv: string; ct: string };

beforeEach(() => {
  window.localStorage.clear();
});

describe('sealing the Core Kit store', () => {
  it('opens what it sealed', async () => {
    const store = sealed(new MemoryKeys());

    await store.setItem(KEY, STORE_VALUE);

    await expect(store.getItem(KEY)).resolves.toBe(STORE_VALUE);
  });

  it('leaves ciphertext in storage, never the value it was handed', async () => {
    await sealed(new MemoryKeys()).setItem(KEY, STORE_VALUE);

    const raw = window.localStorage.getItem(KEY) ?? '';
    expect(raw).not.toContain('sessionId');
    expect(raw).not.toContain('not-a-real-session-id');
    expect(rawEnvelope().v).toBe(1);
  });

  it('mints a wrapping key whose bytes cannot leave WebCrypto', async () => {
    const keys = new MemoryKeys();

    await sealed(keys).setItem(KEY, STORE_VALUE);

    const wrapping = keys.held;
    expect(wrapping?.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', wrapping as CryptoKey)).rejects.toThrow();
  });

  /**
   * Sealing under an exportable key would leave the Core Kit store openable by a
   * later read of IndexedDB alone, which is what this custody exists to deny.
   */
  it('replaces a stored wrapping key whose bytes can be exported', async () => {
    const keys = new MemoryKeys();
    keys.held = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);

    await sealed(keys).setItem(KEY, STORE_VALUE);

    expect(keys.held.extractable).toBe(false);
  });

  it('replaces a stored wrapping key of another algorithm', async () => {
    const keys = new MemoryKeys();
    keys.held = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);

    await sealed(keys).setItem(KEY, STORE_VALUE);

    expect(keys.held.algorithm.name).toBe('AES-GCM');
  });

  /**
   * A key without `encrypt` makes every seal throw, so a store left on it never
   * takes another write. Replacing it costs the one re-login a dropped store costs.
   */
  it('replaces a stored wrapping key that cannot seal', async () => {
    const keys = new MemoryKeys();
    keys.held = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'decrypt',
    ]);

    await sealed(keys).setItem(KEY, STORE_VALUE);

    expect(keys.held.usages).toContain('encrypt');
  });

  it('replaces a stored wrapping key of a shorter length', async () => {
    const keys = new MemoryKeys();
    keys.held = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, [
      'encrypt',
      'decrypt',
    ]);

    await sealed(keys).setItem(KEY, STORE_VALUE);

    expect((keys.held.algorithm as AesKeyAlgorithm).length).toBe(256);
  });

  it('seals each write under its own nonce', async () => {
    const store = sealed(new MemoryKeys());

    await store.setItem(KEY, STORE_VALUE);
    const first = rawEnvelope();
    await store.setItem(KEY, STORE_VALUE);
    const second = rawEnvelope();

    expect(second.iv).not.toBe(first.iv);
    expect(second.ct).not.toBe(first.ct);
  });

  it('reads back what another store on this origin sealed', async () => {
    const keys = new MemoryKeys();
    const locks = new SerialLocks();

    await sealed(keys, locks).setItem(KEY, STORE_VALUE);

    await expect(sealed(keys, locks).getItem(KEY)).resolves.toBe(STORE_VALUE);
  });

  it('re-reads the key store rather than trusting a memo another tab replaced', async () => {
    const keys = new MemoryKeys();
    const locks = new SerialLocks();
    const reader = sealed(keys, locks);
    await reader.setItem(KEY, STORE_VALUE);
    await reader.getItem(KEY);

    // The other tab logs out and back in, which re-keys the store under it.
    keys.held = null;
    await sealed(keys, locks).setItem(KEY, STORE_VALUE);

    await expect(reader.getItem(KEY)).resolves.toBe(STORE_VALUE);
  });

  it('mints one wrapping key however many tabs cold-start at once', async () => {
    const keys = new MemoryKeys();
    const locks = new SerialLocks();
    const first = sealed(keys, locks);
    const second = sealed(keys, locks);

    await Promise.all([first.setItem(KEY, STORE_VALUE), second.setItem(KEY, STORE_VALUE)]);

    expect(keys.writes).toBe(1);
    await expect(first.getItem(KEY)).resolves.toBe(STORE_VALUE);
  });
});

describe('a sealed store it cannot open', () => {
  it('drops a store written before the seal rather than leaving it readable', async () => {
    window.localStorage.setItem(KEY, STORE_VALUE);
    const keys = new MemoryKeys();

    await expect(sealed(keys).getItem(KEY)).resolves.toBeNull();

    expect(window.localStorage.getItem(KEY)).toBeNull();
    expect(keys.writes).toBe(0);
  });

  it('drops a value sealed under a wrapping key this device no longer has', async () => {
    const keys = new MemoryKeys();
    await sealed(keys).setItem(KEY, STORE_VALUE);
    keys.held = null;

    await expect(sealed(keys).getItem(KEY)).resolves.toBeNull();

    expect(window.localStorage.getItem(KEY)).toBeNull();
  });

  it('refuses ciphertext transplanted from another storage key', async () => {
    const keys = new MemoryKeys();
    await sealed(keys).setItem(KEY, STORE_VALUE);
    const envelope = window.localStorage.getItem(KEY) ?? '';
    window.localStorage.setItem('another_store', envelope);

    await expect(sealed(keys).getItem('another_store')).resolves.toBeNull();
  });

  it('drops an envelope from a version this build does not know', async () => {
    const keys = new MemoryKeys();
    await sealed(keys).setItem(KEY, STORE_VALUE);
    window.localStorage.setItem(KEY, JSON.stringify({ ...rawEnvelope(), v: 2 }));

    await expect(sealed(keys).getItem(KEY)).resolves.toBeNull();
    expect(window.localStorage.getItem(KEY)).toBeNull();
  });

  it('refuses ciphertext that was edited under the key that seals it', async () => {
    const keys = new MemoryKeys();
    await sealed(keys).setItem(KEY, STORE_VALUE);
    const envelope = rawEnvelope();
    const flipped = envelope.ct.startsWith('A')
      ? `B${envelope.ct.slice(1)}`
      : `A${envelope.ct.slice(1)}`;
    window.localStorage.setItem(KEY, JSON.stringify({ ...envelope, ct: flipped }));

    await expect(sealed(keys).getItem(KEY)).resolves.toBeNull();
  });

  it('fails the read rather than dropping a session when the key store is unreachable', async () => {
    const keys = new MemoryKeys();
    await sealed(keys).setItem(KEY, STORE_VALUE);
    const stored = window.localStorage.getItem(KEY);
    keys.refusal = new Error('the wrapping-key database is shut');

    await expect(sealed(keys).getItem(KEY)).rejects.toThrow('the wrapping-key database is shut');

    expect(window.localStorage.getItem(KEY)).toBe(stored);
  });

  it('retries the key store after a refusal rather than caching it', async () => {
    const keys = new MemoryKeys();
    const store = sealed(keys);
    keys.refusal = new Error('the wrapping-key database is shut');
    await expect(store.setItem(KEY, STORE_VALUE)).rejects.toThrow();

    keys.refusal = null;
    await store.setItem(KEY, STORE_VALUE);

    await expect(store.getItem(KEY)).resolves.toBe(STORE_VALUE);
  });
});

describe('purging the sealed store', () => {
  it('takes the value and the key that opens it', async () => {
    const keys = new MemoryKeys();
    const store = sealed(keys);
    await store.setItem(KEY, STORE_VALUE);

    await store.purge(KEY);

    expect(window.localStorage.getItem(KEY)).toBeNull();
    expect(keys.held).toBeNull();
  });

  it('clears the value even when the key store refuses to give up the key', async () => {
    const keys = new MemoryKeys();
    const store = sealed(keys);
    await store.setItem(KEY, STORE_VALUE);
    keys.clear = () => Promise.reject(new Error('the wrapping-key database is shut'));

    await store.purge(KEY);

    expect(window.localStorage.getItem(KEY)).toBeNull();
  });
});
