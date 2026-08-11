/**
 * The browser seams the sealed Core Kit store sits on: jsdom has neither
 * IndexedDB nor the Web Locks API, so both are substituted while WebCrypto —
 * the part under test — stays real.
 */

import type { LockGrant, LockManagerLike } from '@cipherbox/client';
import { SealedStore, type WrappingKeyStore } from '../auth/sealedStore';

export class MemoryKeys implements WrappingKeyStore {
  held: CryptoKey | null = null;
  writes = 0;
  /** Set to model a key store that is present but unreachable. */
  refusal: Error | null = null;

  read(): Promise<CryptoKey | null> {
    return this.refusal ? Promise.reject(this.refusal) : Promise.resolve(this.held);
  }

  write(key: CryptoKey): Promise<void> {
    this.writes += 1;
    this.held = key;
    return Promise.resolve();
  }

  clear(): Promise<void> {
    this.held = null;
    return Promise.resolve();
  }
}

/** One holder at a time, which is the only guarantee the wrapping key needs. */
export class SerialLocks implements LockManagerLike {
  private tail: Promise<unknown> = Promise.resolve();

  request(
    name: string,
    _options: unknown,
    callback: (lock: LockGrant | null) => Promise<unknown>
  ): Promise<unknown> {
    const granted: LockGrant = { name };
    const run = this.tail.then(() => callback(granted));
    this.tail = run.catch(() => undefined);
    return run;
  }
}

/** A sealed store over this origin's real `localStorage`. */
export function sealedTestStore(
  keys: WrappingKeyStore = new MemoryKeys(),
  locks: LockManagerLike = new SerialLocks()
): SealedStore {
  return new SealedStore(window.localStorage, keys, locks);
}
