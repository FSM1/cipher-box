/**
 * The browser seams the WebCrypto custody stores sit on: jsdom has neither
 * IndexedDB nor the Web Locks API, so both are substituted while WebCrypto —
 * the part under test — stays real.
 */

import type { LockGrant, LockManagerLike } from '@cipherbox/client';
import {
  DeviceIdentity,
  type DeviceIdentityStore,
  type DeviceKeyStore,
} from '../auth/deviceIdentity';
import type { KeyRecordStore } from '../auth/keyStore';
import { SealedStore, type WrappingKeyStore } from '../auth/sealedStore';

export class MemoryRecords<T> implements KeyRecordStore<T> {
  held: T | null = null;
  writes = 0;
  /** Set to model a key store that is present but unreachable. */
  refusal: Error | null = null;

  read(): Promise<T | null> {
    return this.refusal ? Promise.reject(this.refusal) : Promise.resolve(this.held);
  }

  write(value: T): Promise<void> {
    this.writes += 1;
    this.held = value;
    return Promise.resolve();
  }

  clear(): Promise<void> {
    if (this.refusal) return Promise.reject(this.refusal);
    this.held = null;
    return Promise.resolve();
  }
}

export class MemoryKeys extends MemoryRecords<CryptoKey> {}

export class MemoryDeviceKeys extends MemoryRecords<CryptoKeyPair> {}

/** One holder at a time, which is the only guarantee either key needs. */
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

/** A device identity over a store this test can seed and read back. */
export function deviceIdentityTestInstance(
  keys: DeviceKeyStore = new MemoryDeviceKeys(),
  locks: LockManagerLike = new SerialLocks()
): DeviceIdentity {
  return new DeviceIdentity(keys, locks, 'test-device-identity');
}

/**
 * The per-subject store, over one memory record per subject, so a test can prove
 * that two subjects on one browser never share a key.
 */
export function deviceIdentitiesTestInstance(
  locks: LockManagerLike = new SerialLocks()
): DeviceIdentityStore & { keysFor(subject: string): MemoryDeviceKeys } {
  const stores = new Map<string, MemoryDeviceKeys>();
  const keysFor = (subject: string): MemoryDeviceKeys => {
    const held = stores.get(subject) ?? new MemoryDeviceKeys();
    stores.set(subject, held);
    return held;
  };
  return {
    keysFor,
    forSubject: (subject) => new DeviceIdentity(keysFor(subject), locks, `test/${subject}`),
  };
}
