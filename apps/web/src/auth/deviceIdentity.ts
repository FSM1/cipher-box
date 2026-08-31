/**
 * This device's identity key (ADR 0009 D4): the Ed25519 key that signs both
 * halves of a device-approval exchange, so an approval rests on a signature
 * rather than on a self-reported identifier.
 *
 * The second WebCrypto custody instance AGENTS.md rule 4 permits, and it needs
 * both halves of that exception. It must sign before `start(secret)` has given
 * the engine a session — a device asking to be approved is a device that cannot
 * yet reconstruct — and it must be non-extractable, which a WASM engine cannot
 * offer because its key bytes live in linear memory. It protects local state
 * only, derives nothing in the KDF catalog, and never leaves WebCrypto.
 */

import type { LockManagerLike } from '@cipherbox/client';
import { indexedDbRecord, type KeyRecordLocation, type KeyRecordStore } from './keyStore';

const ALGORITHM = 'Ed25519';

/** Raw Ed25519 sizes, which the device registry constrains to 64 and 128 hex characters. */
const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

/** The identity key's own database, separate from the Core Kit wrapping key's. */
const DEVICE_KEY_RECORD: KeyRecordLocation = {
  database: 'cipherbox-device-identity',
  version: 1,
  store: 'identity-keys',
  id: 'device-identity',
};

/** Tabs cold-start together; the loser of an unserialised race would overwrite the key. */
const DEVICE_KEY_LOCK = 'cipherbox-device-identity';

/**
 * What a device with no usable Ed25519 is told. Its way in is still open: the
 * recovery phrase is every account's guaranteed path (ADR 0009 D2).
 */
const UNUSABLE = 'this browser cannot hold a device identity key — use your recovery phrase';

/** What a stored pair is proved against. Ed25519 signs deterministically, so this seeds nothing. */
const PROBE = new TextEncoder().encode('cipherbox/device-identity/probe/v1');

/** Where the identity key lives. Its handle is storable; its private bytes are not. */
export type DeviceKeyStore = KeyRecordStore<CryptoKeyPair>;

/**
 * The identity key on one origin. Minted on first use rather than at boot, so a
 * visitor who never signs in is never given a durable device identifier.
 *
 * Every use reads the store under the lock rather than keeping the pair in
 * hand, so an erase in one tab is not outlived by another tab's copy.
 */
export class DeviceIdentity {
  constructor(
    private readonly keys: DeviceKeyStore,
    private readonly locks: LockManagerLike
  ) {}

  /** The raw public key, in the lowercase hex the device registry takes. */
  async publicKeyHex(): Promise<string> {
    const { publicKey } = await this.keyPair();
    return toHex(new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)), PUBLIC_KEY_BYTES);
  }

  /** An Ed25519 signature over `message`, in the lowercase hex the API verifies. */
  async sign(message: Uint8Array<ArrayBuffer>): Promise<string> {
    const { privateKey } = await this.keyPair();
    const signature = await crypto.subtle.sign(ALGORITHM, privateKey, message);
    return toHex(new Uint8Array(signature), SIGNATURE_BYTES);
  }

  /**
   * Erase this identity. The next use mints a key the account has never seen,
   * which is what makes a cleared store a new device rather than a wedge: it can
   * still open a rendezvous, and an approval registers it afresh.
   */
  forget(): Promise<void> {
    return this.exclusively(() => this.keys.clear());
  }

  private keyPair(): Promise<CryptoKeyPair> {
    return this.exclusively(async () => {
      const stored = await this.keys.read();
      if (stored !== null && (await heldInCustody(stored))) return stored;
      const minted = await mint();
      await this.keys.write(minted);
      return minted;
    });
  }

  private async exclusively<T>(run: () => Promise<T>): Promise<T> {
    let outcome: { value: T } | undefined;
    await this.locks.request(DEVICE_KEY_LOCK, { mode: 'exclusive' }, async () => {
      outcome = { value: await run() };
    });
    if (outcome === undefined) throw new Error('the device identity lock was not granted');
    return outcome.value;
  }
}

/** This origin's identity key: the handle in IndexedDB, the private bytes nowhere. */
export function webDeviceIdentity(): DeviceIdentity {
  return new DeviceIdentity(indexedDbDeviceKeys(), navigator.locks);
}

function indexedDbDeviceKeys(): DeviceKeyStore {
  return indexedDbRecord(DEVICE_KEY_RECORD, isKeyPair);
}

async function mint(): Promise<CryptoKeyPair> {
  try {
    return (await crypto.subtle.generateKey({ name: ALGORITHM }, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
  } catch (cause) {
    throw new Error(UNUSABLE, { cause });
  }
}

/** Whether a stored record is a key pair at all; the custody check is separate. */
function isKeyPair(value: unknown): value is CryptoKeyPair {
  if (typeof value !== 'object' || value === null) return false;
  const { publicKey, privateKey } = value as { publicKey?: unknown; privateKey?: unknown };
  return publicKey instanceof CryptoKey && privateKey instanceof CryptoKey;
}

/**
 * Whether a stored pair is one this module would mint and can still use. An
 * exportable private half is the property this custody exists to deny, and a
 * pair whose halves do not match reports one key while signing under another,
 * so every signature it makes is refused. Either is replaced by a fresh key,
 * which makes this a new device — the same defined path a cleared store takes.
 */
async function heldInCustody(pair: CryptoKeyPair): Promise<boolean> {
  if (pair.privateKey.extractable) return false;
  try {
    const signature = await crypto.subtle.sign(ALGORITHM, pair.privateKey, PROBE);
    return await crypto.subtle.verify(ALGORITHM, pair.publicKey, signature, PROBE);
  } catch {
    return false;
  }
}

/**
 * The produce side of the registry's hex constraints, checked here rather than
 * left to an opaque server refusal: a WebCrypto that answered with anything but
 * the raw Ed25519 size would otherwise be reported as a rejected registration.
 */
function toHex(bytes: Uint8Array, expected: number): string {
  if (bytes.length !== expected) throw new Error(UNUSABLE);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
