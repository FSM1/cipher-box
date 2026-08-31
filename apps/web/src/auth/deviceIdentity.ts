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
const DEVICE_KEY_DATABASE = {
  database: 'cipherbox-device-identity',
  version: 1,
  store: 'identity-keys',
} as const;

/**
 * One key per identity subject, never one per browser.
 *
 * The registry declares `public_key` unique across every account, so two
 * members on one browser would collide on a shared key and the second could
 * never register. A key that outlived one account and joined another would also
 * hand the server a stable pseudonym linking them, which is a correlation this
 * product gives it nowhere else.
 *
 * The subject is named by a digest, never in the clear: for the email verifier
 * it is an email address, and a record key holding one would leave any script on
 * this origin an enumerable list of every member who signed in here. A digest
 * for a record name derives no key and touches no wire format, so it stays
 * inside the rule 4 exception.
 */
async function subjectTag(subject: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(subject));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * The record and the lock one subject occupies. Both wait on the same digest,
 * so a caller holds the lock that guards the record it is about to read.
 */
export async function deviceKeyPlace(
  subject: string
): Promise<{ record: KeyRecordLocation; lock: string }> {
  const tag = await subjectTag(subject);
  return {
    record: { ...DEVICE_KEY_DATABASE, id: `device-identity/${tag}` },
    lock: `cipherbox-device-identity/${tag}`,
  };
}

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
 * The identity key one subject holds on this browser. Minted on first use
 * rather than at boot, so a visitor who never signs in is never given a durable
 * device identifier.
 *
 * Every use reads the store under the lock rather than keeping the pair in
 * hand, so an erase in one tab is not outlived by another tab's copy.
 */
export class DeviceIdentity {
  /**
   * The store and the lock name may still be settling: naming a subject means
   * digesting it, and every use awaits both before it touches either.
   */
  constructor(
    private readonly keys: DeviceKeyStore | Promise<DeviceKeyStore>,
    private readonly locks: LockManagerLike,
    private readonly lockName: string | Promise<string>
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
    return this.exclusively(async () => (await this.keys).clear());
  }

  private keyPair(): Promise<CryptoKeyPair> {
    return this.exclusively(async () => {
      const keys = await this.keys;
      const stored = await keys.read();
      if (stored !== null && (await heldInCustody(stored))) return stored;
      const minted = await mint();
      await keys.write(minted);
      return minted;
    });
  }

  private async exclusively<T>(run: () => Promise<T>): Promise<T> {
    let outcome: { value: T } | undefined;
    await this.locks.request(await this.lockName, { mode: 'exclusive' }, async () => {
      outcome = { value: await run() };
    });
    if (outcome === undefined) throw new Error('the device identity lock was not granted');
    return outcome.value;
  }
}

/** Where this browser keeps one identity key per subject it has signed in as. */
export interface DeviceIdentityStore {
  forSubject(subject: string): DeviceIdentity;
}

/** This origin's identity keys: the handles in IndexedDB, the private bytes nowhere. */
export function webDeviceIdentities(): DeviceIdentityStore {
  return {
    forSubject: (subject) => {
      const place = deviceKeyPlace(subject);
      return new DeviceIdentity(
        place.then(({ record }) => indexedDbRecord(record, isKeyPair)),
        navigator.locks,
        place.then(({ lock }) => lock)
      );
    },
  };
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
 * so every signature it makes is refused.
 *
 * Only a proven custody failure answers `false`. A WebCrypto that cannot run
 * the probe at all is reported, because a replacement there would discard an
 * identity the account has already approved.
 */
async function heldInCustody(pair: CryptoKeyPair): Promise<boolean> {
  if (pair.privateKey.extractable) return false;
  try {
    const signature = await crypto.subtle.sign(ALGORITHM, pair.privateKey, PROBE);
    return await crypto.subtle.verify(ALGORITHM, pair.publicKey, signature, PROBE);
  } catch (cause) {
    // A key of another algorithm, or without the usage, is refused this way.
    if (cause instanceof DOMException && cause.name === 'InvalidAccessError') return false;
    throw new Error(UNUSABLE, { cause });
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
