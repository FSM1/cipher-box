import { createPublicKey, verify } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  deviceIdentityTestInstance as identity,
  MemoryDeviceKeys,
  SerialLocks,
} from '../test/storeFakes';

/** What the device registry takes, and what a rendezvous signature must be. */
const PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/;
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;

const MESSAGE = new TextEncoder().encode('cipherbox/device-approval/request/v1');

/** The guidance a browser that cannot hold this key must give the member. */
const UNUSABLE = 'this browser cannot hold a device identity key — use your recovery phrase';

/** SPKI DER header for an id-Ed25519 subjectPublicKey (RFC 8410 §4). */
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Verifies exactly as the API does: the raw hex public key wrapped into SPKI,
 * then a plain Ed25519 verify. A key or signature this rejects is one the
 * device registry would reject too.
 */
function verifiesAsTheApiWould(
  publicKeyHex: string,
  signatureHex: string,
  message: Uint8Array<ArrayBuffer>
): boolean {
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]),
    format: 'der',
    type: 'spki',
  });
  return verify(null, message, key, Buffer.from(signatureHex, 'hex'));
}

const mintPair = async (extractable: boolean): Promise<CryptoKeyPair> =>
  (await crypto.subtle.generateKey({ name: 'Ed25519' }, extractable, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

let keys: MemoryDeviceKeys;

beforeEach(() => {
  keys = new MemoryDeviceKeys();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the device identity key', () => {
  it('mints nothing until a caller asks for the key', () => {
    identity(keys);

    expect(keys.writes).toBe(0);
    expect(keys.held).toBeNull();
  });

  it('signs so the API verifies it against the public key it reports', async () => {
    const device = identity(keys);

    const publicKey = await device.publicKeyHex();
    const signature = await device.sign(MESSAGE);

    expect(publicKey).toMatch(PUBLIC_KEY_HEX);
    expect(signature).toMatch(SIGNATURE_HEX);
    expect(verifiesAsTheApiWould(publicKey, signature, MESSAGE)).toBe(true);
  });

  it('signs each message distinctly, so a signature carries the message it was taken over', async () => {
    const device = identity(keys);
    const other = new TextEncoder().encode('cipherbox/device-approval/response/v1');

    const publicKey = await device.publicKeyHex();
    const signature = await device.sign(MESSAGE);

    expect(verifiesAsTheApiWould(publicKey, signature, other)).toBe(false);
  });

  it('mints a private half whose bytes cannot leave WebCrypto', async () => {
    await identity(keys).publicKeyHex();

    const privateKey = keys.held?.privateKey as CryptoKey;
    expect(privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', privateKey)).rejects.toThrow();
  });

  it('keeps one identity across uses, so a device does not change who it is', async () => {
    const device = identity(keys);

    const first = await device.publicKeyHex();
    const second = await device.publicKeyHex();

    expect(second).toBe(first);
    expect(keys.writes).toBe(1);
  });

  it('reads back the identity another instance on this origin minted', async () => {
    const locks = new SerialLocks();
    const first = await identity(keys, locks).publicKeyHex();

    await expect(identity(keys, locks).publicKeyHex()).resolves.toBe(first);
    expect(keys.writes).toBe(1);
  });

  it('mints one identity however many tabs cold-start at once', async () => {
    const locks = new SerialLocks();

    const minted = await Promise.all([
      identity(keys, locks).publicKeyHex(),
      identity(keys, locks).publicKeyHex(),
      identity(keys, locks).publicKeyHex(),
    ]);

    expect(new Set(minted).size).toBe(1);
    expect(keys.writes).toBe(1);
  });
});

describe('a store that no longer holds this device identity', () => {
  it('makes a cleared store a new device rather than a wedge', async () => {
    const device = identity(keys);
    const before = await device.publicKeyHex();

    await device.forget();

    const after = await device.publicKeyHex();
    expect(after).toMatch(PUBLIC_KEY_HEX);
    expect(after).not.toBe(before);
  });

  it('reports an erase the key store refused, rather than reporting a forget that did not happen', async () => {
    const device = identity(keys);
    await device.publicKeyHex();
    keys.refusal = new Error('the identity-key database is shut');

    await expect(device.forget()).rejects.toThrow('the identity-key database is shut');
  });

  it('replaces a record whose private half is extractable', async () => {
    keys.held = await mintPair(true);

    await identity(keys).publicKeyHex();

    expect(keys.held.privateKey.extractable).toBe(false);
  });

  /**
   * Halves from different pairs report one key while signing under another, so
   * the API refuses every signature. Left in place it is a permanent wedge.
   */
  it('replaces a record whose halves are not a pair', async () => {
    const [one, other] = await Promise.all([mintPair(false), mintPair(false)]);
    keys.held = { publicKey: one.publicKey, privateKey: other.privateKey };

    const device = identity(keys);
    const publicKey = await device.publicKeyHex();
    const signature = await device.sign(MESSAGE);

    expect(verifiesAsTheApiWould(publicKey, signature, MESSAGE)).toBe(true);
  });

  /**
   * A WebCrypto that cannot run the probe proves nothing about the stored pair.
   * A replacement there would discard an identity the account already approved.
   */
  it('reports a probe the browser refused, rather than replacing the stored key', async () => {
    const held = await mintPair(false);
    keys.held = held;
    vi.spyOn(crypto.subtle, 'sign').mockRejectedValue(new DOMException('busy', 'OperationError'));

    await expect(identity(keys).publicKeyHex()).rejects.toThrow(UNUSABLE);

    expect(keys.held).toBe(held);
    expect(keys.writes).toBe(0);
  });

  it('tells a browser with no Ed25519 to use its recovery phrase', async () => {
    vi.spyOn(crypto.subtle, 'generateKey').mockRejectedValue(
      new DOMException('unsupported', 'NotSupportedError')
    );

    await expect(identity(keys).publicKeyHex()).rejects.toThrow(UNUSABLE);
  });

  it('retries a load the key store refused once, rather than replaying the refusal', async () => {
    const device = identity(keys);
    keys.refusal = new Error('the identity-key database is shut');

    await expect(device.publicKeyHex()).rejects.toThrow('the identity-key database is shut');
    keys.refusal = null;

    await expect(device.publicKeyHex()).resolves.toMatch(PUBLIC_KEY_HEX);
  });

  it('does not outlive an erase another instance on this origin made', async () => {
    const locks = new SerialLocks();
    const warm = identity(keys, locks);
    const before = await warm.publicKeyHex();

    await identity(keys, locks).forget();

    await expect(warm.publicKeyHex()).resolves.not.toBe(before);
  });
});
