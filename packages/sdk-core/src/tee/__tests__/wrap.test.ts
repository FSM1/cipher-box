/**
 * Round-trip test for wrapIpnsKeyForTee (bytes-in/bytes-out, 77-05).
 *
 * Proves the ECIES round-trip still holds after the signature change from
 * `(ipnsPrivateKey: Uint8Array, currentPublicKey: string): Promise<string>`
 * to `(ipnsPrivateKey: Uint8Array, teePublicKey: Uint8Array): Promise<Uint8Array>` —
 * no hex encoding/decoding inside the helper, hex lives only at the 3 call
 * sites (folder/registration.ts, vault/index.ts, file/index.ts).
 */

import { describe, it, expect } from 'vitest';
import * as secp256k1 from '@noble/secp256k1';
import { unwrapKey, generateRandomBytes } from '@cipherbox/crypto';
import { wrapIpnsKeyForTee } from '../wrap';

/** Generate a secp256k1 keypair — matches the TEE's real key type (apps/tee-worker). */
function generateTeeTestKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed
  return { publicKey, privateKey };
}

describe('wrapIpnsKeyForTee (bytes-in/bytes-out)', () => {
  it('round-trips a 32-byte ipnsPrivateKey through ECIES wrap/unwrap', async () => {
    const teeKeypair = generateTeeTestKeypair();
    const ipnsPrivateKey = generateRandomBytes(32);

    const wrapped = await wrapIpnsKeyForTee(ipnsPrivateKey, teeKeypair.publicKey);

    expect(wrapped).toBeInstanceOf(Uint8Array);

    const unwrapped = await unwrapKey(wrapped, teeKeypair.privateKey);

    expect(unwrapped).toEqual(ipnsPrivateKey);
  });
});
