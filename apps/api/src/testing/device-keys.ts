import { generateKeyPairSync, KeyObject, sign } from 'node:crypto';

/** A throwaway Ed25519 device identity key, in the wire shape the API expects. */
export interface TestDeviceKey {
  /** Raw 32-byte public key, lowercase hex. */
  publicKey: string;
  /** Lowercase-hex Ed25519 signature over `message`. */
  sign(message: Buffer): string;
}

/**
 * Mint a device identity key for the suites. The browser holds this key in
 * WebCrypto; here it is a plain Node keypair, because what is under test is the
 * verification side of the exchange, not the custody.
 */
export function createTestDeviceKey(): TestDeviceKey {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: rawPublicKeyHex(publicKey),
    sign: (message) => sign(null, message, privateKey).toString('hex'),
  };
}

/** The last 32 bytes of the SPKI DER are the raw subjectPublicKey (RFC 8410 §4). */
function rawPublicKeyHex(publicKey: KeyObject): string {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return der.subarray(der.length - 32).toString('hex');
}
