import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';

/** A secp256k1 account identity key, with the public key in the hex forms the login routes take. */
export interface TestIdentity {
  privateKey: Uint8Array;
  /** Compressed, the form an account is keyed by. */
  publicKey: string;
  publicKeyUncompressed: string;
}

export function newIdentity(): TestIdentity {
  const privateKey = secp256k1.utils.randomPrivateKey();
  return {
    privateKey,
    publicKey: Buffer.from(secp256k1.getPublicKey(privateKey, true)).toString('hex'),
    publicKeyUncompressed: Buffer.from(secp256k1.getPublicKey(privateKey, false)).toString('hex'),
  };
}

/** The account key's signature over a challenge, in the form the login routes take. */
export function signChallenge(challenge: string, privateKey: Uint8Array): string {
  const hash = createHash('sha256').update(challenge, 'utf8').digest();
  return secp256k1.sign(hash, privateKey).toCompactHex();
}
