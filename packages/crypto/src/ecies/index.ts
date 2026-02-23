/**
 * @cipherbox/crypto - ECIES Module
 *
 * ECIES (Elliptic Curve Integrated Encryption Scheme) key wrapping using secp256k1.
 * Used to wrap file keys with user's VaultKey public key.
 */

export { wrapKey } from './encrypt';
export { unwrapKey } from './decrypt';
export { reWrapKey } from './rewrap';
