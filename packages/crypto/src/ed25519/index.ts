/**
 * @cipherbox/crypto - Ed25519 Module
 *
 * Ed25519 key generation, signing, and verification for IPNS operations.
 */

export { generateEd25519Keypair, type Ed25519Keypair } from './keygen';
export { signEd25519, verifyEd25519 } from './sign';
