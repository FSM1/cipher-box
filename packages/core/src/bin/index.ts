/**
 * @cipherbox/core - Recycle Bin Metadata Module
 *
 * Crypto primitives for the encrypted recycle bin:
 * - Types for bin metadata schema
 * - Runtime validation
 * - ECIES encryption/decryption
 * - Deterministic IPNS keypair derivation
 */

export type { BinEntry, RecycleBinMetadata } from './types';

export { validateBinMetadata } from './schema';
export { encryptBinMetadata, decryptBinMetadata } from './encrypt';
export { deriveBinIpnsKeypair } from './derive-ipns';
