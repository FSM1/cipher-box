/**
 * @cipherbox/crypto - Device Registry Module
 *
 * Crypto primitives for the encrypted device registry:
 * - Types for registry schema
 * - Runtime validation
 * - ECIES encryption/decryption
 * - Deterministic IPNS keypair derivation
 */

export type { DeviceAuthStatus, DevicePlatform, DeviceEntry, DeviceRegistry } from './types';

export { validateDeviceRegistry } from './schema';
export { encryptRegistry, decryptRegistry } from './encrypt';
export { deriveRegistryIpnsKeypair } from './derive-ipns';
