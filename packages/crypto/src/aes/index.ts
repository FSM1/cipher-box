/**
 * @cipherbox/crypto - AES Module
 *
 * AES-256-GCM encryption and decryption for file content and folder metadata.
 * AES-256-CTR encryption and decryption for streaming media content.
 */

export { encryptAesGcm, encryptAesGcmAad } from './encrypt';
export { decryptAesGcm, decryptAesGcmAad } from './decrypt';
export { sealAesGcm, unsealAesGcm, sealAesGcmAad, unsealAesGcmAad, buildNodeAad } from './seal';
export { encryptAesCtr } from './encrypt-ctr';
export { decryptAesCtr, decryptAesCtrRange } from './decrypt-ctr';
// Internal helper, exported from the aes barrel for test access only —
// intentionally NOT re-exported from the top-level package index.
export { importAesKey } from './import-key';
