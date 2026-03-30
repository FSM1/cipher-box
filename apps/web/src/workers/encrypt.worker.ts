/// <reference lib="webworker" />

// eciesjs (transitive dep of @cipherbox/crypto) uses Buffer globally.
// Workers don't inherit the main thread's polyfills, so import explicitly.
import { Buffer } from 'buffer';
globalThis.Buffer = Buffer;

import {
  generateFileKey,
  generateIv,
  generateCtrIv,
  encryptAesGcm,
  encryptAesCtr,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';

import type { EncryptRequest, EncryptResponse } from './encrypt.types';

self.onmessage = async (event: MessageEvent<EncryptRequest>) => {
  const { id, data, userPublicKey, encryptionMode } = event.data;
  let fileKey: Uint8Array | null = null;
  try {
    fileKey = generateFileKey();
    const iv = encryptionMode === 'CTR' ? generateCtrIv() : generateIv();

    const ciphertext =
      encryptionMode === 'CTR'
        ? await encryptAesCtr(data, fileKey, iv)
        : await encryptAesGcm(data, fileKey, iv);

    const wrappedKey = await wrapKey(fileKey, userPublicKey);

    // Copy fileKey before clearing — clearBytes must happen before postMessage
    // so the key material doesn't linger in Worker memory after transfer
    const fileKeyCopy = new Uint8Array(fileKey);
    clearBytes(fileKey);
    fileKey = null; // Prevent double-clear in finally

    const response: EncryptResponse = {
      type: 'success',
      id,
      ciphertext,
      wrappedKey: bytesToHex(wrappedKey),
      iv: bytesToHex(iv),
      fileKey: fileKeyCopy,
      originalSize: data.byteLength,
      encryptedSize: ciphertext.byteLength,
    };

    // Transfer ownership of large buffers (zero-copy)
    self.postMessage(response, [ciphertext.buffer, fileKeyCopy.buffer] as Transferable[]);
  } catch (err) {
    const response: EncryptResponse = {
      type: 'error',
      id,
      error: (err as Error).message,
    };
    self.postMessage(response);
  } finally {
    // Clear key material on any exit path (encrypt/wrap/postMessage failure)
    if (fileKey) {
      clearBytes(fileKey);
    }
  }
};
