/// <reference lib="webworker" />

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

export type EncryptRequest = {
  type: 'encrypt';
  id: string;
  data: Uint8Array;
  userPublicKey: Uint8Array;
  encryptionMode: 'GCM' | 'CTR';
};

export type EncryptResponse =
  | {
      type: 'success';
      id: string;
      ciphertext: Uint8Array;
      wrappedKey: string;
      iv: string;
      fileKey: Uint8Array;
      originalSize: number;
      encryptedSize: number;
    }
  | {
      type: 'error';
      id: string;
      error: string;
    };

self.onmessage = async (event: MessageEvent<EncryptRequest>) => {
  const { id, data, userPublicKey, encryptionMode } = event.data;
  try {
    const fileKey = generateFileKey();
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
  }
};
