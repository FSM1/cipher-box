/**
 * Shared message types for the encryption Web Worker protocol.
 *
 * Extracted to a separate file so the main-thread service can import
 * these types without pulling in the worker's WebWorker lib references.
 */

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
