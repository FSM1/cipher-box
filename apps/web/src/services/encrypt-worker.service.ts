import type { ExternalEncryptFn } from '@cipherbox/sdk-core';
import type { EncryptRequest, EncryptResponse } from '../workers/encrypt.types';

/**
 * Main-thread wrapper for the encryption Web Worker.
 *
 * Creates one Worker instance lazily on first use and reuses it for all
 * encryption operations. Each encrypt() call sends a message with a
 * correlation ID and returns a Promise resolved by the matching response.
 *
 * Uses Transferable ArrayBuffer transfers in both directions to avoid
 * copying large file data between threads.
 */
export class EncryptionWorkerService {
  private worker: Worker | null = null;
  private pending = new Map<
    string,
    {
      resolve: (value: Awaited<ReturnType<ExternalEncryptFn>>) => void;
      reject: (reason: Error) => void;
    }
  >();
  private idCounter = 0;

  /** Lazily create the Worker on first use. */
  private getWorker(): Worker {
    if (!this.worker) {
      // Static string literal required for Vite static analysis
      this.worker = new Worker(new URL('../workers/encrypt.worker.ts', import.meta.url), {
        type: 'module',
      });
      this.worker.onmessage = (event: MessageEvent<EncryptResponse>) => {
        const response = event.data;
        const entry = this.pending.get(response.id);
        if (!entry) return;
        this.pending.delete(response.id);

        if (response.type === 'error') {
          entry.reject(new Error(response.error));
        } else {
          entry.resolve({
            ciphertext: response.ciphertext,
            wrappedKey: response.wrappedKey,
            iv: response.iv,
            fileKey: response.fileKey,
            originalSize: response.originalSize,
            encryptedSize: response.encryptedSize,
          });
        }
      };
      this.worker.onerror = (event) => {
        // Reject all pending operations on worker crash
        for (const [, entry] of this.pending) {
          entry.reject(new Error(`Worker error: ${event.message}`));
        }
        this.pending.clear();
      };
    }
    return this.worker;
  }

  /**
   * Encrypt file data in the Web Worker.
   *
   * Transfers the data ArrayBuffer to the Worker (zero-copy) and receives
   * the ciphertext ArrayBuffer back (zero-copy). After calling this, the
   * original `data` Uint8Array becomes zero-length (transferred).
   */
  encrypt(params: Parameters<ExternalEncryptFn>[0]): ReturnType<ExternalEncryptFn> {
    return new Promise((resolve, reject) => {
      this.idCounter += 1;
      const id = `enc-${this.idCounter}-${Date.now()}`;
      this.pending.set(id, { resolve, reject });

      const worker = this.getWorker();
      const message: EncryptRequest = {
        type: 'encrypt',
        id,
        data: params.data,
        userPublicKey: params.userPublicKey,
        encryptionMode: params.encryptionMode,
      };

      // Transfer the data buffer to worker (zero-copy, original becomes empty).
      // If data is a subview, copy first — transferring .buffer would detach
      // the entire underlying ArrayBuffer beyond the intended range.
      const isFullBuffer =
        params.data.byteOffset === 0 &&
        params.data.byteLength === params.data.buffer.byteLength;
      const transferData = isFullBuffer ? params.data : params.data.slice();
      message.data = transferData;
      worker.postMessage(message, [transferData.buffer] as Transferable[]);
    });
  }

  /**
   * Build an ExternalEncryptFn compatible with sdkCore.uploadFile's encryptFn param.
   * This is the function passed to client.uploadFiles({ encryptFn }).
   */
  createEncryptFn(): ExternalEncryptFn {
    return (params) => this.encrypt(params);
  }

  /**
   * Terminate the Worker and reject all pending operations.
   * Call on logout or SDK client destroy.
   */
  destroy(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    for (const [, entry] of this.pending) {
      entry.reject(new Error('EncryptionWorkerService destroyed'));
    }
    this.pending.clear();
  }
}

/** Singleton instance. Created lazily, destroyed on logout. */
let instance: EncryptionWorkerService | null = null;

export function getEncryptionWorker(): EncryptionWorkerService {
  if (!instance) {
    instance = new EncryptionWorkerService();
  }
  return instance;
}

export function destroyEncryptionWorker(): void {
  if (instance) {
    instance.destroy();
    instance = null;
  }
}
