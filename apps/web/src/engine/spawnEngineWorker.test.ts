import { describe, expect, it } from 'vitest';
import type { EngineBootstrapConfig } from './config';
import { spawnEngineWorker } from './spawnEngineWorker';

const config: EngineBootstrapConfig = {
  recordEndpoints: ['https://routing.example.test'],
  mailboxUrl: 'https://api.example.test/mailbox',
  wasmModuleUrl: '/wasm/cipherbox_wasm.js',
  wasmBinaryUrl: '/wasm/cipherbox_wasm_bg.wasm',
};

describe('spawnEngineWorker', () => {
  it('completes the bootstrap handshake before returning the worker', () => {
    const posted: unknown[] = [];
    const worker = {
      postMessage: (message: unknown) => posted.push(message),
    } as unknown as Worker;

    const spawned = spawnEngineWorker(config, () => worker);

    expect(spawned).toBe(worker);
    expect(posted).toEqual([{ type: 'bootstrap', ...config }]);
  });
});
