import { describe, expect, it } from 'vitest';
import { spawnEngineWorker, type EngineHostConfig } from './spawnEngineWorker.js';

const config: EngineHostConfig = {
  apiBaseUrl: 'https://api.example.test/',
  recordEndpoints: ['https://routing.example.test'],
  wasmModuleUrl: '/wasm/cipherbox_wasm.js',
  wasmBinaryUrl: '/wasm/cipherbox_wasm_bg.wasm',
};

function recordingWorker(posted: unknown[]): Worker {
  return { postMessage: (message: unknown) => posted.push(message) } as unknown as Worker;
}

describe('spawnEngineWorker', () => {
  it('bootstraps the worker before returning it', () => {
    const posted: unknown[] = [];
    const worker = recordingWorker(posted);

    expect(spawnEngineWorker(config, () => worker)).toBe(worker);
    expect(posted).toEqual([
      {
        type: 'bootstrap',
        recordEndpoints: ['https://routing.example.test'],
        mailboxUrl: 'https://api.example.test/mailbox/messages',
        dbPrefix: undefined,
        wasmModuleUrl: '/wasm/cipherbox_wasm.js',
        wasmBinaryUrl: '/wasm/cipherbox_wasm_bg.wasm',
        profile: undefined,
      },
    ]);
  });
});
