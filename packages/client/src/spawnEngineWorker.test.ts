import { describe, expect, it } from 'vitest';
import { spawnEngineWorker, type EngineHostConfig } from './spawnEngineWorker.js';

const config: EngineHostConfig = {
  apiBaseUrl: 'https://api.example.test/',
  recordEndpoints: ['https://routing.example.test'],
  acceleratorBaseUrl: 'https://accelerator.example.test',
  publicGateways: ['https://gateway.example.test'],
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
    // Every config field reaches the worker, not just the ones spelled out here.
    expect(posted).toEqual([{ type: 'bootstrap', ...config }]);
  });
});
