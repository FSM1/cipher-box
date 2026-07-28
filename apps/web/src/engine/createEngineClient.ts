import { EngineClient, spawnEngineWorker } from '@cipherbox/client';
import { engineHostConfig } from './config';
// `?url` hands the engine worker the artifact's built URL instead of inlining
// it here: Vite emits both files as content-hashed assets, so the artifact is
// fingerprinted and served immutable (blueprint/web-client.md "WASM packaging").
import wasmModuleUrl from '../wasm/cipherbox_wasm.js?url';
import wasmBinaryUrl from '../wasm/cipherbox_wasm_bg.wasm?url';

/**
 * Wires this tab's engine client to the browser: `navigator.locks` drives the
 * leader election, and the leader hosts the engine worker
 * (blueprint/web-client.md "Engine hosting and tab leadership").
 */
export function createEngineClient(): EngineClient {
  const host = engineHostConfig(import.meta.env, { wasmModuleUrl, wasmBinaryUrl });
  return new EngineClient({
    locks: navigator.locks,
    spawnWorker: () => spawnEngineWorker(host),
    onError: (error) => console.error('[engine]', error.message),
  });
}
