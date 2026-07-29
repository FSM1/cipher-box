import { EngineClient, spawnEngineWorker, type SecretSource } from '@cipherbox/client';
import { engineHostConfig } from './config';
// Content-hashed by Vite, so the artifact is served immutable
// (blueprint/web-client.md "WASM packaging").
import wasmModuleUrl from '../wasm/cipherbox_wasm.js?url';
import wasmBinaryUrl from '../wasm/cipherbox_wasm_bg.wasm?url';

/**
 * Wires this tab's engine client to the browser: `navigator.locks` drives the
 * leader election, and the leader hosts the engine worker
 * (blueprint/web-client.md "Engine hosting and tab leadership").
 */
export function createEngineClient(secretSource: SecretSource): EngineClient {
  const host = engineHostConfig(import.meta.env, { wasmModuleUrl, wasmBinaryUrl });
  return new EngineClient({
    locks: navigator.locks,
    spawnWorker: () => spawnEngineWorker(host),
    secretSource,
    onError: (error) => console.error('[engine]', error.message),
  });
}
