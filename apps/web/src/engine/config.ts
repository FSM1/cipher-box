import type { EngineHostConfig } from '@cipherbox/client';

const DEFAULT_API_URL = 'http://localhost:3000';
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';
const DEFAULT_WASM_MODULE_URL = '/wasm/cipherbox_wasm.js';
const DEFAULT_WASM_BINARY_URL = '/wasm/cipherbox_wasm_bg.wasm';

/** Reads the app's build-time environment into the engine host's configuration. */
export function engineHostConfig(env: Partial<ImportMetaEnv>): EngineHostConfig {
  return {
    apiBaseUrl: env.VITE_API_URL ?? DEFAULT_API_URL,
    recordEndpoints: (env.VITE_ROUTING_ENDPOINTS ?? DEFAULT_ROUTING_ENDPOINTS)
      .split(',')
      .map((endpoint) => endpoint.trim())
      .filter((endpoint) => endpoint.length > 0),
    wasmModuleUrl: env.VITE_WASM_MODULE_URL ?? DEFAULT_WASM_MODULE_URL,
    wasmBinaryUrl: env.VITE_WASM_BINARY_URL ?? DEFAULT_WASM_BINARY_URL,
  };
}
