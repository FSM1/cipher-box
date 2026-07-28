import type { EngineHostConfig } from '@cipherbox/client';

const DEFAULT_API_URL = 'http://localhost:3000';
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';

/** Where the bundler placed the engine's WASM artifact; not environment-configurable. */
export type WasmArtifactUrls = Pick<EngineHostConfig, 'wasmModuleUrl' | 'wasmBinaryUrl'>;

/** Reads the app's build-time environment into the engine host's configuration. */
export function engineHostConfig(
  env: Partial<ImportMetaEnv>,
  artifact: WasmArtifactUrls
): EngineHostConfig {
  const recordEndpoints = (env.VITE_ROUTING_ENDPOINTS ?? DEFAULT_ROUTING_ENDPOINTS)
    .split(',')
    .map((endpoint) => endpoint.trim())
    .filter((endpoint) => endpoint.length > 0);
  // Config-edge mirror of the `FetchRecordTransport` empty-endpoint-set rejection.
  if (recordEndpoints.length === 0) {
    throw new Error('VITE_ROUTING_ENDPOINTS must list at least one routing endpoint');
  }

  return {
    apiBaseUrl: env.VITE_API_URL ?? DEFAULT_API_URL,
    recordEndpoints,
    ...artifact,
  };
}
