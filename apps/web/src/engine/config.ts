import type { EngineHostConfig } from '@cipherbox/client';

const DEFAULT_API_URL = 'http://localhost:3000';
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';

/** The API origin the engine authenticates and publishes against. */
export function apiBaseUrl(env: Partial<ImportMetaEnv>): string {
  return env.VITE_API_URL ?? DEFAULT_API_URL;
}

/**
 * Reads the app's build-time environment into the engine host's configuration.
 * The artifact URLs come from the bundler, not the environment.
 */
export function engineHostConfig(
  env: Partial<ImportMetaEnv>,
  artifact: Pick<EngineHostConfig, 'wasmModuleUrl' | 'wasmBinaryUrl'>
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
    apiBaseUrl: apiBaseUrl(env),
    recordEndpoints,
    ...artifact,
  };
}
