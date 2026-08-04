import type { EngineHostConfig } from '@cipherbox/client';

const DEFAULT_API_URL = 'http://localhost:3000';
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';

/** The deployments the build-time environment names. */
export type Environment = 'local' | 'ci' | 'staging' | 'production';

/** The API origin the engine authenticates and publishes against. */
export function apiBaseUrl(env: Partial<ImportMetaEnv>): string {
  // `VITE_API_URL=` reads as `''`, which `new URL` rejects rather than defaults.
  return env.VITE_API_URL || DEFAULT_API_URL;
}

const ENVIRONMENTS: readonly Environment[] = ['local', 'ci', 'staging', 'production'];

/** Deployments whose bundle is shipped to users, and so must be able to log in. */
const DEPLOYED: readonly Environment[] = ['staging', 'production'];

/** Reads a comma-separated variable as a trimmed, blank-free list. */
function list(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * Which deployment this build is; absent means a working-copy `vite dev`. A
 * typo is rejected rather than defaulted: it would silently pick the wrong
 * Web3Auth network, and so a different identity over an empty vault.
 */
export function environment(env: Partial<ImportMetaEnv>): Environment {
  const value = env.VITE_ENVIRONMENT;
  if (value === undefined || value === '') return 'local';
  if (!ENVIRONMENTS.includes(value as Environment)) {
    throw new Error(`VITE_ENVIRONMENT must be one of ${ENVIRONMENTS.join(', ')}`);
  }
  return value as Environment;
}

/**
 * Reads the app's build-time environment into the engine host's configuration.
 * The artifact URLs come from the bundler, not the environment.
 */
export function engineHostConfig(
  env: Partial<ImportMetaEnv>,
  artifact: Pick<EngineHostConfig, 'wasmModuleUrl' | 'wasmBinaryUrl'>
): EngineHostConfig {
  const recordEndpoints = list(env.VITE_ROUTING_ENDPOINTS ?? DEFAULT_ROUTING_ENDPOINTS);
  // Config-edge mirror of the `FetchRecordTransport` empty-endpoint-set rejection.
  if (recordEndpoints.length === 0) {
    throw new Error('VITE_ROUTING_ENDPOINTS must list at least one routing endpoint');
  }

  // The content gateway has no default: an unconfigured build reads nothing
  // rather than reaching for an endpoint nobody chose. The network is canonical
  // and every block is CID-verified, so these are accelerator hints, not trust
  // anchors (CONTEXT.md "Read accelerator").
  const publicGateways = list(env.VITE_PUBLIC_GATEWAYS);

  return {
    apiBaseUrl: apiBaseUrl(env),
    recordEndpoints,
    acceleratorBaseUrl: env.VITE_READ_ACCELERATOR_URL || undefined,
    publicGateways: publicGateways.length > 0 ? publicGateways : undefined,
    ...artifact,
  };
}

/**
 * The build-time variables a deployed bundle cannot log in without, of those
 * `env` does not supply. Checked by the bundler so a missing one is a red build
 * rather than a throw in the browser at first login; a working-copy or CI build
 * names no deployment and is exempt.
 */
export function missingDeployEnv(env: Partial<ImportMetaEnv>): string[] {
  if (!DEPLOYED.includes(environment(env))) return [];
  return (['VITE_WEB3AUTH_CLIENT_ID', 'VITE_WEB3AUTH_VERIFIER'] as const).filter(
    (name) => !env[name]
  );
}
