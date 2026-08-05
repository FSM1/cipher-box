// `vite.config.ts` imports the deploy gate from here while resolving config, so
// this module must keep to type-only imports — a value import of the client
// package would pull the WASM engine into the bundler.
import type { EngineHostConfig } from '@cipherbox/client';

const DEFAULT_API_URL = 'http://localhost:3000';
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';

/** The deployments the build-time environment names. */
export type Environment = 'local' | 'ci' | 'staging' | 'production';

/**
 * The API origin the engine authenticates and publishes against. Trimmed, since
 * it is concatenated into request URLs; a whitespace-only value trims to blank
 * rather than defaulting, so the engine's own edge check refuses it instead of
 * a misconfigured deployment quietly talking to the user's own machine.
 */
export function apiBaseUrl(env: Partial<ImportMetaEnv>): string {
  // `VITE_API_URL=` reads as `''`, which `new URL` rejects rather than defaults.
  return env.VITE_API_URL === undefined || env.VITE_API_URL === ''
    ? DEFAULT_API_URL
    : env.VITE_API_URL.trim();
}

const ENVIRONMENTS: readonly Environment[] = ['local', 'ci', 'staging', 'production'];

/** Deployments whose bundle is shipped to users, and so must be able to log in. */
const DEPLOYED: readonly Environment[] = ['staging', 'production'];

/** The one list of what a Core Kit session needs, shared with the build gate. */
const LOGIN_ENV = ['VITE_WEB3AUTH_CLIENT_ID', 'VITE_WEB3AUTH_VERIFIER'] as const;

/**
 * What a deployed bundle cannot work without. `VITE_API_URL` is here because an
 * unset one falls back to `localhost`, which the engine would then authenticate
 * against — a working build pointed at whatever answers on the user's machine.
 */
const DEPLOY_ENV = [...LOGIN_ENV, 'VITE_API_URL'] as const;

/**
 * A variable's configured value, or `undefined` when it carries none. Absent,
 * empty and whitespace-only are one state: a repo variable set to a stray space
 * or newline is unset, not configured.
 */
function configured(value: string | undefined): string | undefined {
  return value?.trim() || undefined;
}

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

  return {
    apiBaseUrl: apiBaseUrl(env),
    recordEndpoints,
    // The content gateway has no default: unset reads nothing rather than
    // reaching for an endpoint nobody chose. Dormant is the fail-closed state,
    // so a blank value must land there rather than configuring a gateway source
    // whose every request fails.
    acceleratorBaseUrl: configured(env.VITE_READ_ACCELERATOR_URL),
    publicGateways: list(env.VITE_PUBLIC_GATEWAYS),
    ...artifact,
  };
}

/** Of the variables Core Kit login needs, those `env` does not supply. */
export function missingLoginEnv(env: Partial<ImportMetaEnv>): string[] {
  return LOGIN_ENV.filter((name) => configured(env[name]) === undefined);
}

/** The Web3Auth identifiers a Core Kit session is built from; refuses a build missing any. */
export function loginEnv(env: Partial<ImportMetaEnv>): { clientId: string; verifier: string } {
  const clientId = configured(env.VITE_WEB3AUTH_CLIENT_ID);
  const verifier = configured(env.VITE_WEB3AUTH_VERIFIER);
  if (!clientId || !verifier) {
    throw new Error(`${missingLoginEnv(env).join(' and ')} must be configured`);
  }
  return { clientId, verifier };
}

/**
 * The variables a deployed bundle is missing. The bundler checks this so an
 * unset one is a red build rather than a broken deploy nobody notices until a
 * user tries to log in; a working-copy or CI build names no deployment and is
 * exempt.
 */
export function missingDeployEnv(env: Partial<ImportMetaEnv>): string[] {
  if (!DEPLOYED.includes(environment(env))) return [];
  return DEPLOY_ENV.filter((name) => configured(env[name]) === undefined);
}

/**
 * Whether this build would ship the e2e introspection hook. `loadEnv` takes
 * `VITE_` variables from the process environment and from any `.env.<mode>`
 * file, so a deployed build refuses the flag rather than trusting that nobody
 * exported it.
 */
export function shipsE2eHook(env: Partial<ImportMetaEnv>): boolean {
  return DEPLOYED.includes(environment(env)) && configured(env.VITE_E2E_HOOK) !== undefined;
}
