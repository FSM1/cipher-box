/**
 * The shell's build-time environment. A subset of web's: no service worker, no
 * routing endpoints, and no wallet — the shell reaches none of them.
 */

/** Shared with `scripts/csp.mjs`, which must allow whatever this resolves to. */
export const DEFAULT_API_URL = 'http://localhost:3000';

export type Environment = 'local' | 'ci' | 'staging' | 'production';

const ENVIRONMENTS: readonly Environment[] = ['local', 'ci', 'staging', 'production'];

export interface DesktopConfig {
  environment: Environment;
  /** The API origin the identity exchange is spoken to. */
  apiBaseUrl: string;
  web3AuthClientId: string;
  verifier: string;
  /** Absent means this build collects no Google credential, so offers none. */
  googleClientId: string | undefined;
}

/**
 * Absent, empty and whitespace-only are one state: a repo variable set to a
 * stray space is unset, not configured.
 */
function configured(value: string | undefined): string | undefined {
  return value?.trim() || undefined;
}

/**
 * A typo is rejected rather than defaulted: it would silently pick the wrong
 * Web3Auth network, and so a different identity over an empty vault.
 */
function environmentOf(env: Partial<ImportMetaEnv>): Environment {
  const value = configured(env.VITE_ENVIRONMENT);
  if (value === undefined) return 'local';
  if (!ENVIRONMENTS.includes(value as Environment)) {
    throw new Error(`VITE_ENVIRONMENT must be one of ${ENVIRONMENTS.join(', ')}`);
  }
  return value as Environment;
}

export function desktopConfig(env: Partial<ImportMetaEnv>): DesktopConfig {
  const web3AuthClientId = configured(env.VITE_WEB3AUTH_CLIENT_ID);
  const verifier = configured(env.VITE_WEB3AUTH_VERIFIER);
  if (!web3AuthClientId || !verifier) {
    throw new Error(
      'this build cannot sign in without VITE_WEB3AUTH_CLIENT_ID and VITE_WEB3AUTH_VERIFIER'
    );
  }
  return {
    environment: environmentOf(env),
    apiBaseUrl: configured(env.VITE_API_URL) ?? DEFAULT_API_URL,
    web3AuthClientId,
    verifier,
    googleClientId: configured(env.VITE_GOOGLE_CLIENT_ID),
  };
}
