/**
 * The offline half of the soak login-secret export (ADR 0053 D2): argument and
 * environment parsing, the wallet-key check, and the output shape. No refusal
 * here repeats its input, because the input is key material.
 */

import type { Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

/** The variable the wallet key is read from when `--stdin` is not given. */
export const WALLET_KEY_ENV = 'SOAK_WALLET_KEY';

/** Where the wallet key comes from. `mint` is a fresh wallet nobody holds yet. */
export type KeySource = 'env' | 'stdin' | 'mint';

export type Invocation = { kind: 'help' } | { kind: 'export'; source: KeySource };

export interface ExportConfig {
  /** The CipherBox API that mints the identity token. */
  apiUrl: string;
  /** The web front whose host the SIWE message names; the API allows only its CORS origins. */
  siweOrigin: string;
  web3AuthClientId: string;
  verifier: string;
}

export type Env = Readonly<Record<string, string | undefined>>;

export const USAGE = `Exports the login secret of a soak wallet account.

Usage: tsx tools/exportLoginSecret.ts [--stdin]

  --stdin  read the wallet key from standard input
  (none)   read the wallet key from ${WALLET_KEY_ENV}; if it is unset,
           mint a fresh wallet and print its key and its login secret

Required environment: VITE_API_URL, E2E_BASE_URL, VITE_WEB3AUTH_CLIENT_ID,
VITE_WEB3AUTH_VERIFIER. The runbook is staging/README.md.
`;

export class UsageError extends Error {}

export function parseInvocation(argv: readonly string[], env: Env): Invocation {
  let stdin = false;
  for (const arg of argv) {
    if (arg === '--help' || arg === '-h') return { kind: 'help' };
    if (arg !== '--stdin') throw new UsageError('unknown argument; see --help');
    stdin = true;
  }
  // An empty variable is a failed `op read`, not a request to mint.
  const inEnv = env[WALLET_KEY_ENV] !== undefined;
  if (stdin && inEnv) {
    throw new UsageError(`give the wallet key through ${WALLET_KEY_ENV} or --stdin, not both`);
  }
  return { kind: 'export', source: stdin ? 'stdin' : inEnv ? 'env' : 'mint' };
}

export function readConfig(env: Env): ExportConfig {
  return {
    apiUrl: httpsUrl(env, 'VITE_API_URL').replace(/\/+$/, ''),
    siweOrigin: new URL(httpsUrl(env, 'E2E_BASE_URL')).origin,
    web3AuthClientId: required(env, 'VITE_WEB3AUTH_CLIENT_ID'),
    verifier: required(env, 'VITE_WEB3AUTH_VERIFIER'),
  };
}

/** A secp256k1 private key as `0x` and 64 lowercase hex characters. */
export function parseWalletKey(raw: string): Hex {
  const trimmed = raw.trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(trimmed)) {
    throw new UsageError('the wallet key is not 32 bytes of hex');
  }
  const key = `0x${trimmed.replace(/^0x/, '').toLowerCase()}` as Hex;
  try {
    privateKeyToAccount(key);
  } catch {
    // The library's message can carry the key.
    throw new UsageError('the wallet key is not a valid secp256k1 private key');
  }
  return key;
}

/** Core Kit's export as the 64 lowercase hex characters the soak stores. */
export function formatLoginSecret(exported: string): string {
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(exported)) {
    throw new Error('the Core Kit export is not a 32-byte hex scalar');
  }
  return exported.replace(/^0x/, '').toLowerCase();
}

/**
 * The one stdout write. An export prints the bare secret, so it pipes into
 * `gh secret set`; a mint prints both values under the 1Password field names.
 */
export function renderOutput(loginSecret: string, mintedWalletKey?: Hex): string {
  if (mintedWalletKey === undefined) return `${loginSecret}\n`;
  return `walletKey=${mintedWalletKey}\nloginSecret=${loginSecret}\n`;
}

function required(env: Env, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new UsageError(`${name} is not set`);
  return value;
}

function httpsUrl(env: Env, name: string): string {
  const value = required(env, name);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new UsageError(`${name} is not a URL`);
  }
  if (url.protocol !== 'https:') throw new UsageError(`${name} must be an https: URL`);
  return value;
}
