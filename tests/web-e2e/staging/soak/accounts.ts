/**
 * The two durable soak accounts (ADR 0053 D1). The web leg signs in with the
 * stored wallet key; a missing key is an error, never a fresh wallet, because a
 * fresh wallet is a fresh account over an empty vault.
 */

import type { Hex } from 'viem';
import { parseWalletKey, type Env } from '../../tools/loginSecretExport';

export type SoakRole = 'owner' | 'grantee';

export const WALLET_KEY_ENV: Readonly<Record<SoakRole, string>> = {
  owner: 'SOAK_OWNER_WALLET_KEY',
  grantee: 'SOAK_GRANTEE_WALLET_KEY',
};

/** The wallet key of `role`. No refusal repeats the value (`parseWalletKey`). */
export function soakWalletKey(env: Env, role: SoakRole): Hex {
  const name = WALLET_KEY_ENV[role];
  const raw = env[name];
  if (raw === undefined || raw.trim() === '') throw new Error(`${name} is not set`);
  try {
    return parseWalletKey(raw);
  } catch (error) {
    throw new Error(`${name}: ${(error as Error).message}`);
  }
}
