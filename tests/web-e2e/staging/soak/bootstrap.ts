/**
 * The bootstrap decision. Only a dispatch with `bootstrap` creates a ledger; a
 * run that finds none fails as `unbootstrapped-or-wiped` and writes nothing.
 */

import type { Env } from '../../tools/loginSecretExport';
import { SoakFailure } from './reasons';

export const BOOTSTRAP_ENV = 'SOAK_BOOTSTRAP';

/** The top-level folder of the soak, in both vaults. */
export const SOAK_FOLDER = 'soak';

/** What the run found in the vault before it wrote anything. */
export interface VaultState {
  readonly soakFolder: boolean;
  readonly ledger: boolean;
}

export type RunPlan =
  | { readonly kind: 'resume' }
  | { readonly kind: 'bootstrap'; readonly archive: boolean }
  | { readonly kind: 'refuse'; readonly reason: 'unbootstrapped-or-wiped' };

/** `SOAK_BOOTSTRAP` as the workflow's boolean input renders it; unset is `false`. */
export function bootstrapRequested(env: Env): boolean {
  const value = env[BOOTSTRAP_ENV];
  if (value === undefined || value === '' || value === 'false') return false;
  if (value === 'true') return true;
  throw new Error(`${BOOTSTRAP_ENV} must be true | false; got "${value}"`);
}

export function planRun(bootstrap: boolean, found: VaultState): RunPlan {
  if (bootstrap) return { kind: 'bootstrap', archive: found.soakFolder };
  return found.ledger ? { kind: 'resume' } : { kind: 'refuse', reason: 'unbootstrapped-or-wiped' };
}

/**
 * Whether the vault root holds `soak/`. A row that its wait missed but the
 * settled listing names is a slow listing, not an absent folder: counted as
 * absent, a bootstrap would skip the archive and create a second `soak/`.
 */
export function soakFolderListed(rowShown: boolean, rootNames: ReadonlySet<string>): boolean {
  if (!rowShown && rootNames.has(SOAK_FOLDER)) {
    throw new SoakFailure('listing-unsettled', `the root listing showed ${SOAK_FOLDER}/ late`);
  }
  return rowShown;
}

/**
 * The name the bootstrap moves an existing `soak/` folder to: `soak-archived-<day>`,
 * with a counter when an earlier bootstrap of the same day took that name.
 */
export function archiveName(day: string, taken: ReadonlySet<string>): string {
  const base = `${SOAK_FOLDER}-archived-${day}`;
  if (!taken.has(base)) return base;
  for (let n = 2; ; n += 1) {
    const candidate = `${base}-${n}`;
    if (!taken.has(candidate)) return candidate;
  }
}
