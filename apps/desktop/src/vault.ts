/**
 * What the signed-in window knows about the vault: the engine's own state, read
 * over IPC.
 *
 * This window is login-and-settings chrome (blueprint/desktop.md, "Tauri
 * shell") — the vault proper is the mount and the web app — so it reads a
 * status rather than a listing, and holds none of it between reads.
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

/** Fired by the shell when the engine emits; `src-tauri/src/session.rs`. */
const VAULT_CHANGED = 'vault-changed';

/** The staleness ladder, as the engine's rungs are named. */
export type Staleness = 'fresh' | 'reconciling' | 'stale' | 'offline';

/** What the engine raised that no read reports, under the event's own name. */
export type VaultWarningKind = 'attributableAbuse' | 'withheldUpdateEscalation' | 'renewalFailed';

export interface VaultWarning {
  kind: VaultWarningKind;
  /** The engine's own classification, when it carried one. Never a record name. */
  detail: string | null;
}

/**
 * Whether the vault is also projected as a filesystem, and where. Exactly one
 * of the two is set: a mount with no path could not be opened, and a session
 * with no mount and no reason is the silent failure this line prevents.
 */
export type MountStatus = { path: string; refusal: null } | { path: null; refusal: string };

export interface VaultStatus {
  /** Items directly under the vault root. */
  items: number;
  staleness: Staleness;
  /** Queued changes that will never publish; never conflated with staleness. */
  deadLetters: number;
  /** False means nothing will publish until a later sign-in mints the vault. */
  provisioned: boolean;
  /** Conditions the engine raised; a trust warning is not a stale view. */
  warnings: VaultWarning[];
  mount: MountStatus;
}

/** Reads the live vault's status; rejects when no session is live. */
export function readVaultStatus(): Promise<VaultStatus> {
  return invoke<VaultStatus>('vault_status');
}

/**
 * Ends the session and sweeps this device's stored vault data — everything a
 * sign-out keeps. Rejects when no session is live, which is the only state that
 * names the account whose data would go.
 */
export function forgetDevice(): Promise<void> {
  return invoke('session_forget_device');
}

/** Calls `changed` whenever the engine emits, until the returned unlisten runs. */
export function onVaultChanged(changed: () => void): Promise<UnlistenFn> {
  return listen(VAULT_CHANGED, changed);
}
