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
export const VAULT_CHANGED = 'vault-changed';

/** The staleness ladder, as the engine's rungs are named. */
export type Staleness = 'fresh' | 'reconciling' | 'stale' | 'offline';

export interface VaultStatus {
  /** Items directly under the vault root. */
  items: number;
  staleness: Staleness;
  /** Queued changes that will never publish; never conflated with staleness. */
  deadLetters: number;
  /** Durable queue entries this device holds but cannot read. */
  retainedRecords: number;
}

/** Reads the live vault's status; rejects when no session is live. */
export function readVaultStatus(): Promise<VaultStatus> {
  return invoke<VaultStatus>('vault_status');
}

/** Calls `changed` whenever the engine emits, until the returned unlisten runs. */
export function onVaultChanged(changed: () => void): Promise<UnlistenFn> {
  return listen(VAULT_CHANGED, () => changed());
}
