import { invoke } from '@tauri-apps/api/core';
import type { LoginFacade } from '@cipherbox/login';

/**
 * The facade the login sequence starts, over Tauri IPC (blueprint/desktop.md,
 * "Tauri shell"). The shell does not link `crates/engine` yet, so what stands
 * behind these two commands is `src-tauri/src/session.rs` — it takes the login
 * secret and zeroizes it, and there is no vault behind it.
 */
export const shellFacade: LoginFacade = {
  // The buffer goes over IPC raw. Serialized as a JSON number array it would
  // leave copies of the secret in strings this frame cannot scrub.
  start: (secret) => invoke('session_start', secret),
  logout: () => invoke('session_logout'),
};
