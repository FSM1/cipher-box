import { invoke } from '@tauri-apps/api/core';
import type { LoginFacade } from '@cipherbox/login';

/**
 * The facade the login sequence starts, over Tauri IPC (blueprint/desktop.md,
 * "Tauri shell"). What stands behind these two commands is
 * `src-tauri/src/session.rs`.
 */
export const shellFacade: LoginFacade = {
  // The buffer goes over IPC raw. Serialized as a JSON number array it would
  // leave copies of the secret in strings this frame cannot scrub. The account
  // id is dropped: the shell derives its own below this seam, in Rust.
  start: (secret) => invoke('session_start', secret),
  logout: () => invoke('session_logout'),
};
