import { invoke } from '@tauri-apps/api/core';
import type { LoginFacade } from '@cipherbox/login';

/** The header `session_start` reads the identity token from; the body is the secret. */
export const IDENTITY_TOKEN_HEADER = 'x-cipherbox-identity-token';

/**
 * The facade the login sequence starts, over Tauri IPC (blueprint/desktop.md,
 * "Tauri shell"). What stands behind these two commands is
 * `src-tauri/src/session.rs`.
 *
 * `logout` reaches the engine's own `Command::Logout`, which revokes this
 * device's refresh token at the API before the local copy goes.
 */
export const shellFacade: LoginFacade = {
  // The buffer goes over IPC raw. Serialized as a JSON number array it would
  // leave copies of the secret in strings this frame cannot scrub. The account
  // id is dropped: the shell derives its own below this seam, in Rust.
  start: (secret, _accountId, identityToken) =>
    invoke(
      'session_start',
      secret,
      identityToken === undefined
        ? undefined
        : { headers: { [IDENTITY_TOKEN_HEADER]: identityToken } }
    ),
  logout: () => invoke('session_logout'),
};
