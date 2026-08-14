import { invoke } from '@tauri-apps/api/core';

/**
 * Google collection, native rather than in-webview (ADR 0008 D3). Google
 * Identity Services does not run here, and the OAuth2 flow it falls back to
 * needs an `http(s)` `redirect_uri`, which a packaged Tauri origin is not — so
 * the consent screen and its loopback callback are served by the shell itself
 * (`src-tauri/src/oauth.rs`).
 *
 * Resolves with the ID token, and rejects if the member closes the window or
 * the exchange passes its deadline.
 */
export function collectGoogleIdToken(clientId: string): Promise<string> {
  return invoke<string>('collect_google_id_token', { clientId });
}
