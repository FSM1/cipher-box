/**
 * The shell's credential collection (ADR 0008 D3) — the only desktop-specific
 * step in the login, everything after it being `@cipherbox/login`'s sequencing.
 *
 * Google is driven from inside its collector rather than handed in: this host
 * runs its own consent flow and has nothing in hand when the flow calls.
 */

import { invoke } from '@tauri-apps/api/core';
import type { CollectedMaterial, CredentialCollector } from '@cipherbox/login';

/**
 * What each of the shell's collectors is handed. `wallet` is `never` because
 * the webview reaches no wallet, and the collector below leaves the member out
 * accordingly — a method absent from a collector is a method this host does not
 * have (ADR 0008 D2).
 */
export interface DesktopCollected extends CollectedMaterial {
  google: void;
  email: { email: string; code: string };
  wallet: never;
}

/**
 * Google is collected natively by the shell rather than in this webview; why,
 * and how the loopback callback is bounded, is in `src-tauri/src/oauth.rs`.
 * Rejects if the member closes the window or the exchange passes its deadline.
 */
function collectGoogleIdToken(clientId: string): Promise<string> {
  return invoke<string>('collect_google_id_token', { clientId });
}

/**
 * A build carrying no Google client ID cannot open the consent screen, so the
 * method is absent rather than offered and unable to complete.
 */
export function desktopCollector(
  googleClientId: string | undefined
): CredentialCollector<DesktopCollected> {
  return {
    ...(googleClientId ? { google: () => collectGoogleIdToken(googleClientId) } : {}),
    email: (answer) => Promise.resolve(answer),
  };
}
