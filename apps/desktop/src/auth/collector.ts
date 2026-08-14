/**
 * The shell's credential collection (ADR 0008 D3) — the only desktop-specific
 * step in the login, everything after it being `@cipherbox/login`'s sequencing.
 *
 * Google is driven from inside its collector rather than handed in: this host
 * runs its own consent flow and has nothing in hand when the flow calls.
 */

import type { CollectedMaterial, CredentialCollector } from '@cipherbox/login';
import { collectGoogleIdToken } from './googleOAuth';

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
 * A build carrying no Google client ID cannot open the consent screen, so the
 * method is absent rather than offered and unable to complete.
 */
export function desktopCollector(
  googleClientId: string | undefined
): CredentialCollector<DesktopCollected> {
  return {
    google: googleClientId ? () => collectGoogleIdToken(googleClientId) : undefined,
    email: (answer) => Promise.resolve(answer),
  };
}
