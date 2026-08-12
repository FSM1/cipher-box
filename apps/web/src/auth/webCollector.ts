/**
 * Web's credential collection (ADR 0008 D3). Collection happens in the DOM
 * before the flow is called — Google Identity Services renders its own button
 * and hands the page a token, and wagmi signs in the wallet — so what the flow
 * asks for is already in hand. A host that drives its own flow, as desktop's
 * loopback OAuth listener does, does that work inside these collectors instead.
 */

import type { CollectedMaterial, CredentialCollector, WalletProof } from '@cipherbox/login';

/** What each of web's collectors is handed. */
export interface WebCollected extends CollectedMaterial {
  /** The ID token Google Identity Services delivered. */
  google: string;
  email: { email: string; code: string };
  wallet: WalletProof;
}

/**
 * A build carrying no Google client ID renders no Google button, so the method
 * is absent here to match — that alone disables it, and no other method is
 * affected (`engine/config`).
 */
export function webCollector(
  googleClientId: string | undefined
): CredentialCollector<WebCollected> {
  return {
    google: googleClientId ? (idToken) => Promise.resolve(idToken) : undefined,
    email: (answer) => Promise.resolve(answer),
    wallet: (proof) => Promise.resolve(proof),
  };
}
