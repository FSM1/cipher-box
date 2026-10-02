/**
 * Registers this browser's device identity key on the account (ADR 0009 D4), so
 * it can approve a sign-in on a new browser. The settings pane and the landing
 * of a sign-in both run it.
 */

import { EngineRequestError, type EngineFacade } from '@cipherbox/client';
import type { WebCoreKitSession } from './coreKit';

/** A registration signs an identity token, which only a fresh sign-in carries. */
export const NO_TOKEN = 'sign in again with "save this device" checked';

export const NO_IDENTITY = 'this browser holds no device identity key';

/** The engine's code for a request the API refused as unauthorized. */
export const AUTH_REFUSAL = 'auth';

/** Resolves to the registered public key, in the hex the registry carries. */
export async function registerThisDevice(
  session: WebCoreKitSession,
  facade: EngineFacade
): Promise<string> {
  const identity = session.deviceIdentity();
  if (!identity) throw new Error(NO_IDENTITY);
  const identityToken = session.identityToken();
  if (identityToken === null) throw new Error(NO_TOKEN);
  const publicKey = await identity.publicKeyHex();
  const challenge = await facade.deviceRegistrationChallenge(publicKey);
  const signature = await identity.sign(Uint8Array.from(challenge));
  try {
    await facade.registerDevice(publicKey, signature, identityToken, null);
  } catch (refusal) {
    // The API refuses an expired token, and every later try with it fails too.
    if (refusal instanceof EngineRequestError && refusal.code === AUTH_REFUSAL) {
      session.dropIdentityToken();
    }
    throw refusal;
  }
  // The API spends the token, so a second registration in this sign-in fails.
  session.dropIdentityToken();
  return publicKey;
}
