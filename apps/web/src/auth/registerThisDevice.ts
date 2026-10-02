import { EngineRequestError, type EngineFacade } from '@cipherbox/client';
import type { WebCoreKitSession } from './coreKit';

/**
 * The remedy for every refusal that a fresh sign-in token cures: a registration
 * signs an identity token, which only a fresh sign-in carries.
 */
export const SIGN_IN_TO_SAVE = 'sign in again with "save this device" checked';

/** A sign-in names the member, and the key is minted on its first use. */
export const NO_IDENTITY = 'this browser holds no device identity key; sign in again to create one';

/** Whether the API refused the request as unauthorized: the token is spent or expired. */
export function isAuthRefusal(failure: unknown): boolean {
  return failure instanceof EngineRequestError && failure.code === 'auth';
}

/**
 * Registers this browser's device identity key on the account (ADR 0009 D4), so
 * it can approve a sign-in on a new browser. Resolves to the registered public
 * key, in the hex the registry carries.
 */
export async function registerThisDevice(
  session: WebCoreKitSession,
  facade: EngineFacade
): Promise<string> {
  const identity = session.deviceIdentity();
  if (!identity) throw new Error(NO_IDENTITY);
  const identityToken = session.identityToken();
  if (identityToken === null) throw new Error(SIGN_IN_TO_SAVE);
  const publicKey = await identity.publicKeyHex();
  const challenge = await facade.deviceRegistrationChallenge(publicKey);
  const signature = await identity.sign(Uint8Array.from(challenge));
  try {
    await facade.registerDevice(publicKey, signature, identityToken, null);
  } catch (refusal) {
    // An expired token fails every later try the same way.
    if (isAuthRefusal(refusal)) session.dropIdentityToken();
    throw refusal;
  }
  // The API spends the token, so a second registration in this sign-in fails.
  session.dropIdentityToken();
  return publicKey;
}
