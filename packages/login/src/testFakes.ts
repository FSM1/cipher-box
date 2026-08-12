/** The seams the flow drives, recorded — so a test asserts what it dispatched. */

import type { CredentialCollector } from './collector';
import type { IdentityCredential, IdentityExchange, IdentityMethod } from './identity';
import type { LoginFacade } from './secret';
import type { AccountRecord, CoreKitSession, LoginProgress } from './session';

/** A 32-byte scalar in the hex shape Core Kit exports. */
export const SECRET_HEX = '0f'.repeat(32);
export const FAKE_NONCE = 'nonce123456789ab';
export const FAKE_IDENTITY_TOKEN = 'header.payload.signature';

/** What web's collectors do: the UI already holds the provider's answer. */
export interface WebCollected {
  google: string;
  email: { email: string; code: string };
  wallet: { message: string; signature: string };
}

export function fakeExchange() {
  const calls = {
    google: [] as string[],
    sentCodes: [] as string[],
    verified: [] as { email: string; code: string }[],
    nonces: 0,
    wallet: [] as { message: string; signature: string }[],
  };
  const grant = (method: IdentityMethod, email: string | null): IdentityCredential => ({
    method,
    token: FAKE_IDENTITY_TOKEN,
    verifierId: `subject-for-${method}`,
    email,
  });
  const exchange: IdentityExchange = {
    fromGoogleToken(idToken) {
      calls.google.push(idToken);
      return Promise.resolve(grant('google', 'user@example.test'));
    },
    sendEmailCode(email) {
      calls.sentCodes.push(email);
      return Promise.resolve();
    },
    fromEmailCode(email, code) {
      calls.verified.push({ email, code });
      return Promise.resolve(grant('email', email));
    },
    walletNonce() {
      calls.nonces += 1;
      return Promise.resolve(FAKE_NONCE);
    },
    fromWalletSignature(message, signature) {
      calls.wallet.push({ message, signature });
      return Promise.resolve(grant('wallet', null));
    },
  };
  return { exchange, calls };
}

export function fakeSession(options: { loggedIn?: boolean } = {}) {
  const calls = { logins: [] as IdentityCredential[], exports: 0, logouts: 0 };
  let loggedIn = options.loggedIn ?? false;
  let method: IdentityMethod | null = null;
  let email: string | null = null;
  const session: CoreKitSession = {
    restore: () => Promise.resolve(),
    isLoggedIn: () => loggedIn,
    login(credential) {
      calls.logins.push(credential);
      method = credential.method;
      email = credential.email;
      loggedIn = true;
      return Promise.resolve();
    },
    method: () => method,
    email: () => email,
    logout() {
      calls.logouts += 1;
      loggedIn = false;
      return Promise.resolve();
    },
    _UNSAFE_exportTssKey() {
      calls.exports += 1;
      return Promise.resolve(SECRET_HEX);
    },
  };
  return { session, calls };
}

export function fakeFacade(overrides: Partial<LoginFacade> = {}) {
  const calls = { secrets: [] as Uint8Array[], logouts: 0 };
  const facade: LoginFacade = {
    start(secret) {
      calls.secrets.push(new Uint8Array(secret).slice());
      return overrides.start?.(secret) ?? Promise.resolve();
    },
    logout() {
      calls.logouts += 1;
      return overrides.logout?.() ?? Promise.resolve();
    },
  };
  return { facade, calls };
}

/** A host whose UI collected the material before it called, as web's does. */
export function passThroughCollector(
  offered: { google?: boolean; email?: boolean; wallet?: boolean } = {
    google: true,
    email: true,
    wallet: true,
  }
): CredentialCollector<WebCollected> {
  return {
    google: offered.google ? (idToken) => Promise.resolve(idToken) : undefined,
    email: offered.email ? (answer) => Promise.resolve(answer) : undefined,
    wallet: offered.wallet ? (proof) => Promise.resolve(proof) : undefined,
  };
}

export function fakeAccount() {
  const calls = { signedIn: [] as { method: IdentityMethod | null; email: string | null }[] };
  let signedOut = 0;
  const account: AccountRecord = {
    signedIn(method, email) {
      calls.signedIn.push({ method, email });
    },
    signedOut() {
      signedOut += 1;
    },
  };
  return { account, calls, signOuts: () => signedOut };
}

/** Records the transitions a host would render. */
export function fakeProgress() {
  const seen: string[] = [];
  const failures: unknown[] = [];
  const progress: LoginProgress = {
    begin: () => seen.push('begin'),
    failed: (failure) => {
      failures.push(failure);
      seen.push('failed');
    },
    end: () => seen.push('end'),
  };
  return { progress, seen, failures };
}
