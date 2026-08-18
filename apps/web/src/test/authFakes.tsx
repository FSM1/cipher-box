/**
 * The engine and Core Kit as the login flow sees them: both seams recorded, so a
 * test asserts what the flow dispatched rather than how it got there.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { EngineClient } from '@cipherbox/client';
import type { ReactNode } from 'react';
import { WagmiProvider } from 'wagmi';
import { CoreKitProvider } from '../auth/CoreKitProvider';
import type { WebCoreKitSession } from '../auth/coreKit';

import { IdentityProvider } from '../auth/IdentityProvider';
import {
  RecoveryRequiredError,
  type IdentityCredential,
  type IdentityExchange,
  type IdentityMethod,
} from '@cipherbox/login';
import { wagmiConfig } from '../lib/wagmi';
import { EngineProvider } from '../providers/EngineProvider';

/** A 32-byte scalar in the hex shape Core Kit exports. */
export const SECRET_HEX = '0f'.repeat(32);

/** The nonce the fake exchange issues for a SIWE challenge. */
export const FAKE_NONCE = 'nonce123456789ab';

/** The identity token the fake exchange mints, whichever method asked. */
export const FAKE_IDENTITY_TOKEN = 'header.payload.signature';

/** The one phrase the fake session enrolls and accepts; 24 words, as a real one is. */
export const FAKE_PHRASE = `${'word '.repeat(23)}last`;

export interface EngineCalls {
  /** The buffers `start` was handed, still live so a test can check zeroization. */
  started: ArrayBuffer[];
  /** What each buffer held on arrival, before the handoff scrubbed it. */
  secrets: Uint8Array[];
  siwe: { message: string; signature: Uint8Array }[];
  siweChallenges: number;
  logouts: number;
}

export function fakeEngineClient(
  overrides: Partial<Record<'start' | 'logout', () => Promise<void>>> = {}
) {
  const calls: EngineCalls = {
    started: [],
    secrets: [],
    logouts: 0,
    siwe: [],
    siweChallenges: 0,
  };
  const client = {
    facade: {
      start(secret: ArrayBuffer) {
        calls.started.push(secret);
        calls.secrets.push(new Uint8Array(secret).slice());
        return overrides.start?.() ?? Promise.resolve();
      },
      siweChallenge() {
        calls.siweChallenges += 1;
        return Promise.resolve(FAKE_NONCE);
      },
      siweLogin(message: string, signature: Uint8Array) {
        calls.siwe.push({ message, signature });
        return Promise.resolve();
      },
      logout() {
        calls.logouts += 1;
        return overrides.logout?.() ?? Promise.resolve();
      },
      subscribe: () => () => undefined,
      snapshot: () => new Promise(() => undefined),
      setFocus: () => Promise.resolve(),
    },
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
  return { client, calls };
}

export interface CoreKitCalls {
  logins: IdentityCredential[];
  exports: number;
  logouts: number;
  phrases: string[];
  enrollments: number;
}

export function fakeCoreKitSession(
  options: {
    loggedIn?: boolean;
    email?: () => string | null;
    /** Stands in for the mount-time restore; omit for one that settles at once. */
    restore?: () => Promise<void>;
    /** Turns every login into one that stops at the factor policy. */
    needsRecovery?: boolean;
    /** Whether this account already carries a factor policy. */
    enrolled?: boolean;
  } = {}
) {
  const calls: CoreKitCalls = { logins: [], exports: 0, logouts: 0, phrases: [], enrollments: 0 };
  let loggedIn = options.loggedIn ?? false;
  // Both read off the redeemed credential, as the real session does: a bare
  // restore knows neither, and a wallet login carries no address.
  let method: IdentityMethod | null = null;
  let email: string | null = null;
  const session: WebCoreKitSession = {
    restore: options.restore ?? (() => Promise.resolve()),
    isLoggedIn: () => loggedIn,
    login(credential) {
      calls.logins.push(credential);
      method = credential.method;
      email = credential.email;
      if (options.needsRecovery) return Promise.reject(new RecoveryRequiredError());
      loggedIn = true;
      return Promise.resolve();
    },
    hasRecoveryPhrase: () => options.enrolled ?? false,
    recoverWithPhrase(phrase) {
      calls.phrases.push(phrase);
      if (phrase !== FAKE_PHRASE) {
        return Promise.reject(new Error('that recovery phrase does not open this account'));
      }
      loggedIn = true;
      return Promise.resolve();
    },
    enrollRecoveryPhrase() {
      calls.enrollments += 1;
      return Promise.resolve(FAKE_PHRASE);
    },
    method: () => method,
    email: options.email ?? (() => email),
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

export interface ExchangeCalls {
  google: string[];
  sentCodes: string[];
  verified: { email: string; code: string }[];
  nonces: number;
  wallet: { message: string; signature: string }[];
}

/** The API's identity surface as the login flow sees it. */
export function fakeIdentityExchange(overrides: Partial<IdentityExchange> = {}): {
  exchange: IdentityExchange;
  calls: ExchangeCalls;
} {
  const calls: ExchangeCalls = {
    google: [],
    sentCodes: [],
    verified: [],
    nonces: 0,
    wallet: [],
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
    ...overrides,
  };
  return { exchange, calls };
}

/** Mounts the providers the login flow reads, over the given fakes. */
export function authWrapper(
  client: EngineClient,
  session: WebCoreKitSession,
  exchange: IdentityExchange = fakeIdentityExchange().exchange
) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <EngineProvider createClient={() => client}>
        <CoreKitProvider createSession={() => session}>
          <IdentityProvider exchange={exchange} googleClientId="google-client-id">
            {children}
          </IdentityProvider>
        </CoreKitProvider>
      </EngineProvider>
    );
  };
}

/** `authWrapper` plus the wallet-side providers the login *page* also mounts. */
export function pageWrapper(
  client: EngineClient,
  session: WebCoreKitSession,
  exchange: IdentityExchange = fakeIdentityExchange().exchange
) {
  const Auth = authWrapper(client, session, exchange);
  // One client per wrapper, not per render: wagmi's cache must survive a
  // re-render or the wallet flow reads as a fresh, disconnected mount.
  const queries = new QueryClient();
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
        <QueryClientProvider client={queries}>
          <Auth>{children}</Auth>
        </QueryClientProvider>
      </WagmiProvider>
    );
  };
}
