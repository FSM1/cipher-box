/**
 * The engine and Core Kit as the login flow sees them: both seams recorded, so a
 * test asserts what the flow dispatched rather than how it got there.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type {
  AuthMethodDescriptor,
  EngineClient,
  SiweIntent,
  VaultSettingsDescriptor,
  VaultStorageDescriptor,
} from '@cipherbox/client';
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
  /** The wallet links, kept apart from `siwe`: a link is not a login. */
  siweLinks: { message: string; signature: Uint8Array }[];
  /** The intent each nonce mint named; a link must never mint from the sign-in pool. */
  siweChallenges: number;
  siweChallengeIntents: SiweIntent[];
  logouts: number;
  /** How many times this tab announced the session end to the origin. */
  originSessionEnds: number;
  /** The settings each accepted or refused save carried. */
  vaultSettings: VaultSettingsDescriptor[];
  /** The method id each unlink named. */
  unlinked: string[];
}

/** A hosted vault whose ledger has drained, as the storage pane first reads it. */
export const FAKE_VAULT_STORAGE: VaultStorageDescriptor = {
  settings: {
    pinMode: 'hosted',
    byoEndpoint: null,
    byoKind: null,
    byoCredentialStored: false,
    keepLatestVersions: null,
    origin: 'resolved',
  },
  quota: { usedBytes: 1024, limitBytes: 4096, advisory: false },
  pendingReclaimBytes: 0,
  reclaimStalls: [],
};

/**
 * The engine as a host reads it: a `start` the engine resolved *is* the session,
 * and tearing the client down ends it — so a test drives sign-in through the
 * engine, exactly as `EngineClient` publishes it.
 */
export function fakeEngineClient(
  overrides: Partial<{
    start: () => Promise<void>;
    logout: () => Promise<void>;
    saveVaultSettings: () => Promise<void>;
    unlinkAuthMethod: () => Promise<void>;
    /** What the storage pane reads back; `null` stands for a probe that failed. */
    vaultStorage: () => Promise<VaultStorageDescriptor>;
    authMethods: () => Promise<AuthMethodDescriptor[]>;
  }> = {}
) {
  const calls: EngineCalls = {
    started: [],
    secrets: [],
    logouts: 0,
    siwe: [],
    siweLinks: [],
    siweChallenges: 0,
    siweChallengeIntents: [],
    originSessionEnds: 0,
    vaultSettings: [],
    unlinked: [],
  };
  const sessionListeners = new Set<() => void>();
  const sessionEndListeners = new Set<() => void>();
  let account: string | null = null;
  const holds = (next: string | null): void => {
    if (account === next) return;
    account = next;
    for (const listener of [...sessionListeners]) listener();
  };
  const client = {
    subscribeSession(listener: () => void) {
      sessionListeners.add(listener);
      return () => sessionListeners.delete(listener);
    },
    signedInAccount: () => account,
    // Announce-only, as the real client is: a tab is not its own sibling.
    endOriginSession() {
      calls.originSessionEnds += 1;
    },
    subscribeSessionEnd(listener: () => void) {
      sessionEndListeners.add(listener);
      return () => sessionEndListeners.delete(listener);
    },
    facade: {
      async start(secret: ArrayBuffer, accountId: string) {
        calls.started.push(secret);
        calls.secrets.push(new Uint8Array(secret).slice());
        await (overrides.start?.() ?? Promise.resolve());
        holds(accountId);
      },
      siweChallenge(intent: SiweIntent) {
        calls.siweChallenges += 1;
        calls.siweChallengeIntents.push(intent);
        return Promise.resolve(FAKE_NONCE);
      },
      siweLogin(message: string, signature: Uint8Array) {
        calls.siwe.push({ message, signature });
        return Promise.resolve();
      },
      siweLink(message: string, signature: Uint8Array) {
        calls.siweLinks.push({ message, signature });
        return Promise.resolve();
      },
      unlinkAuthMethod(methodId: string) {
        calls.unlinked.push(methodId);
        return overrides.unlinkAuthMethod?.() ?? Promise.resolve();
      },
      vaultStorage: () => overrides.vaultStorage?.() ?? Promise.resolve(FAKE_VAULT_STORAGE),
      authMethods: () => overrides.authMethods?.() ?? Promise.resolve([]),
      async logout() {
        calls.logouts += 1;
        // The engine is zeroized either way: `EngineFacade.logout` tears the
        // transport down whatever the command answers.
        try {
          await (overrides.logout?.() ?? Promise.resolve());
        } finally {
          holds(null);
        }
      },
      forgetDevice: () => Promise.resolve(),
      saveVaultSettings(settings: VaultSettingsDescriptor) {
        calls.vaultSettings.push(settings);
        return overrides.saveVaultSettings?.() ?? Promise.resolve();
      },
      subscribe: () => () => undefined,
      snapshot: () => new Promise(() => undefined),
      setFocus: () => Promise.resolve(),
    },
    reportFocus: () => undefined,
    dispose() {
      holds(null);
      return Promise.resolve();
    },
  } as unknown as EngineClient;
  /** Replays the origin-wide session end a sibling tab would have announced. */
  const endSessionElsewhere = (): void => {
    holds(null);
    for (const listener of [...sessionEndListeners]) listener();
  };
  return { client, calls, endSessionElsewhere };
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
    /** What an enrollment could not confirm after the policy was cut. */
    enrollWarning?: string;
  } = {}
) {
  const calls: CoreKitCalls = { logins: [], exports: 0, logouts: 0, phrases: [], enrollments: 0 };
  let loggedIn = options.loggedIn ?? false;
  // Both read off the redeemed credential, as the real session does: a bare
  // restore knows neither, and a wallet login carries no address.
  let method: IdentityMethod | null = null;
  let email: string | null = null;
  const session: WebCoreKitSession = {
    accountId: () => 'acct01',
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
      return Promise.resolve({ phrase: FAKE_PHRASE, warning: options.enrollWarning ?? null });
    },
    method: () => method,
    email: options.email ?? (() => email),
    logout() {
      calls.logouts += 1;
      loggedIn = false;
      return Promise.resolve();
    },
    forgetDevice: () => Promise.resolve(),
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
