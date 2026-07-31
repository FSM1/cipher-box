/**
 * The engine and Core Kit as the login flow sees them: both seams recorded, so a
 * test asserts what the flow dispatched rather than how it got there.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { EngineClient } from '@cipherbox/client';
import type { ReactNode } from 'react';
import { WagmiProvider } from 'wagmi';
import { CoreKitProvider } from '../auth/CoreKitProvider';
import type { CoreKitLoginMethod, CoreKitSession } from '../auth/coreKit';
import { wagmiConfig } from '../lib/wagmi';
import { EngineProvider } from '../providers/EngineProvider';

/** A 32-byte scalar in the hex shape Core Kit exports. */
export const SECRET_HEX = '0f'.repeat(32);

export interface EngineCalls {
  /** The buffers `start` was handed, still live so a test can check zeroization. */
  started: ArrayBuffer[];
  /** What each buffer held on arrival, before the handoff scrubbed it. */
  secrets: Uint8Array[];
  siwe: { message: string; signature: Uint8Array }[];
  logouts: number;
}

export function fakeEngineClient(
  overrides: Partial<Record<'start' | 'logout', () => Promise<void>>> = {}
) {
  const calls: EngineCalls = { started: [], secrets: [], logouts: 0, siwe: [] };
  const client = {
    facade: {
      start(secret: ArrayBuffer) {
        calls.started.push(secret);
        calls.secrets.push(new Uint8Array(secret).slice());
        return overrides.start?.() ?? Promise.resolve();
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
  logins: { method: CoreKitLoginMethod; email?: string }[];
  exports: number;
  logouts: number;
}

export function fakeCoreKitSession(
  options: { loggedIn?: boolean; login?: () => Promise<void> } = {}
) {
  const calls: CoreKitCalls = { logins: [], exports: 0, logouts: 0 };
  let loggedIn = options.loggedIn ?? false;
  const session: CoreKitSession = {
    restore: () => Promise.resolve(),
    isLoggedIn: () => loggedIn,
    async login(method, email) {
      calls.logins.push({ method, email });
      await (options.login?.() ?? Promise.resolve());
      loggedIn = true;
    },
    method: () => 'google',
    email: () => 'user@example.test',
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

/** Mounts the two providers the login flow reads, over the given fakes. */
export function authWrapper(client: EngineClient, session: CoreKitSession) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <EngineProvider createClient={() => client}>
        <CoreKitProvider createSession={() => session}>{children}</CoreKitProvider>
      </EngineProvider>
    );
  };
}

/** `authWrapper` plus the wallet-side providers the login *page* also mounts. */
export function pageWrapper(client: EngineClient, session: CoreKitSession) {
  const Auth = authWrapper(client, session);
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
        <QueryClientProvider client={new QueryClient()}>
          <Auth>{children}</Auth>
        </QueryClientProvider>
      </WagmiProvider>
    );
  };
}
