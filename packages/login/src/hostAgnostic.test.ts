/**
 * The package is host-agnostic by law (ADR 0008 D3), which is what lets desktop
 * import it: no browser API, no React. `tsconfig.json` drops the `DOM` lib so a
 * browser API cannot typecheck here; this runs the whole sequencing with the
 * browser globals booby-trapped, so one reached at runtime fails the suite too.
 */

import { describe, expect, it } from 'vitest';
import { createLoginFlow } from './flow';
import { createIdentityExchange } from './identity';
import {
  fakeAccount,
  fakeFacade,
  fakeProgress,
  fakeSession,
  passThroughCollector,
  type WebCollected,
} from './testFakes';

/** What a browser host would have and this package must never reach for. */
const BROWSER_GLOBALS = [
  'window',
  'document',
  'navigator',
  'location',
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'caches',
  'BroadcastChannel',
  'Worker',
  'XMLHttpRequest',
] as const;

/** Runs `body` in a realm where every browser global throws on first touch. */
async function withNoBrowserApi(body: () => Promise<void>): Promise<void> {
  const original = BROWSER_GLOBALS.map(
    (name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)] as const
  );
  for (const [name] of original) {
    Object.defineProperty(globalThis, name, {
      configurable: true,
      get() {
        throw new Error(`the login package reached for the browser API \`${name}\``);
      },
    });
  }
  try {
    await body();
  } finally {
    for (const [name, descriptor] of original) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete (globalThis as Record<string, unknown>)[name];
    }
  }
}

describe('a host-agnostic login', () => {
  it('sequences a whole login with no browser API in reach', async () => {
    const session = fakeSession();
    const facade = fakeFacade();
    const account = fakeAccount();
    const grant = { token: 'header.payload.signature', verifierId: 'subject-42', email: null };
    const flow = createLoginFlow<WebCollected>({
      exchange: createIdentityExchange('https://api.example.test'),
      collector: passThroughCollector(),
      session: session.session,
      facade: facade.facade,
      secrets: null,
      account: account.account,
      progress: fakeProgress().progress,
    });

    await withNoBrowserApi(async () => {
      globalThis.fetch = () =>
        Promise.resolve(
          new Response(JSON.stringify(grant), { headers: { 'content-type': 'application/json' } })
        );
      await flow.loginWithGoogle('google.id.token');
    });

    expect(session.calls.logins).toHaveLength(1);
    expect(facade.calls.secrets).toHaveLength(1);
    expect(account.calls.signedIn).toEqual([{ method: 'google', email: null }]);
  });

  it('cannot reach React at all', async () => {
    // React is not a declared dependency, so this package's module graph cannot
    // resolve it: an import added here would fail to load rather than pass.
    const react = 'react';
    await expect(import(/* @vite-ignore */ react)).rejects.toThrow();
  });
});
