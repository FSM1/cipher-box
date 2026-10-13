import type { Locator, Page } from '@playwright/test';
import { describe, expect, it, vi } from 'vitest';
import { devnetFault } from '../staging/loginRetry';
import { LoginPage } from './login.page';

// Vitest owns polling in the harness unit gate; the page object is real.
vi.mock('@playwright/test', () => ({ expect }));

const POLY_FAILURE = 'master poly commits inconsistent with tssPubKey';
const NONCE_FAILURE = 'could not retrieve nonce: the request failed with status 429';
const CONNECTOR_FAILURE = 'the wallet connector refused the request';

/** A page whose state the test changes between reads; `onRead` runs after each read. */
function browser() {
  const shown = new Set<string>();
  const disabled = new Set<string>();
  const banners: string[] = [];
  const hooks = { onRead: (_id: string) => {} };
  const page = {
    getByTestId(id: string) {
      const read = <T>(value: T): T => {
        hooks.onRead(id);
        return value;
      };
      return {
        isVisible: async () => read(shown.has(id)),
        isEnabled: async () => read(!disabled.has(id)),
        allInnerTexts: async () => read(id === 'login-error' ? [...banners] : []),
      };
    },
  };
  const login = new LoginPage(page as unknown as Page);
  const signedIn = page.getByTestId('file-browser') as unknown as Locator;
  return { shown, disabled, banners, hooks, login, signedIn };
}

describe('the settled outcome of a sign-in or a resume', () => {
  it('reads a disabled wallet button as a resume in flight, and waits for the sign-in', async () => {
    const b = browser();
    b.shown.add('wallet-login-button');
    b.disabled.add('wallet-login-button');
    let reads = 0;
    b.hooks.onRead = (id) => {
      if (id === 'wallet-login-button' && ++reads === 2) b.shown.add('file-browser');
    };

    await expect(b.login.outcome(b.signedIn, 10_000, b.login.walletButton)).resolves.toEqual({
      kind: 'signed-in',
    });
  });

  it('reads a banner drawn in the same update as the button as the refusal', async () => {
    const b = browser();
    b.hooks.onRead = (id) => {
      if (id !== 'login-error' || b.banners.length > 0) return;
      b.banners.push(POLY_FAILURE);
      b.shown.add('wallet-login-button');
    };

    await expect(b.login.outcome(b.signedIn, 10_000, b.login.walletButton)).resolves.toEqual({
      kind: 'refused',
      text: POLY_FAILURE,
    });
  });

  it('reads an enabled wallet button with no banner as signed out', async () => {
    const b = browser();
    b.shown.add('wallet-login-button');

    await expect(b.login.outcome(b.signedIn, 10_000, b.login.walletButton)).resolves.toEqual({
      kind: 'signed-out',
    });
  });

  it('reads every banner on the page', async () => {
    const b = browser();
    b.banners.push(POLY_FAILURE, NONCE_FAILURE);

    await expect(b.login.outcome(b.signedIn, 10_000)).resolves.toEqual({
      kind: 'refused',
      text: `${POLY_FAILURE} | ${NONCE_FAILURE}`,
    });
  });
});

describe('the wait for an earlier banner to clear', () => {
  it('stops at a new refusal while the earlier banner stays', async () => {
    const b = browser();
    b.banners.push(POLY_FAILURE);
    setTimeout(() => b.banners.push(NONCE_FAILURE), 200);
    const started = Date.now();

    await expect(b.login.replaced([POLY_FAILURE], 30_000)).resolves.toEqual([NONCE_FAILURE]);

    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('classes a new connector failure next to a stale poly-commits banner as the connector failure', async () => {
    const b = browser();
    b.banners.push(POLY_FAILURE);
    setTimeout(() => b.banners.push(CONNECTOR_FAILURE), 200);

    const fresh = await b.login.replaced([POLY_FAILURE], 30_000);

    expect(fresh).toEqual([CONNECTOR_FAILURE]);
    expect(devnetFault(fresh.join(' | '))).toBeNull();
  });

  it('reads an earlier banner that outlasts the wait as it stands', async () => {
    const b = browser();
    b.banners.push(POLY_FAILURE);

    await expect(b.login.replaced([POLY_FAILURE], 300)).resolves.toEqual([]);
    await expect(b.login.outcome(b.signedIn, 10_000)).resolves.toEqual({
      kind: 'refused',
      text: POLY_FAILURE,
    });
  });

  it('stops once the login clears the banner', async () => {
    const b = browser();
    b.banners.push(POLY_FAILURE);
    setTimeout(() => b.banners.splice(0), 200);
    const started = Date.now();

    await expect(b.login.replaced([POLY_FAILURE], 30_000)).resolves.toEqual([]);

    expect(Date.now() - started).toBeLessThan(5_000);
  });
});
