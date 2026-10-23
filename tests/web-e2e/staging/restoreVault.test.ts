import type { Page } from '@playwright/test';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RETURNED_TO_SIGN_IN } from '../page-objects/login.page';
import { signInWithWallet } from './fixtures';
import { reloadVault, restoreVault, resumeSession } from './restoreVault';

// Vitest owns polling in the harness unit gate; the page objects and helper are real.
vi.mock('@playwright/test', () => ({ expect }));
vi.mock('./fixtures', () => ({ signInWithWallet: vi.fn() }));

const POLY_FAILURE = 'master poly commits inconsistent with tssPubKey';

type Listener = (event: unknown) => void;

function browser() {
  const visible = new Map<string, string>();
  const disabled = new Set<string>();
  const listeners = new Map<string, Set<Listener>>();
  const calls = {
    goto: vi.fn(),
    reload: vi.fn(),
    on(name: string, listener: Listener) {
      listeners.set(name, (listeners.get(name) ?? new Set()).add(listener));
    },
    off(name: string, listener: Listener) {
      listeners.get(name)?.delete(listener);
    },
    getByTestId(id: string) {
      return {
        id,
        isVisible: async () => visible.has(id),
        isEnabled: async () => !disabled.has(id),
        allInnerTexts: async () => (visible.has(id) ? [visible.get(id)!] : []),
      };
    },
  };
  const failRequest = (url: string, errorText: string): void => {
    const request = { url: () => url, failure: () => ({ errorText }) };
    for (const listener of listeners.get('requestfailed') ?? []) listener(request);
  };
  return { visible, disabled, calls, listeners, failRequest, page: calls as unknown as Page };
}

beforeEach(() => {
  vi.mocked(signInWithWallet).mockReset();
});

describe('returning to the vault with a saved session', () => {
  it('waits for the file browser when the session restores', async () => {
    const b = browser();
    const restored = restoreVault(b.page);
    b.visible.set('file-browser', '');

    expect((await restored).page).toBe(b.page);
    expect(b.calls.goto).toHaveBeenCalledExactlyOnceWith('/files');
    expect(signInWithWallet).not.toHaveBeenCalled();
  });

  it.each([
    'the request to api-staging.cipherbox.cc failed with status 429',
    'sign out in that tab, or close it, then sign in again here.',
  ])('reports a refused restore without another login: %s', async (refusal) => {
    const b = browser();
    b.visible.set('login-error', refusal);
    b.visible.set('wallet-login-button', '');

    await expect(restoreVault(b.page)).rejects.toThrow(
      `the saved session did not restore: ${refusal}; devnet fault: none`
    );
    expect(b.calls.goto).toHaveBeenCalledTimes(1);
    expect(signInWithWallet).not.toHaveBeenCalled();
  });

  it('signs in again through the retry fixture when a devnet fault refuses the resume', async () => {
    const b = browser();
    b.visible.set('login-error', POLY_FAILURE);
    b.visible.set('wallet-login-button', '');

    await restoreVault(b.page);

    expect(signInWithWallet).toHaveBeenCalledExactlyOnceWith(
      b.page,
      expect.objectContaining({ id: 'file-browser' }),
      POLY_FAILURE,
      []
    );
  });

  it('waits out a disabled wallet button while the resume runs', async () => {
    const b = browser();
    b.visible.set('wallet-login-button', '');
    b.disabled.add('wallet-login-button');
    setTimeout(() => b.visible.set('file-browser', ''), 100);

    await restoreVault(b.page);

    expect(signInWithWallet).not.toHaveBeenCalled();
  });

  it('reports a lost session even if the sign-in page has no error', async () => {
    const b = browser();
    b.visible.set('wallet-login-button', '');

    await expect(restoreVault(b.page)).rejects.toThrow(RETURNED_TO_SIGN_IN);
    expect(signInWithWallet).not.toHaveBeenCalled();
  });

  it('redacts the refusal before it enters the public test report', async () => {
    const b = browser();
    const secret = 'a'.repeat(64);
    b.visible.set('login-error', `refused ${secret} for person@example.test`);

    await expect(restoreVault(b.page)).rejects.toThrow(
      'the saved session did not restore: refused [redacted] for [redacted]'
    );
  });

  it('bounds a restore that never reaches either the vault or sign-in', async () => {
    const b = browser();

    await expect(restoreVault(b.page, 20)).rejects.toThrow('neither signed in nor refused');
  });
});

describe('resuming a session on a page that is already open', () => {
  it('waits for the locator the caller names, and signs in again on a devnet fault', async () => {
    const b = browser();
    const joinable = b.page.getByTestId('invite-join');
    b.visible.set('login-error', POLY_FAILURE);
    b.visible.set('wallet-login-button', '');

    await resumeSession(b.page, joinable);

    expect(signInWithWallet).toHaveBeenCalledExactlyOnceWith(b.page, joinable, POLY_FAILURE, []);
    expect(b.calls.goto).not.toHaveBeenCalled();
  });

  it('signs in again on Failed to fetch when a request to a devnet node failed', async () => {
    const b = browser();
    const joinable = b.page.getByTestId('invite-join');
    const resume = resumeSession(b.page, joinable);
    b.failRequest('https://node-3.dev-node.web3auth.io/rss/rss_round_1', 'net::ERR_FAILED');
    b.visible.set('login-error', 'Failed to fetch');
    b.visible.set('wallet-login-button', '');

    await resume;

    expect(signInWithWallet).toHaveBeenCalledExactlyOnceWith(b.page, joinable, 'Failed to fetch', [
      'node-3.dev-node.web3auth.io/rss/rss_round_1 net::ERR_FAILED',
    ]);
    expect(b.listeners.get('requestfailed')?.size).toBe(0);
  });

  it('names the failed host of Failed to fetch elsewhere, and does not sign in', async () => {
    const b = browser();
    const resume = resumeSession(b.page, b.page.getByTestId('invite-join'));
    b.failRequest('https://api.example.com/auth/refresh', 'net::ERR_FAILED');
    b.visible.set('login-error', 'Failed to fetch');
    b.visible.set('wallet-login-button', '');

    await expect(resume).rejects.toThrow(
      'devnet fault: none; the refused requests: api.example.com/auth/refresh net::ERR_FAILED'
    );
    expect(signInWithWallet).not.toHaveBeenCalled();
  });

  it('does not sign in when the resume reaches the locator', async () => {
    const b = browser();
    b.visible.set('invite-join', '');

    await resumeSession(b.page, b.page.getByTestId('invite-join'));

    expect(signInWithWallet).not.toHaveBeenCalled();
  });
});

describe('reloading the vault', () => {
  it('reloads once and waits for the file browser', async () => {
    const b = browser();
    b.visible.set('file-browser', '');

    expect((await reloadVault(b.page)).page).toBe(b.page);
    expect(b.calls.reload).toHaveBeenCalledTimes(1);
    expect(b.calls.goto).not.toHaveBeenCalled();
  });

  it.each([
    [POLY_FAILURE, 'poly-commits'],
    ["Cannot read properties of undefined (reading 'ciphertext')", 'rss-envelope'],
    ['the engine refused the vault anchor at its cold start', 'none'],
  ])(
    'fails with the full refusal and its fault class, with no new login: %s',
    async (refusal, fault) => {
      const b = browser();
      b.visible.set('login-error', refusal);
      b.visible.set('wallet-login-button', '');

      await expect(reloadVault(b.page)).rejects.toThrow(
        `the saved session did not restore: ${refusal}; devnet fault: ${fault}`
      );
      expect(signInWithWallet).not.toHaveBeenCalled();
    }
  );

  it('fails a reload that returns to sign-in with no banner, with no new login', async () => {
    const b = browser();
    b.visible.set('wallet-login-button', '');

    await expect(reloadVault(b.page)).rejects.toThrow(
      `the saved session did not restore: ${RETURNED_TO_SIGN_IN}; devnet fault: none`
    );
    expect(signInWithWallet).not.toHaveBeenCalled();
  });
});
