import type { Page } from '@playwright/test';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { signInWithWallet } from './fixtures';
import { reloadVault, restoreVault, resumeSession } from './restoreVault';

// Vitest owns polling in the harness unit gate; the page objects and helper are real.
vi.mock('@playwright/test', () => ({ expect }));
vi.mock('./fixtures', () => ({ signInWithWallet: vi.fn() }));

const POLY_FAILURE = 'master poly commits inconsistent with tssPubKey';

function browser() {
  const visible = new Map<string, string>();
  const calls = {
    goto: vi.fn(),
    reload: vi.fn(),
    getByTestId(id: string) {
      const locator = {
        id,
        first: () => locator,
        count: async () => (visible.has(id) ? 1 : 0),
        isVisible: async () => visible.has(id),
        innerText: async () => visible.get(id) ?? '',
      };
      return locator;
    },
  };
  return { visible, calls, page: calls as unknown as Page };
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
      expect.objectContaining({ id: 'file-browser' })
    );
  });

  it('reports a lost session even if the sign-in page has no error', async () => {
    const b = browser();
    b.visible.set('wallet-login-button', '');

    await expect(restoreVault(b.page)).rejects.toThrow('returned to sign-in without an error');
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

    expect(signInWithWallet).toHaveBeenCalledExactlyOnceWith(b.page, joinable);
    expect(b.calls.goto).not.toHaveBeenCalled();
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
    ['returned to sign-in without an error', 'none'],
  ])(
    'fails with the full refusal and its fault class, with no new login: %s',
    async (refusal, fault) => {
      const b = browser();
      if (refusal !== 'returned to sign-in without an error') b.visible.set('login-error', refusal);
      b.visible.set('wallet-login-button', '');

      await expect(reloadVault(b.page)).rejects.toThrow(
        `the saved session did not restore: ${refusal}; devnet fault: ${fault}`
      );
      expect(signInWithWallet).not.toHaveBeenCalled();
    }
  );
});
