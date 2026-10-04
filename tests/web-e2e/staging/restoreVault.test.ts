import type { Page } from '@playwright/test';
import { describe, expect, it, vi } from 'vitest';
import { restoreVault } from './restoreVault';

// Vitest owns polling in the harness unit gate; the page objects and helper are real.
vi.mock('@playwright/test', () => ({ expect }));

function browser() {
  const visible = new Map<string, string>();
  const calls = {
    goto: vi.fn(),
    getByTestId(id: string) {
      const locator = {
        first: () => locator,
        isVisible: async () => visible.has(id),
        innerText: async () => visible.get(id) ?? '',
      };
      return locator;
    },
  };
  return { visible, calls, page: calls as unknown as Page };
}

describe('returning to the vault with a saved session', () => {
  it('waits for the file browser when the session restores', async () => {
    const b = browser();
    const restored = restoreVault(b.page);
    b.visible.set('file-browser', '');

    expect((await restored).page).toBe(b.page);
    expect(b.calls.goto).toHaveBeenCalledExactlyOnceWith('/files');
  });

  it.each([
    'master poly commits inconsistent with tssPubKey',
    'the request to api-staging.cipherbox.cc failed with status 429',
    'sign out in that tab, or close it, then sign in again here.',
  ])('reports a refused restore without another login: %s', async (refusal) => {
    const b = browser();
    b.visible.set('login-error', refusal);
    b.visible.set('wallet-login-button', '');

    await expect(restoreVault(b.page)).rejects.toThrow(
      `the saved session did not restore: ${refusal}`
    );
    expect(b.calls.goto).toHaveBeenCalledTimes(1);
  });

  it('reports a lost session even if the sign-in page has no error', async () => {
    const b = browser();
    b.visible.set('wallet-login-button', '');

    await expect(restoreVault(b.page)).rejects.toThrow('returned to sign-in without an error');
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

    await expect(restoreVault(b.page, 20)).rejects.toThrow(
      'the saved session did not restore the file browser'
    );
  });
});
