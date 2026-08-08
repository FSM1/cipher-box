import { expect, test } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { VaultPage } from '../page-objects/vault.page';

test('the front door offers every built login method', async ({ page }) => {
  const login = new LoginPage(page);
  await page.goto('/');

  await expect(login.googleButton).toBeVisible();
  await expect(login.emailInput).toBeVisible();
  await expect(login.walletButton).toBeVisible();
});

test('the tab comes under the app-shell service worker', async ({ page }) => {
  await page.goto('/');

  await expect
    .poll(() => page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? null))
    .toMatch(/\/sw\.js$/);
});

test('an unauthenticated deep link lands on the front door', async ({ page }) => {
  const files = new FilesPage(page);
  await files.goto();

  await expect(page).toHaveURL(/\/$/);
  await expect(new LoginPage(page).googleButton).toBeVisible();
  await expect(files.browser).toHaveCount(0);
});

test('a cold start opens a fresh vault at its root', async ({ page }) => {
  const vault = new VaultPage(page);
  const files = new FilesPage(page);

  await vault.open();
  await vault.coldStart();
  const { view } = await vault.settled();

  // A first-run vault is anchored at a root that is its own listed folder.
  expect(view.folder).toBe(view.root);
  expect(view.children).toEqual([]);
  expect(view.deadLetters).toEqual([]);
  expect((await vault.events()).map((event) => event.kind)).toContain('snapshotUpdated');

  await expect(files.browser).toBeVisible();
  await expect(files.emptyState).toBeVisible();
  await expect(files.breadcrumbs).toBeVisible();
  await expect(files.status).toHaveAttribute('data-staleness', view.staleness);
});

test('signing out returns the tab to the front door', async ({ page }) => {
  const vault = new VaultPage(page);
  const files = new FilesPage(page);

  await vault.open();
  await vault.coldStart();
  await vault.settled();
  await expect(files.browser).toBeVisible();

  await files.signOut();

  await expect(page).toHaveURL(/\/$/);
  await expect(new LoginPage(page).googleButton).toBeVisible();
  await expect(files.browser).toHaveCount(0);
});

/**
 * The whole accepted key set: Core Kit's own store, which is the only one this
 * app hands out (`apps/web/src/auth/coreKit.ts`), and the log level a torus
 * dependency's logger writes on import.
 */
const ALLOWED_STORAGE_KEY = /^(loglevel|corekit_store$)/;

/**
 * This build carries no Web3Auth credentials, so Core Kit never constructs and
 * the suite signs in through the introspection hook — what this gates is that
 * the login flow and cold start persist nothing of their own beside that set.
 */
test('the login flow leaves nothing outside the storage allow-list', async ({ page }) => {
  const vault = new VaultPage(page);

  await vault.open();
  await vault.coldStart();
  await vault.settled();

  const stored = await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }));

  expect(stored.local.filter((key) => !ALLOWED_STORAGE_KEY.test(key))).toEqual([]);
  expect(stored.session).toEqual([]);
});
