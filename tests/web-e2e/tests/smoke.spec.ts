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
 * Everything the origin is allowed to leave in Web Storage. Core Kit is the only
 * thing this app gives a store to (`apps/web/src/auth/coreKit.ts`), and that store
 * is a bearer path back to a logged-in session — so anything appearing beside it
 * fails here rather than passing review.
 *
 * `loglevel` caches a log level per named logger at import time; it holds no
 * session state.
 */
const ALLOWED_STORAGE_KEY = /^loglevel:/;

/**
 * Deliberately scoped to what the app itself persists: this build carries no
 * Web3Auth credentials, so `createCoreKitSession` throws and Core Kit never
 * constructs — the suite signs in through the introspection hook instead, and has
 * no interactive session whose key set it could observe. What it gates is that the
 * login flow, the cold start and a reload add nothing of their own beside it.
 */
test('a signed-in tab leaves nothing outside the storage allow-list', async ({ page }) => {
  const vault = new VaultPage(page);

  await vault.open();
  await vault.coldStart();
  await vault.settled();
  // Nothing in the tab survives a reload in memory, so what answers afterwards is
  // exactly what the flow persisted.
  await vault.open();

  const stored = await page.evaluate(() => ({
    local: Object.keys(localStorage),
    session: Object.keys(sessionStorage),
  }));

  expect(stored.local.filter((key) => !ALLOWED_STORAGE_KEY.test(key))).toEqual([]);
  expect(stored.session).toEqual([]);
});
