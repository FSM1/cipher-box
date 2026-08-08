import { expect, test } from '../fixtures';
import { LoginPage } from '../page-objects/login.page';

/** The build-flag invariant, asserted on the artifact rather than on the source. */
test('the release bundle exposes no introspection hook', async ({ page }) => {
  await page.goto('/');
  // Proves this is the app, not an error page.
  await expect(new LoginPage(page).googleButton).toBeVisible();

  expect(await page.evaluate(() => '__CIPHERBOX_ENGINE__' in window)).toBe(false);
});

test('the release bundle registers the built service worker', async ({ page }) => {
  await page.goto('/');

  await expect
    .poll(() => page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? null))
    .toMatch(/\/sw\.js$/);
});
