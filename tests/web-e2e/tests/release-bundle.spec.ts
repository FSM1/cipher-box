import { expect, test } from '@playwright/test';
import { LoginPage } from '../page-objects/login.page';

/**
 * The build-flag invariant, asserted on the artifact rather than on the source:
 * the same production build without `VITE_E2E_HOOK` must carry no engine taps
 * and no injected cold start.
 */
test('the release bundle exposes no introspection hook', async ({ page }) => {
  await page.goto('/');
  // The front door rendering is what proves this is the app and not an error
  // page, so the assertion below is about an absent hook, not an absent bundle.
  await expect(new LoginPage(page).googleButton).toBeVisible();

  expect(await page.evaluate(() => '__CIPHERBOX_ENGINE__' in window)).toBe(false);
});
