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

/**
 * The served artifact refuses framing — a signed-in vault an attacker's page can
 * embed is a clickjacking surface over every route.
 */
test('the served bundle cannot be framed', async ({ page }) => {
  const response = await page.goto('/');
  expect(response?.headers()['content-security-policy']).toContain("frame-ancestors 'none'");

  // Blocked, the frame is replaced by an opaque-origin error page, so its
  // document stops being reachable from a parent on its own origin.
  const reachable = await page.evaluate(
    () =>
      new Promise<boolean>((resolve) => {
        const frame = document.createElement('iframe');
        const settle = () => resolve(frame.contentDocument !== null);
        frame.addEventListener('load', settle);
        // A refusal Chromium never announces as a load must still settle.
        setTimeout(settle, 5_000);
        frame.src = '/';
        document.body.append(frame);
      })
  );
  expect(reachable).toBe(false);
});
