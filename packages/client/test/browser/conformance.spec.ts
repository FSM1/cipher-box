import { expect, test, type Page } from '@playwright/test';

/**
 * The merge-blocking browser suite (blueprint/testing.md "Host suites").
 *
 * Each seam's engine conformance kit runs against the real browser
 * implementation in a worker realm, over real IndexedDB and OPFS. `http` has no
 * engine kit (its behavior belongs to the live contract suite) — a focused
 * behavioral check stands in for it here.
 */

type SeamOutcome = { ok: boolean; error?: string };

const kitSeams = [
  'floorStore',
  'snapshotCache',
  'stagingStore',
  'credentialStore',
  'scheduler',
  'recordTransport',
] as const;

function runSeam(page: Page, seam: string): Promise<SeamOutcome> {
  return page.evaluate(
    (name) => (window as unknown as { runSeam(s: string): Promise<SeamOutcome> }).runSeam(name),
    seam
  );
}

test.describe('browser seam conformance', () => {
  test.beforeEach(async ({ page }) => {
    // Surface worker console output (including the panic hook's assertion
    // message on a kit failure) into the test log for diagnosis.
    page.on('console', (message) => {
      if (message.type() === 'debug') return; // skip Vite HMR chatter
      console.log(`[browser:${message.type()}] ${message.text()}`);
    });
    page.on('pageerror', (error) => console.log(`[browser:pageerror] ${error.message}`));
    await page.goto('/');
    await page.waitForFunction(
      () => typeof (window as unknown as { runSeam?: unknown }).runSeam === 'function'
    );
  });

  for (const seam of kitSeams) {
    test(`${seam} passes its engine conformance kit`, async ({ page }) => {
      const outcome = await runSeam(page, seam);
      expect(outcome.error ?? '', `${seam} kit failure`).toBe('');
      expect(outcome.ok).toBe(true);
    });
  }

  test('http seam moves bytes and surfaces non-2xx as a response', async ({ page }) => {
    const outcome = await runSeam(page, 'http');
    expect(outcome.error ?? '', 'http behavioral failure').toBe('');
    expect(outcome.ok).toBe(true);
  });
});
