import { expect, test, type Page } from '@playwright/test';

/**
 * The engine-worker slice of the merge-blocking browser suite
 * (blueprint/testing.md law 1, blueprint/web-client.md "Engine hosting"). It
 * covers the promise-correlated RPC layer, the one-way event stream, the
 * bigint/transfer boundary, and cold start + logout — the real engine over the
 * real seams, the protocol fake where the engine cannot yet drive a property.
 */

interface RealEngineResult {
  beforeStart: string;
  startOk: boolean;
  secretDetached: boolean;
  afterStart: string;
  afterLogout: string;
}

interface EngineHarness {
  runRealEngine(): Promise<RealEngineResult>;
  runFakeOutOfOrder(): Promise<{ order: string[] }>;
  runFakeEvents(): Promise<{ events: number[] }>;
  runBoundary(name: string): Promise<{ ok: boolean; error?: string }>;
}

test.describe('engine worker host', () => {
  test.beforeEach(async ({ page }) => {
    page.on('console', (message) => {
      if (message.type() === 'debug') return;
      console.log(`[browser:${message.type()}] ${message.text()}`);
    });
    page.on('pageerror', (error) => console.log(`[browser:pageerror] ${error.message}`));
    await page.goto('/');
    await page.waitForFunction(
      () => typeof (window as unknown as { runRealEngine?: unknown }).runRealEngine === 'function'
    );
  });

  test('cold start, RPC round-trip, and logout teardown end to end', async ({ page }) => {
    const result: RealEngineResult = await page.evaluate(() =>
      (window as unknown as EngineHarness).runRealEngine()
    );

    // A command before start is rejected as "not started" (start lifecycle gate).
    expect(result.beforeStart).toContain('not started');
    // start(secret) resolves: the secret transferred in and the engine came up.
    expect(result.startOk).toBe(true);
    expect(result.secretDetached).toBe(true);
    // Post-start the engine answers (its command pipeline is unimplemented, but
    // it is started) — proving a correlated round-trip to the real engine.
    expect(result.afterStart).toContain('not implemented');
    // After logout the transport is torn down and rejects further work.
    expect(result.afterLogout).toContain('closed');
  });

  test('RPC responses correlate by id even when answered out of order', async ({ page }) => {
    const { order } = await page.evaluate(() =>
      (window as unknown as EngineHarness).runFakeOutOfOrder()
    );
    // The second-issued command is answered first; both promises still resolve,
    // each matched to its own request.
    expect(order).toEqual(['second', 'first']);
  });

  test('the event stream is delivered in order with no drops', async ({ page }) => {
    const { events } = await page.evaluate(() =>
      (window as unknown as EngineHarness).runFakeEvents()
    );
    expect(events).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  });

  test('the u64 event boundary round-trips a bigint beyond MAX_SAFE_INTEGER', async ({ page }) => {
    const outcome = await runBoundary(page, 'bigint');
    expect(outcome.error ?? '', 'bigint boundary failure').toBe('');
    expect(outcome.ok).toBe(true);
  });

  test('a WASM-backed seam view is copied before await, surviving detachment', async ({ page }) => {
    const outcome = await runBoundary(page, 'stagingDetachment');
    expect(outcome.error ?? '', 'staging detachment failure (#717)').toBe('');
    expect(outcome.ok).toBe(true);
  });
});

function runBoundary(page: Page, name: string): Promise<{ ok: boolean; error?: string }> {
  return page.evaluate(
    (boundary) => (window as unknown as EngineHarness).runBoundary(boundary),
    name
  );
}
