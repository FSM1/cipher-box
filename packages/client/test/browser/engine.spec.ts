import { expect, test, type Page } from '@playwright/test';

import type { BoundaryOutcome, RealEngineResult, SnapshotSuiteResult } from './engineHarness.js';

/**
 * The engine-worker slice of the merge-blocking browser suite
 * (blueprint/testing.md law 1, blueprint/web-client.md "Engine hosting"). It
 * covers the promise-correlated RPC layer, the one-way event stream, the
 * bigint/transfer boundary, and cold start + logout — the real engine over the
 * real seams, the protocol fake where the engine cannot yet drive a property.
 */

interface EngineHarness {
  runRealEngine(): Promise<RealEngineResult>;
  runSnapshotSuite(): Promise<SnapshotSuiteResult>;
  runFakeOutOfOrder(): Promise<{ order: string[] }>;
  runFakeEvents(): Promise<{ events: number[] }>;
  runBoundary(name: string): Promise<BoundaryOutcome>;
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

  // The auth mock backs the cold-start assertion below, so it has to answer
  // every request: one that throws mid-handler leaves the engine's own fetch
  // hanging, and this suite reports a timeout instead of the real failure.
  test('the auth mock answers a malformed body rather than hanging', async ({ request }) => {
    for (const route of ['challenge', 'login']) {
      const response = await request.post(`/mock-api/engine/auth/${route}`, {
        headers: { 'content-type': 'application/json' },
        data: 'null',
      });
      expect(response.status()).toBe(400);
    }
  });

  test('cold start, RPC round-trip, and logout teardown end to end', async ({ page, request }) => {
    const before = await (await request.get('/mock-api/engine/auth/seen')).json();
    const result: RealEngineResult = await page.evaluate(() =>
      (window as unknown as EngineHarness).runRealEngine()
    );

    // Cold start exchanged a challenge for tokens: a start that skipped the
    // login would resolve just the same, so the mock's own tally is the proof.
    const after = await (await request.get('/mock-api/engine/auth/seen')).json();
    expect(after.logins).toBe(before.logins + 1);
    expect(after.challenges).toBe(before.challenges + 1);

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

  test('snapshot and download reads over the real engine', async ({ page }) => {
    const result: SnapshotSuiteResult = await page.evaluate(() =>
      (window as unknown as EngineHarness).runSnapshotSuite()
    );

    // The snapshot echoes the anchored all-zero root as both root and folder.
    expect(result.rootEchoed).toBe(true);

    // A rootless read is answered from the engine's own root, so a host never
    // has to name one before it has seen a view (#900).
    expect(result.rootlessFolderHex).toBe(result.rootHex);

    // Both metadata creates project as pending children with no content plane.
    expect(result.children).toHaveLength(2);
    const docs = result.children.find((child) => child.name === 'docs');
    const file = result.children.find((child) => child.name === 'pending.txt');
    expect(docs).toMatchObject({ kind: 'folder', pending: 'metadata', deadLetter: false });
    // A pending create authors the node's next record, so the overlay stamps
    // its authored time; size stays absent until the content plane projects it.
    expect(file).toMatchObject({
      kind: 'file',
      pending: 'metadata',
      deadLetter: false,
      sizeNull: true,
      mtimeNull: false,
    });

    // The nested folder's breadcrumb trail ends at the root.
    expect(result.nestedAncestors.length).toBeGreaterThanOrEqual(1);
    expect(result.nestedAncestors.at(-1)!.idHex).toBe(result.rootHex);

    // An unknown node fails with the engine's stable code, crossed intact —
    // plus the human-readable message alongside it.
    expect(result.unknownCode).toBe('unknownNode');
    expect(result.unknownError).toContain('unknown node');
    // A pending-only file has no published content: availability, not trust.
    expect(result.downloadCode).toBe('contentUnavailable');
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

  test('a WASM-backed staging key is encoded before await, surviving detachment', async ({
    page,
  }) => {
    const outcome = await runBoundary(page, 'stagingKeyDetachment');
    expect(outcome.error ?? '', 'staging key detachment failure (#717)').toBe('');
    expect(outcome.ok).toBe(true);
  });

  test('a WASM-backed snapshot key is encoded before await, surviving detachment', async ({
    page,
  }) => {
    const outcome = await runBoundary(page, 'snapshotKeyDetachment');
    expect(outcome.error ?? '', 'snapshot key detachment failure (#717)').toBe('');
    expect(outcome.ok).toBe(true);
  });

  test('a WASM-backed floor key is encoded before await, surviving detachment', async ({
    page,
  }) => {
    const outcome = await runBoundary(page, 'floorKeyDetachment');
    expect(outcome.error ?? '', 'floor key detachment failure (#730)').toBe('');
    expect(outcome.ok).toBe(true);
  });
});

function runBoundary(page: Page, name: string): Promise<BoundaryOutcome> {
  return page.evaluate(
    (boundary) => (window as unknown as EngineHarness).runBoundary(boundary),
    name
  );
}
