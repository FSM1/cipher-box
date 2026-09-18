/**
 * The two front defects the v2.0.2 deploy shipped, watched on the wire of a
 * real session: a record publish the browser never completes, and a read answer
 * the browser is told it may reuse.
 *
 * The cases after the first are the proof of what those checks do with an
 * answer they did not see in the real session: three answer the same requests
 * with a broken front and assert the check refuses them, and the last holds the
 * check to a publish the front answered whose answer the browser then dropped.
 */

import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { expect, signIn, test } from './fixtures';
import { routingOrigin, watchRoutingFront } from './frontContract';

/** A name nothing has ever published under, so a read of it is a vacancy. */
const ABSENT = 'k51qzi5uqu5dh9ihj4p2v5sl3hxvbgvpsnbnbxjdvgfcgb0w5s4nxjdsfyqzjt';

/** Drives one read and one publish of that name from the page's own origin. */
async function probe(page: Page, routing: string, method: 'GET' | 'PUT'): Promise<void> {
  await page.evaluate(
    async ([url, verb]) => {
      await fetch(url, {
        method: verb,
        ...(verb === 'PUT'
          ? {
              headers: { 'content-type': 'application/vnd.ipfs.ipns-record' },
              body: new Uint8Array([1, 2, 3]),
            }
          : {}),
      }).catch(() => undefined);
    },
    [`${routing}/routing/v1/ipns/${ABSENT}`, method] as const
  );
}

test('the routing front carries a real session', async ({ page, baseURL }) => {
  const log = watchRoutingFront(page, routingOrigin(baseURL!));

  await signIn(page);
  const files = new FilesPage(page);
  await files.createFolder('front-contract');
  await expect(files.row('front-contract')).toBeVisible();
  // The write is queued before it is published; the publish is what this reads.
  await expect
    .poll(() => log.publishes.length + log.refusedPublishes.length, { timeout: 180_000 })
    .toBeGreaterThan(0);

  expect(log.refusedPublishes, 'the front landed every record publish').toEqual([]);
  expect(log.reads.length, 'the session read the routing front').toBeGreaterThan(0);
  expect(log.cacheableReads, 'no read answer carried a cache lifetime').toEqual([]);
});

test('the check refuses a front that blocks the record publish', async ({ page, baseURL }) => {
  const routing = routingOrigin(baseURL!);
  const log = watchRoutingFront(page, routing);
  // What the browser does with a preflight whose allow list omits the record
  // media type: it never sends the request.
  await page.route(`${routing}/routing/v1/ipns/*`, (route) => route.abort('failed'));

  await page.goto('/');
  await probe(page, routing, 'PUT');

  expect(log.refusedPublishes).not.toEqual([]);
});

test('the check refuses a front that answers the record publish with a refusal', async ({
  page,
  baseURL,
}) => {
  const routing = routingOrigin(baseURL!);
  const log = watchRoutingFront(page, routing);
  // A publish the front answers rather than drops: the request completes, so
  // only the status separates a landed record from a refused one.
  const cors = {
    'access-control-allow-origin': new URL(baseURL!).origin,
    'access-control-allow-methods': 'GET, PUT, OPTIONS',
    'access-control-allow-headers': 'content-type',
  };
  await page.route(`${routing}/routing/v1/ipns/*`, (route) =>
    route.request().method() === 'OPTIONS'
      ? route.fulfill({ status: 204, headers: cors })
      : route.fulfill({ status: 502, headers: cors, body: 'bad gateway' })
  );

  await page.goto('/');
  await probe(page, routing, 'PUT');

  await expect.poll(() => log.refusedPublishes).not.toEqual([]);
  expect(log.publishes, 'a refused publish is never counted as a publish').toEqual([]);
});

/**
 * A front of its own, whose publish answer carries a body it never finishes, so
 * a caller that drops that body leaves an answered request the browser reports
 * as failed. `page.route` cannot stage this: it serves a whole body.
 */
async function slowAnsweringFront(): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = createServer((request, response) => {
    if (request.url === '/') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<!doctype html><title>routing front</title>');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '20000000' });
    const pump = setInterval(() => response.write('x'.repeat(64_000)), 50);
    response.on('close', () => clearInterval(pump));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test('the check accepts a publish whose answer the browser dropped', async ({ page }) => {
  const front = await slowAnsweringFront();
  try {
    const log = watchRoutingFront(page, front.origin);
    const failed: string[] = [];
    page.on('requestfailed', (request) => failed.push(request.url()));

    await page.goto(`${front.origin}/`);
    await page.evaluate(async (url) => {
      // What the record transport does with a publish answer: it reads the
      // status and never the body.
      const answer = await fetch(url, { method: 'PUT', body: new Uint8Array([1, 2, 3]) });
      await answer.body?.cancel();
    }, `${front.origin}/routing/v1/ipns/${ABSENT}`);

    await expect.poll(() => failed).not.toEqual([]);
    expect(log.publishes, 'the front answered the publish').not.toEqual([]);
    expect(log.refusedPublishes, 'an answered publish is never refused').toEqual([]);
  } finally {
    await front.close();
  }
});

test('the check refuses a cacheable vacancy', async ({ page, baseURL }) => {
  const routing = routingOrigin(baseURL!);
  const log = watchRoutingFront(page, routing);
  // someguy's own answer for a missing name, which the front must override.
  await page.route(`${routing}/routing/v1/ipns/*`, (route) =>
    route.fulfill({
      status: 200,
      headers: {
        'access-control-allow-origin': new URL(baseURL!).origin,
        'cache-control': 'public, max-age=15, stale-while-revalidate=172800',
      },
      body: 'not found',
    })
  );

  await page.goto('/');
  await probe(page, routing, 'GET');

  expect(log.cacheableReads).not.toEqual([]);
});
