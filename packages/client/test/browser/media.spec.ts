import { createHash } from 'node:crypto';
import { expect, test, type BrowserContext, type Page } from '@playwright/test';

import { hex } from './hexUtil.js';
import { fixtureSlice, LEADER_SEED, SECOND_TAB_SEED, TAB_SEED } from './mediaFixture.js';
import type { MediaFetchResult } from './media.js';
import { MEDIA_WINDOW_BYTES } from '../../src/media/protocol.js';

/**
 * The Service Worker media-brokerage slice of the merge-blocking browser suite
 * (blueprint/testing.md law 1, blueprint/web-client.md "Streaming media — the SW
 * is a dumb pipe"). A real Service Worker intercepts real `/stream/` fetches and
 * forwards them over a real `MessageChannel` to the tab-side broker, whose
 * windowed reads come back as a real `ReadableStream`.
 */

interface MediaHarness {
  cbMediaEngine(options: { lockName: string; channelName: string }): Promise<string>;
  cbMediaStart(options: { reader: 'local' | 'engine'; seed?: number }): Promise<boolean>;
  cbMediaAwaitControl(): Promise<boolean>;
  cbMediaTicket(size: number, mimeType: string): string;
  cbMediaFetch(url: string, range: string | null): Promise<MediaFetchResult>;
  cbMediaReaderCalls(): number;
  cbMediaOpenCalls(): number;
  cbMediaPortRequests(): number;
  cbMediaDispose(): Promise<void>;
}

const MIME = 'video/mp4';
let testSeq = 0;

function digestOf(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function headers(result: MediaFetchResult): Map<string, string> {
  return new Map(result.headers);
}

function names(): { lockName: string; channelName: string } {
  testSeq += 1;
  return { lockName: `cb-media-lock-${testSeq}`, channelName: `cb-media-chan-${testSeq}` };
}

interface Tab {
  page: Page;
  engine(lockName: string, channelName: string): Promise<string>;
  start(reader: 'local' | 'engine', seed?: number): Promise<boolean>;
  awaitControl(): Promise<boolean>;
  ticket(size: number): Promise<string>;
  fetch(url: string, range?: string): Promise<MediaFetchResult>;
  readerCalls(): Promise<number>;
  openCalls(): Promise<number>;
  portRequests(): Promise<number>;
  dispose(): Promise<void>;
}

async function openTab(context: BrowserContext): Promise<Tab> {
  const page = await context.newPage();
  page.on('pageerror', (error) => console.log(`[browser:pageerror] ${error.message}`));
  await page.goto('/');
  await page.waitForFunction(
    () => typeof (window as unknown as { cbMediaStart?: unknown }).cbMediaStart === 'function'
  );
  return {
    page,
    engine: (lockName, channelName) =>
      page.evaluate((opts) => (window as unknown as MediaHarness).cbMediaEngine(opts), {
        lockName,
        channelName,
      }),
    start: (reader, seed) =>
      page.evaluate((opts) => (window as unknown as MediaHarness).cbMediaStart(opts), {
        reader,
        seed,
      }),
    awaitControl: () =>
      page.evaluate(() => (window as unknown as MediaHarness).cbMediaAwaitControl()),
    ticket: (size) =>
      page.evaluate(
        (args) => (window as unknown as MediaHarness).cbMediaTicket(args.size, args.mime),
        { size, mime: MIME }
      ),
    fetch: (url, range) =>
      page.evaluate(
        (args) => (window as unknown as MediaHarness).cbMediaFetch(args.url, args.range),
        {
          url,
          range: range ?? null,
        }
      ),
    readerCalls: () =>
      page.evaluate(() => (window as unknown as MediaHarness).cbMediaReaderCalls()),
    openCalls: () => page.evaluate(() => (window as unknown as MediaHarness).cbMediaOpenCalls()),
    portRequests: () =>
      page.evaluate(() => (window as unknown as MediaHarness).cbMediaPortRequests()),
    dispose: () => page.evaluate(() => (window as unknown as MediaHarness).cbMediaDispose()),
  };
}

/** A controlled tab whose broker serves the fixture bytes for `seed`. */
async function localTab(context: BrowserContext, seed?: number): Promise<Tab> {
  const tab = await openTab(context);
  expect(await tab.start('local', seed)).toBe(true);
  expect(await tab.awaitControl()).toBe(true);
  return tab;
}

test.describe('Service Worker media brokerage over a real byte pipe', () => {
  test('a whole-file request returns 200 with the exact bytes, ranges offered and no-store', async ({
    context,
  }) => {
    const tab = await localTab(context);
    const size = 4096;

    const result = await tab.fetch(await tab.ticket(size));

    expect(result.status).toBe(200);
    expect(result.bodyHex).toBe(hex(fixtureSlice(0, size, TAB_SEED)));
    const head = headers(result);
    expect(head.get('accept-ranges')).toBe('bytes');
    expect(head.get('cache-control')).toBe('no-store');
    expect(head.get('content-type')).toBe(MIME);
    expect(head.get('content-length')).toBe(String(size));

    await tab.dispose();
  });

  test('a Range request returns 206 with the window bytes and a matching content-range', async ({
    context,
  }) => {
    const tab = await localTab(context);
    const size = 4096;

    const result = await tab.fetch(await tab.ticket(size), 'bytes=1000-1999');

    expect(result.status).toBe(206);
    expect(result.bodyHex).toBe(hex(fixtureSlice(1000, 1000, TAB_SEED)));
    const head = headers(result);
    expect(head.get('content-range')).toBe(`bytes 1000-1999/${size}`);
    expect(head.get('content-length')).toBe('1000');

    await tab.dispose();
  });

  test('a range past EOF returns 416 with the unsatisfiable content-range', async ({ context }) => {
    const tab = await localTab(context);
    const size = 4096;

    const result = await tab.fetch(await tab.ticket(size), `bytes=${size}-`);

    expect(result.status).toBe(416);
    expect(result.byteLength).toBe(0);
    expect(headers(result).get('content-range')).toBe(`bytes */${size}`);

    await tab.dispose();
  });

  test('an unknown ticket returns 404', async ({ context }) => {
    const tab = await localTab(context);

    const result = await tab.fetch('/stream/no-such-ticket');

    expect(result.status).toBe(404);
    expect(result.byteLength).toBe(0);

    await tab.dispose();
  });

  test('a file larger than one window streams through several windows, byte-exact', async ({
    context,
  }) => {
    const tab = await localTab(context);
    const size = MEDIA_WINDOW_BYTES * 2 + 512 * 1024;

    const result = await tab.fetch(await tab.ticket(size));

    expect(result.status).toBe(200);
    expect(result.byteLength).toBe(size);
    expect(result.digestHex).toBe(digestOf(fixtureSlice(0, size, TAB_SEED)));
    // Peak memory is one window, not the file: one read per window, no more.
    expect(await tab.readerCalls()).toBe(Math.ceil(size / MEDIA_WINDOW_BYTES));
    // And one pinned version for the whole body, not one resolve per window.
    expect(await tab.openCalls()).toBe(1);

    await tab.dispose();
  });

  test('two open tabs each stream from their own broker', async ({ context }) => {
    const a = await localTab(context, TAB_SEED);
    const b = await localTab(context, SECOND_TAB_SEED);
    const sizeA = 4096;
    const sizeB = 2048;
    const ticketA = await a.ticket(sizeA);
    const ticketB = await b.ticket(sizeB);

    // B brokered last, so a worker holding one port would answer A's ticket from
    // B's registry — which has never seen it.
    const fromA = await a.fetch(ticketA);
    const fromB = await b.fetch(ticketB);

    expect(fromA.status).toBe(200);
    expect(fromA.bodyHex).toBe(hex(fixtureSlice(0, sizeA, TAB_SEED)));
    expect(fromB.status).toBe(200);
    expect(fromB.bodyHex).toBe(hex(fixtureSlice(0, sizeB, SECOND_TAB_SEED)));

    await b.dispose();
    await a.dispose();
  });

  test('a killed Service Worker re-brokers a port and the next request still streams', async ({
    context,
  }) => {
    const tab = await localTab(context);
    const size = 2048;
    const ticket = await tab.ticket(size);
    expect((await tab.fetch(ticket)).status).toBe(200);

    const before = await tab.portRequests();
    const cdp = await context.newCDPSession(tab.page);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    await cdp.detach();

    // A restarted worker holds no port, so it must ask the tab for a fresh one
    // before it can answer — this request succeeds only if it re-brokered.
    const result = await tab.fetch(ticket);
    expect(result.status).toBe(200);
    expect(result.bodyHex).toBe(hex(fixtureSlice(0, size, TAB_SEED)));
    expect(await tab.portRequests()).toBeGreaterThan(before);

    await tab.dispose();
  });

  test('a follower tab routes its media read through the leader engine', async ({ context }) => {
    const { lockName, channelName } = names();
    const a = await openTab(context);
    const b = await openTab(context);

    expect(await a.engine(lockName, channelName)).toBe('leader');
    expect(await b.engine(lockName, channelName)).toBe('follower');

    // Only the follower brokers a port, so the pipe answers from its reader —
    // the broadcast wire to the leader's engine worker.
    expect(await b.start('engine')).toBe(true);
    expect(await b.awaitControl()).toBe(true);

    const size = 96 * 1024;
    const result = await b.fetch(await b.ticket(size));

    expect(result.status).toBe(200);
    expect(result.byteLength).toBe(size);
    // The leader's seed: bytes the follower's own tab never synthesizes.
    expect(result.digestHex).toBe(digestOf(fixtureSlice(0, size, LEADER_SEED)));

    await b.dispose();
    await a.dispose();
  });
});
