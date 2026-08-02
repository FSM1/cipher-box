import { describe, expect, it } from 'vitest';

import {
  APP_SHELL_CACHE,
  appShellClaims,
  deleteStaleCaches,
  precacheAppShell,
  readPrecachedUrls,
  respondFromAppShell,
} from './precache.js';
import {
  failingFetch,
  FakeCacheStorage,
  manifestFetch,
  SW_ORIGIN as ORIGIN,
} from './testDoubles.js';

/** `mode: 'navigate'` cannot be set through the `Request` constructor. */
const navigation = (url: string): Request =>
  ({ method: 'GET', url, mode: 'navigate' }) as unknown as Request;

describe('precacheAppShell', () => {
  it('caches every same-origin manifest entry', async () => {
    const caches = new FakeCacheStorage();

    await precacheAppShell(caches, manifestFetch('["/index.html","/assets/app.js"]'), ORIGIN);

    expect([...caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([
      `${ORIGIN}/index.html`,
      `${ORIGIN}/assets/app.js`,
    ]);
  });

  it('is a no-op when the build ships no manifest', async () => {
    const caches = new FakeCacheStorage();

    await precacheAppShell(caches, manifestFetch('', false), ORIGIN);

    expect(caches.opened.size).toBe(0);
  });

  it('is a no-op when the manifest body is not a JSON array', async () => {
    const caches = new FakeCacheStorage();

    await precacheAppShell(caches, manifestFetch('<!doctype html>'), ORIGIN);
    await precacheAppShell(caches, manifestFetch('{"files":[]}'), ORIGIN);

    expect(caches.opened.size).toBe(0);
  });

  it('rejects manifest entries that resolve to another origin or the media path', async () => {
    const caches = new FakeCacheStorage();

    await precacheAppShell(
      caches,
      manifestFetch(
        '["/index.html","https://evil.example/x.js","//evil.example/y.js","/stream/t"]'
      ),
      ORIGIN
    );

    expect([...caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([`${ORIGIN}/index.html`]);
  });

  it('caches the reachable entries when one manifest entry will not cache', async () => {
    const caches = new FakeCacheStorage();
    caches.cache(APP_SHELL_CACHE).unreachable.add(`${ORIGIN}/assets/gone.js`);

    await precacheAppShell(
      caches,
      manifestFetch('["/index.html","/assets/gone.js","/assets/app.js"]'),
      ORIGIN
    );

    expect([...caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([
      `${ORIGIN}/index.html`,
      `${ORIGIN}/assets/app.js`,
    ]);
  });

  it('keeps an entry the manifest still lists when its refresh fails', async () => {
    const caches = new FakeCacheStorage();

    await precacheAppShell(caches, manifestFetch('["/index.html","/assets/app.js"]'), ORIGIN);
    caches.cache(APP_SHELL_CACHE).unreachable.add(`${ORIGIN}/assets/app.js`);
    await precacheAppShell(caches, manifestFetch('["/index.html","/assets/app.js"]'), ORIGIN);

    expect([...caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([
      `${ORIGIN}/index.html`,
      `${ORIGIN}/assets/app.js`,
    ]);
  });

  it('prunes entries a later manifest no longer lists', async () => {
    const caches = new FakeCacheStorage();

    await precacheAppShell(caches, manifestFetch('["/index.html","/assets/old.js"]'), ORIGIN);
    await precacheAppShell(caches, manifestFetch('["/index.html","/assets/new.js"]'), ORIGIN);

    expect([...caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([
      `${ORIGIN}/index.html`,
      `${ORIGIN}/assets/new.js`,
    ]);
  });
});

describe('deleteStaleCaches', () => {
  it('drops cipherbox caches from earlier deploys and keeps the shell', async () => {
    const caches = new FakeCacheStorage();
    caches.cache(APP_SHELL_CACHE);
    caches.cache('cipherbox-app-shell-v0');
    caches.cache('unrelated-cache');

    await deleteStaleCaches(caches);

    expect([...caches.opened.keys()]).toEqual([APP_SHELL_CACHE, 'unrelated-cache']);
  });
});

describe('appShellClaims', () => {
  it('claims navigations and precached same-origin GETs only', () => {
    const precached = new Set([`${ORIGIN}/assets/app.js`]);

    expect(appShellClaims(navigation(`${ORIGIN}/files`), ORIGIN, precached)).toBe(true);
    expect(appShellClaims(new Request(`${ORIGIN}/assets/app.js`), ORIGIN, precached)).toBe(true);
    expect(appShellClaims(new Request(`${ORIGIN}/api/vault`), ORIGIN, precached)).toBe(false);
    expect(appShellClaims(new Request('https://gateway.example/ipfs/x'), ORIGIN, precached)).toBe(
      false
    );
    expect(
      appShellClaims(new Request(`${ORIGIN}/assets/app.js`, { method: 'POST' }), ORIGIN, precached)
    ).toBe(false);
  });
});

describe('respondFromAppShell', () => {
  it('serves a precached asset from the cache without a network fetch', async () => {
    const caches = new FakeCacheStorage();
    await precacheAppShell(caches, manifestFetch('["/assets/app.js"]'), ORIGIN);

    const response = await respondFromAppShell(
      new Request(`${ORIGIN}/assets/app.js`),
      caches,
      failingFetch,
      ORIGIN
    );

    expect(await response?.text()).toBe(`body:${ORIGIN}/assets/app.js`);
  });

  it('falls back to the cached shell when a navigation cannot reach the network', async () => {
    const caches = new FakeCacheStorage();
    await precacheAppShell(caches, manifestFetch('["/index.html"]'), ORIGIN);

    const response = await respondFromAppShell(
      navigation(`${ORIGIN}/files/abc`),
      caches,
      failingFetch,
      ORIGIN
    );

    expect(await response?.text()).toBe(`body:${ORIGIN}/index.html`);
  });

  it('prefers the network for a navigation', async () => {
    const caches = new FakeCacheStorage();
    await precacheAppShell(caches, manifestFetch('["/index.html"]'), ORIGIN);
    const online = (async () => new Response('fresh')) as unknown as typeof fetch;

    const response = await respondFromAppShell(
      navigation(`${ORIGIN}/files/abc`),
      caches,
      online,
      ORIGIN
    );

    expect(await response?.text()).toBe('fresh');
  });

  it('does not intercept non-GET, cross-origin, or uncached requests', async () => {
    const caches = new FakeCacheStorage();
    await precacheAppShell(caches, manifestFetch('["/index.html"]'), ORIGIN);

    expect(
      await respondFromAppShell(
        new Request(`${ORIGIN}/index.html`, { method: 'POST' }),
        caches,
        failingFetch,
        ORIGIN
      )
    ).toBeUndefined();
    expect(
      await respondFromAppShell(
        new Request('https://gateway.example/ipfs/x'),
        caches,
        failingFetch,
        ORIGIN
      )
    ).toBeUndefined();
    expect(
      await respondFromAppShell(new Request(`${ORIGIN}/api/vault`), caches, failingFetch, ORIGIN)
    ).toBeUndefined();
  });

  it('never writes a response into the cache', async () => {
    const caches = new FakeCacheStorage();
    await precacheAppShell(caches, manifestFetch('["/index.html"]'), ORIGIN);
    const online = (async () => new Response('fresh')) as unknown as typeof fetch;

    await respondFromAppShell(navigation(`${ORIGIN}/files`), caches, online, ORIGIN);
    await respondFromAppShell(new Request(`${ORIGIN}/api/vault`), caches, online, ORIGIN);

    expect(caches.cache(APP_SHELL_CACHE).putCalls).toBe(0);
    expect([...caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([`${ORIGIN}/index.html`]);
  });
});

describe('readPrecachedUrls', () => {
  it('mirrors the cached URLs', async () => {
    const caches = new FakeCacheStorage();
    await precacheAppShell(caches, manifestFetch('["/index.html","/assets/app.js"]'), ORIGIN);

    expect([...(await readPrecachedUrls(caches))]).toEqual([
      `${ORIGIN}/index.html`,
      `${ORIGIN}/assets/app.js`,
    ]);
  });
});
