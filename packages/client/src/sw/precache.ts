/**
 * The app-shell precache (blueprint/web-client.md: a vault you can mutate
 * offline is a vault whose UI must boot offline).
 *
 * `precacheAppShell` is the only writer and it writes only manifest entries;
 * `CacheLike` exposes no `put`, so vault data — never in the manifest — cannot
 * structurally reach the cache.
 */

import { STREAM_PATH_PREFIX } from '../media/protocol.js';

export const APP_SHELL_CACHE = 'cipherbox-app-shell';

const PRECACHE_MANIFEST_URL = '/precache-manifest.json';

/** The document a navigation falls back to when the network is unreachable. */
const APP_SHELL_DOCUMENT = '/index.html';
const CACHE_PREFIX = 'cipherbox-';

/** The subset of `Cache` the shell drives (injectable). */
export interface CacheLike {
  addAll(requests: readonly string[]): Promise<void>;
  match(request: string): Promise<Response | undefined>;
  keys(): Promise<readonly { readonly url: string }[]>;
  delete(request: string): Promise<boolean>;
}

/** The subset of `CacheStorage` the shell drives (injectable). */
export interface CacheStorageLike {
  open(name: string): Promise<CacheLike>;
  keys(): Promise<readonly string[]>;
  delete(name: string): Promise<boolean>;
}

/**
 * Fetches the build's manifest and brings the cache in line with it. A dev build
 * ships no manifest, so an unreachable or unparseable one is a no-op.
 */
export async function precacheAppShell(
  caches: CacheStorageLike,
  fetchFn: typeof fetch,
  origin: string
): Promise<void> {
  const urls = await readManifest(fetchFn, origin);
  if (!urls) return;

  const cache = await caches.open(APP_SHELL_CACHE);
  // `addAll` is atomic, so one entry that will not cache would drop the whole
  // shell; per entry, a miss costs only that asset.
  for (const url of urls) {
    try {
      await cache.addAll([url]);
    } catch {
      continue;
    }
  }

  // Pruning follows the manifest, not what cached: an entry the build still
  // lists is wanted even when this pass failed to refresh it.
  const wanted = new Set(urls);
  for (const entry of await cache.keys()) {
    if (!wanted.has(entry.url)) await cache.delete(entry.url);
  }
}

/** The URLs currently precached, mirrored so a fetch handler can claim synchronously. */
export async function readPrecachedUrls(caches: CacheStorageLike): Promise<ReadonlySet<string>> {
  const cache = await caches.open(APP_SHELL_CACHE);
  return new Set((await cache.keys()).map((entry) => entry.url));
}

/** Drops caches left by earlier deploys so a redeploy does not accumulate. */
export async function deleteStaleCaches(caches: CacheStorageLike): Promise<void> {
  for (const name of await caches.keys()) {
    if (name.startsWith(CACHE_PREFIX) && name !== APP_SHELL_CACHE) await caches.delete(name);
  }
}

/** The requests the shell could ever own; the cheap gate before the claim itself. */
export function sameOriginGet(request: Request, origin: string): boolean {
  return request.method === 'GET' && new URL(request.url).origin === origin;
}

/** Whether the shell owns this request — decided synchronously, before `respondWith`. */
export function appShellClaims(
  request: Request,
  origin: string,
  precached: ReadonlySet<string>
): boolean {
  if (!sameOriginGet(request, origin)) return false;
  return request.mode === 'navigate' || precached.has(new URL(request.url).toString());
}

/**
 * Answers a request from the shell: navigations network-first with the cached
 * document as the offline fallback, precached URLs cache-first. `undefined`
 * means "not the shell's" — do not intercept.
 */
export async function respondFromAppShell(
  request: Request,
  caches: CacheStorageLike,
  fetchFn: typeof fetch,
  origin: string
): Promise<Response | undefined> {
  if (request.method !== 'GET') return undefined;
  const url = new URL(request.url);
  if (url.origin !== origin) return undefined;

  const cache = await caches.open(APP_SHELL_CACHE);
  if (request.mode === 'navigate') {
    try {
      return await fetchFn(request);
    } catch (error) {
      const shell = await cache.match(new URL(APP_SHELL_DOCUMENT, origin).toString());
      if (!shell) throw error;
      return shell;
    }
  }
  return cache.match(url.toString());
}

async function readManifest(fetchFn: typeof fetch, origin: string): Promise<string[] | null> {
  let parsed: unknown;
  try {
    const manifest = new URL(PRECACHE_MANIFEST_URL, origin).toString();
    const response = await fetchFn(manifest, { cache: 'no-store' });
    if (!response.ok) return null;
    parsed = await response.json();
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  return parsed
    .map((entry) => (typeof entry === 'string' ? resolveEntry(entry, origin) : null))
    .filter((url): url is string => url !== null);
}

/**
 * A stale or tampered manifest must not make the worker cache a third party's
 * bytes, nor the media path, whose responses are vault plaintext.
 */
function resolveEntry(entry: string, origin: string): string | null {
  let url: URL;
  try {
    url = new URL(entry, origin);
  } catch {
    return null;
  }
  if (url.origin !== origin) return null;
  if (url.pathname.startsWith(STREAM_PATH_PREFIX)) return null;
  return url.toString();
}
