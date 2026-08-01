/**
 * Cache doubles for the Service Worker unit suite. Excluded from the build
 * (tsconfig.build.json).
 */

import type { CacheLike, CacheStorageLike } from './precache.js';

export const SW_ORIGIN = 'https://vault.example';

export class FakeCache implements CacheLike {
  readonly entries = new Map<string, string>();
  putCalls = 0;

  async addAll(requests: readonly string[]): Promise<void> {
    for (const request of requests) this.entries.set(request, `body:${request}`);
  }

  async match(request: string): Promise<Response | undefined> {
    const body = this.entries.get(request);
    return body === undefined ? undefined : new Response(body);
  }

  async keys(): Promise<readonly { readonly url: string }[]> {
    return [...this.entries.keys()].map((url) => ({ url }));
  }

  async delete(request: string): Promise<boolean> {
    return this.entries.delete(request);
  }

  /** Not on `CacheLike`; present only so a test can prove nothing calls it. */
  put(): void {
    this.putCalls += 1;
  }
}

export class FakeCacheStorage implements CacheStorageLike {
  readonly opened = new Map<string, FakeCache>();

  async open(name: string): Promise<CacheLike> {
    return this.cache(name);
  }

  async keys(): Promise<readonly string[]> {
    return [...this.opened.keys()];
  }

  async delete(name: string): Promise<boolean> {
    return this.opened.delete(name);
  }

  cache(name: string): FakeCache {
    const existing = this.opened.get(name);
    if (existing) return existing;
    const created = new FakeCache();
    this.opened.set(name, created);
    return created;
  }
}

export const manifestFetch = (body: string, ok = true): typeof fetch =>
  (async () => new Response(body, { status: ok ? 200 : 404 })) as unknown as typeof fetch;

export const failingFetch: typeof fetch = (async () => {
  throw new TypeError('offline');
}) as unknown as typeof fetch;
