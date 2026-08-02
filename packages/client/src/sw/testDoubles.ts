/**
 * Doubles for the Service Worker and media unit suites. Excluded from the build
 * (tsconfig.build.json).
 */

import type { MediaRequest, MediaResponse, MessagePortLike } from '../media/protocol.js';
import type { CacheLike, CacheStorageLike } from './precache.js';

export const SW_ORIGIN = 'https://vault.example';

export class FakeCache implements CacheLike {
  readonly entries = new Map<string, string>();
  /** URLs the real `Cache.addAll` would reject on. */
  readonly unreachable = new Set<string>();

  async addAll(requests: readonly string[]): Promise<void> {
    if (requests.some((request) => this.unreachable.has(request))) {
      throw new TypeError('addAll: a request did not respond OK');
    }
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

/** Answers a post synchronously, standing in for the far side of the port. */
export type PortReply = (message: MediaRequest, port: FakePort) => void;

/**
 * One end of a `MessageChannel`. A post reaches the far side either through
 * `peer` (a wired pair) or through `reply` (a scripted answer).
 */
export class FakePort implements MessagePortLike {
  peer: FakePort | null = null;
  readonly sent: Array<MediaRequest | MediaResponse> = [];
  started = false;
  closed = false;
  private listeners: Array<(event: MessageEvent) => void> = [];

  constructor(private readonly reply?: PortReply) {}

  postMessage(message: unknown): void {
    this.sent.push(message as MediaRequest);
    this.reply?.(message as MediaRequest, this);
    this.peer?.deliverRaw(message);
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners.push(listener);
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners = this.listeners.filter((entry) => entry !== listener);
  }

  start(): void {
    this.started = true;
  }

  close(): void {
    this.closed = true;
  }

  deliver(response: MediaResponse): void {
    this.deliverRaw(response);
  }

  /** Delivers whatever a version-skewed or hostile port might post. */
  deliverRaw(data: unknown): void {
    if (this.closed) return;
    for (const listener of [...this.listeners]) {
      listener({ data } as unknown as MessageEvent);
    }
  }

  get listenerCount(): number {
    return this.listeners.length;
  }

  countOf(type: MediaRequest['type']): number {
    return this.sent.filter((message) => message.type === type).length;
  }
}
