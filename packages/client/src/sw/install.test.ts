import { describe, expect, it } from 'vitest';

import { MEDIA_PORT_OFFER } from '../media/protocol.js';
import {
  RELAY_DELIVER,
  RELAY_PORT,
  RELAY_SELF,
  RELAY_WHOAMI,
  type MessagePortLike,
} from '../portRelay.js';
import type { WindowClientLike } from './clients.js';
import {
  installServiceWorker,
  type ExtendableEventLike,
  type FetchEventLike,
  type MediaPipeLike,
  type ServiceWorkerEventMap,
  type ServiceWorkerScopeLike,
} from './install.js';
import { APP_SHELL_CACHE } from './precache.js';
import {
  failingFetch,
  FakeCacheStorage,
  manifestFetch,
  SW_ORIGIN as ORIGIN,
} from './testDoubles.js';

/** A window client, recording what the worker forwarded to it. */
class FakeWindow implements WindowClientLike {
  readonly received: Array<{ message: unknown; transfer: MessagePortLike[] }> = [];

  constructor(readonly id: string) {}

  postMessage(message: unknown, transfer?: MessagePortLike[]): void {
    this.received.push({ message, transfer: transfer ? [...transfer] : [] });
  }
}

class FakeScope implements ServiceWorkerScopeLike {
  readonly location = { origin: ORIGIN };
  readonly caches = new FakeCacheStorage();
  readonly windows: FakeWindow[] = [];
  skipWaitingCalls = 0;
  claimCalls = 0;
  readonly clients = {
    matchAll: async (): Promise<readonly WindowClientLike[]> => this.windows,
    claim: async (): Promise<void> => void (this.claimCalls += 1),
  };
  private readonly listeners = new Map<string, (event: never) => void>();

  skipWaiting(): void {
    this.skipWaitingCalls += 1;
  }

  addEventListener<K extends keyof ServiceWorkerEventMap>(
    type: K,
    listener: (event: ServiceWorkerEventMap[K]) => void
  ): void {
    this.listeners.set(type, listener as (event: never) => void);
  }

  dispatch<K extends keyof ServiceWorkerEventMap>(type: K, event: ServiceWorkerEventMap[K]): void {
    const listener = this.listeners.get(type) as
      | ((event: ServiceWorkerEventMap[K]) => void)
      | undefined;
    listener?.(event);
  }
}

class FakePipe implements MediaPipeLike {
  readonly adopted: Array<{ port: MessagePortLike; clientId?: string }> = [];
  readonly responded: Array<{ url: string; clientId?: string }> = [];

  handles(url: URL): boolean {
    return url.pathname.startsWith('/stream/');
  }

  async respond(request: Request, clientId?: string): Promise<Response> {
    this.responded.push({ url: request.url, clientId });
    return new Response('piped', { status: 206 });
  }

  adoptPort(port: MessagePortLike, clientId?: string): void {
    this.adopted.push({ port, clientId });
  }
}

/** Drives an extendable event and awaits whatever the listener extended it with. */
async function dispatchExtendable(
  scope: FakeScope,
  type: 'install' | 'activate'
): Promise<undefined> {
  const extended: Promise<unknown>[] = [];
  const event: ExtendableEventLike = { waitUntil: (promise) => void extended.push(promise) };
  scope.dispatch(type, event);
  await Promise.all(extended);
  return undefined;
}

function dispatchFetch(
  scope: FakeScope,
  request: Request,
  clientId?: string
): Promise<Response> | undefined {
  let answer: Promise<Response> | undefined;
  const event: FetchEventLike = {
    request,
    clientId,
    respondWith: (response) => {
      answer = Promise.resolve(response);
    },
  };
  scope.dispatch('fetch', event);
  return answer;
}

async function wire(fetchFn: typeof fetch): Promise<{ scope: FakeScope; pipe: FakePipe }> {
  const scope = new FakeScope();
  const pipe = new FakePipe();
  installServiceWorker(scope, { pipe, fetchFn });
  await dispatchExtendable(scope, 'install');
  await dispatchExtendable(scope, 'activate');
  return { scope, pipe };
}

describe('installServiceWorker', () => {
  it('precaches the app shell and claims clients on activate', async () => {
    const { scope } = await wire(manifestFetch('["/index.html"]'));

    expect(scope.skipWaitingCalls).toBe(1);
    expect(scope.claimCalls).toBe(1);
    expect([...scope.caches.cache(APP_SHELL_CACHE).entries.keys()]).toEqual([
      `${ORIGIN}/index.html`,
    ]);
  });

  it('answers a stream request from the media pipe, naming the client that asked', async () => {
    const { scope, pipe } = await wire(manifestFetch('["/index.html"]'));

    const response = await dispatchFetch(scope, new Request(`${ORIGIN}/stream/tkt`), 'window-7');

    expect(response?.status).toBe(206);
    expect(pipe.responded).toEqual([{ url: `${ORIGIN}/stream/tkt`, clientId: 'window-7' }]);
  });

  it('answers a precached asset from the app shell', async () => {
    const { scope, pipe } = await wire(manifestFetch('["/assets/app.js"]'));

    const response = await dispatchFetch(scope, new Request(`${ORIGIN}/assets/app.js`));

    expect(await response?.text()).toBe(`body:${ORIGIN}/assets/app.js`);
    expect(pipe.responded).toEqual([]);
  });

  it('leaves an unclaimed request to the network', async () => {
    const { scope } = await wire(manifestFetch('["/index.html"]'));

    expect(dispatchFetch(scope, new Request(`${ORIGIN}/api/vault`))).toBeUndefined();
    expect(dispatchFetch(scope, new Request('https://gateway.example/ipfs/x'))).toBeUndefined();
    expect(
      dispatchFetch(scope, new Request(`${ORIGIN}/index.html`, { method: 'POST' }))
    ).toBeUndefined();
  });

  it('serves a precached asset on a restart, before the re-learn settles', async () => {
    const scope = new FakeScope();
    // A restarted worker: the cache is warm from an earlier run, but this
    // instance has learned nothing when the browser dispatches the fetch.
    await scope.caches.cache(APP_SHELL_CACHE).addAll([`${ORIGIN}/assets/app.js`]);
    installServiceWorker(scope, { pipe: new FakePipe(), fetchFn: failingFetch });

    const response = await dispatchFetch(scope, new Request(`${ORIGIN}/assets/app.js`));

    expect(await response?.text()).toBe(`body:${ORIGIN}/assets/app.js`);
  });

  it('installs cleanly when no manifest is published', async () => {
    const { scope } = await wire(failingFetch);

    expect(scope.caches.opened.has(APP_SHELL_CACHE)).toBe(true);
    expect(scope.caches.cache(APP_SHELL_CACHE).entries.size).toBe(0);
  });

  it('installs and keeps piping when the shell will not cache', async () => {
    const scope = new FakeScope();
    const pipe = new FakePipe();
    scope.caches.cache(APP_SHELL_CACHE).addAll = () => Promise.reject(new TypeError('404'));
    installServiceWorker(scope, { pipe, fetchFn: manifestFetch('["/index.html"]') });

    await expect(dispatchExtendable(scope, 'install')).resolves.toBeUndefined();
    await dispatchExtendable(scope, 'activate');

    expect(await dispatchFetch(scope, new Request(`${ORIGIN}/stream/tkt`))).toBeDefined();
  });

  it('hands an offered port to the pipe under the client that offered it', async () => {
    const { scope, pipe } = await wire(manifestFetch('["/index.html"]'));
    const port = {} as MessagePortLike;

    scope.dispatch('message', {
      data: { type: MEDIA_PORT_OFFER },
      ports: [port],
      source: { id: 'window-7', postMessage: () => undefined },
    });
    scope.dispatch('message', { data: { type: 'other' }, ports: [{} as MessagePortLike] });

    expect(pipe.adopted).toEqual([{ port, clientId: 'window-7' }]);
  });

  it('adopts a port offered without a client identity', async () => {
    const { scope, pipe } = await wire(manifestFetch('["/index.html"]'));
    const port = {} as MessagePortLike;

    scope.dispatch('message', { data: { type: MEDIA_PORT_OFFER }, ports: [port], source: null });

    expect(pipe.adopted).toEqual([{ port, clientId: undefined }]);
  });
});

describe('service worker port brokerage', () => {
  const closable = (): MessagePortLike & { closed: boolean } => {
    const port = {
      closed: false,
      close: () => void (port.closed = true),
    } as unknown as MessagePortLike & { closed: boolean };
    return port;
  };

  it('names the asking client back to itself', async () => {
    const { scope } = await wire(manifestFetch('["/index.html"]'));
    const named: unknown[] = [];

    scope.dispatch('message', {
      data: { type: RELAY_WHOAMI },
      ports: [],
      source: { id: 'window-3', postMessage: (message) => void named.push(message) },
    });

    expect(named).toEqual([{ type: RELAY_SELF, id: 'window-3' }]);
  });

  it('forwards a delivered port to the addressed client and nobody else', async () => {
    const { scope } = await wire(manifestFetch('["/index.html"]'));
    const target = new FakeWindow('window-9');
    const bystander = new FakeWindow('window-1');
    scope.windows.push(bystander, target);
    const port = closable();

    const extended: Promise<unknown>[] = [];
    scope.dispatch('message', {
      data: { type: RELAY_DELIVER, to: 'window-9' },
      ports: [port],
      waitUntil: (promise) => void extended.push(promise),
    });
    await Promise.all(extended);

    expect(target.received).toEqual([{ message: { type: RELAY_PORT }, transfer: [port] }]);
    expect(bystander.received).toEqual([]);
  });

  it('closes a port addressed to a client that is gone', async () => {
    const { scope } = await wire(manifestFetch('["/index.html"]'));
    const port = closable();

    const extended: Promise<unknown>[] = [];
    scope.dispatch('message', {
      data: { type: RELAY_DELIVER, to: 'window-gone' },
      ports: [port],
      waitUntil: (promise) => void extended.push(promise),
    });
    await Promise.all(extended);

    expect(port.closed).toBe(true);
  });

  it('drops a delivery naming no client', async () => {
    const { scope } = await wire(manifestFetch('["/index.html"]'));
    const target = new FakeWindow('window-9');
    scope.windows.push(target);
    const port = closable();

    scope.dispatch('message', { data: { type: RELAY_DELIVER }, ports: [port] });

    expect(target.received).toEqual([]);
  });
});
