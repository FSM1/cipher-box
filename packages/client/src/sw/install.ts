/**
 * Wires a Service Worker global scope to the media pipe and the app-shell
 * precache (blueprint/web-client.md "Content paths").
 */

import { MEDIA_PORT_OFFER, type MessagePortLike } from '../media/protocol.js';
import {
  RELAY_DELIVER,
  RELAY_PORT,
  RELAY_SELF,
  RELAY_WHOAMI,
  type RelayMessage,
} from '../portCourier.js';
import { MediaPipe, type MediaPipeScopeLike, type WindowClientLike } from './pipe.js';
import {
  appShellClaims,
  deleteStaleCaches,
  precacheAppShell,
  readPrecachedUrls,
  respondFromAppShell,
  sameOriginGet,
  type CacheStorageLike,
} from './precache.js';

export interface ExtendableEventLike {
  waitUntil(promise: Promise<unknown>): void;
}

export interface FetchEventLike {
  readonly request: Request;
  /** The window client that issued the request; empty when the browser knows none. */
  readonly clientId?: string;
  respondWith(response: Response | Promise<Response>): void;
}

/** The client that sent a message; its `id` is the one `FetchEventLike.clientId` carries. */
export interface MessageSourceLike {
  readonly id: string;
  postMessage(message: unknown): void;
}

export interface PortMessageEventLike {
  readonly data: unknown;
  readonly ports: readonly MessagePortLike[];
  readonly source?: MessageSourceLike | null;
  waitUntil?(promise: Promise<unknown>): void;
}

export interface ServiceWorkerEventMap {
  install: ExtendableEventLike;
  activate: ExtendableEventLike;
  fetch: FetchEventLike;
  message: PortMessageEventLike;
}

/** The subset of a Service Worker global scope the wiring drives (injectable). */
export interface ServiceWorkerScopeLike extends MediaPipeScopeLike {
  readonly caches: CacheStorageLike;
  readonly clients: MediaPipeScopeLike['clients'] & { claim(): Promise<void> };
  skipWaiting(): Promise<void> | void;
  addEventListener<K extends keyof ServiceWorkerEventMap>(
    type: K,
    listener: (event: ServiceWorkerEventMap[K]) => void
  ): void;
}

/** The pipe surface the fetch and message listeners drive. */
export type MediaPipeLike = Pick<MediaPipe, 'handles' | 'respond' | 'adoptPort'>;

export interface ServiceWorkerDeps {
  pipe?: MediaPipeLike;
  fetchFn?: typeof fetch;
}

export function installServiceWorker(
  scope: ServiceWorkerScopeLike,
  deps: ServiceWorkerDeps = {}
): void {
  const fetchFn =
    deps.fetchFn ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  const pipe = deps.pipe ?? new MediaPipe(scope);
  const origin = scope.location.origin;

  let precached: ReadonlySet<string> = new Set();
  let learned = false;
  const refresh = async (): Promise<void> => {
    precached = await readPrecachedUrls(scope.caches);
    learned = true;
  };
  // A restarted worker gets no fresh `install`, so it re-learns the shell here.
  let learning = refresh().catch(ignore);

  scope.addEventListener('install', (event) => {
    void scope.skipWaiting();
    // A manifest entry that will not cache degrades to no offline shell, never a
    // failed install.
    learning = precacheAppShell(scope.caches, fetchFn, origin).then(refresh).catch(ignore);
    event.waitUntil(learning);
  });

  scope.addEventListener('activate', (event) => {
    learning = deleteStaleCaches(scope.caches)
      .then(() => scope.clients.claim())
      .then(refresh)
      .catch(ignore);
    event.waitUntil(learning);
  });

  scope.addEventListener('fetch', (event) => {
    const request = event.request;
    if (pipe.handles(new URL(request.url))) {
      event.respondWith(pipe.respond(request, event.clientId));
      return;
    }
    const answer = (): Promise<Response> =>
      respondFromAppShell(request, scope.caches, fetchFn, origin).then(
        (response) => response ?? fetchFn(request)
      );
    // The browser restarts a stopped worker to dispatch this, so the first fetch
    // can outrun the re-learn. Claiming on an empty set would miss the shell.
    if (!learned && sameOriginGet(request, origin)) {
      event.respondWith(
        learning.then(() =>
          appShellClaims(request, origin, precached) ? answer() : fetchFn(request)
        )
      );
      return;
    }
    if (!appShellClaims(request, origin, precached)) return;
    event.respondWith(answer());
  });

  scope.addEventListener('message', (event) => {
    const data = event.data as { type?: unknown; to?: unknown } | null;
    if (data?.type === MEDIA_PORT_OFFER) {
      const port = event.ports[0];
      if (port) pipe.adoptPort(port, event.source?.id);
      return;
    }
    // Port brokerage between two tabs. The worker names a client to itself and
    // forwards the far end of a channel; it reads neither and keeps no state, so
    // its death costs a re-broker and never a channel already open.
    if (data?.type === RELAY_WHOAMI) {
      const source = event.source;
      if (source) {
        const self: RelayMessage = { type: RELAY_SELF, id: source.id };
        source.postMessage(self);
      }
      return;
    }
    if (data?.type !== RELAY_DELIVER) return;
    const port = event.ports[0];
    if (!port || typeof data.to !== 'string') return;
    const delivery = deliverPort(scope, data.to, port);
    if (event.waitUntil) event.waitUntil(delivery);
  });
}

async function deliverPort(
  scope: ServiceWorkerScopeLike,
  to: string,
  port: MessagePortLike
): Promise<void> {
  // A tab that the worker has not claimed yet is still a legitimate target.
  const clients = await scope.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const target: WindowClientLike | undefined = clients.find((client) => client.id === to);
  if (!target) {
    port.close();
    return;
  }
  const message: RelayMessage = { type: RELAY_PORT };
  target.postMessage(message, [port]);
}

const ignore = (): void => undefined;
