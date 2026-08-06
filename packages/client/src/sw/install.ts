/**
 * Wires a Service Worker global scope to the media pipe and the app-shell
 * precache (blueprint/web-client.md "Content paths").
 */

import { MEDIA_PORT_OFFER } from '../media/protocol.js';
import { RELAY_DELIVER, RELAY_SELF, RELAY_WHOAMI, type MessagePortLike } from '../portRelay.js';
import type { ClientsLike } from './clients.js';
import { MediaPipe, type MediaPipeScopeLike } from './pipe.js';
import { deliverPort } from './relay.js';
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
  readonly clients: ClientsLike & { claim(): Promise<void> };
  skipWaiting(): Promise<void> | void;
  addEventListener<K extends keyof ServiceWorkerEventMap>(
    type: K,
    listener: (event: ServiceWorkerEventMap[K]) => void
  ): void;
}

/** The pipe surface the fetch and message listeners drive. */
export type MediaPipeLike = Pick<MediaPipe, 'handles' | 'respond' | 'adoptPort' | 'requestPorts'>;

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
  // It gets no fresh `activate` either, and it holds none of the ports its
  // predecessor served — the tabs must re-broker to release those cursors.
  void pipe.requestPorts();

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
    const port: MessagePortLike | undefined = event.ports[0];
    switch (data?.type) {
      case MEDIA_PORT_OFFER:
        if (port) pipe.adoptPort(port, event.source?.id);
        return;
      case RELAY_WHOAMI:
        event.source?.postMessage({ type: RELAY_SELF, id: event.source.id });
        return;
      case RELAY_DELIVER: {
        if (!port) return;
        if (typeof data.to !== 'string') {
          port.close();
          return;
        }
        const delivery = deliverPort(scope.clients, data.to, port);
        event.waitUntil?.(delivery);
        return;
      }
    }
  });
}

const ignore = (): void => undefined;
