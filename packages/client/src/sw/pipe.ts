/**
 * The Service Worker end of the media byte pipe (blueprint/web-client.md
 * "Streaming media — the SW is a dumb pipe"). Nothing here survives a worker
 * kill, so a port that stops answering is re-brokered, not reported as a failure.
 */

import {
  MEDIA_PORT_REQUEST,
  STREAM_PATH_PREFIX,
  ticketFromPath,
  type MediaRequest,
  type MediaResponse,
} from '../media/protocol.js';
import { safeMimeType } from '../media/range.js';
import type { MessagePortLike } from '../portRelay.js';
import type { ClientsLike, WindowClientLike } from './clients.js';

/** The subset of a Service Worker global scope the pipe drives. */
export interface MediaPipeScopeLike {
  readonly clients: ClientsLike;
  readonly location: { readonly origin: string };
}

export interface MediaPipeOptions {
  brokerTimeoutMs?: number;
  responseTimeoutMs?: number;
  pullTimeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5000;

/** A pull drives a real ranged engine read over the network, so it gets a far longer leash. */
const DEFAULT_PULL_TIMEOUT_MS = 30000;

/** One entry for every offer and request without a client identity; a real client id is never empty. */
const ANONYMOUS_CLIENT = '';

/** Why a body reading over a superseded or discarded port ends. */
const PORT_REPLACED = 'media port replaced';

type MediaHeadResponse = Extract<MediaResponse, { type: 'cb:media:head' }>;

/** A client's end of the pipe, with the listener bound to it. */
interface PortEntry {
  readonly port: MessagePortLike;
  readonly listener: (event: MessageEvent) => void;
}

/** Receives every port message correlated to one request id, until it settles. */
interface ResponseSink {
  readonly port: MessagePortLike;
  readonly deliver: (response: MediaResponse) => void;
}

/** A response body still streaming, and the port it reads from. */
interface BodyEntry {
  readonly port: MessagePortLike;
  readonly controller: ReadableStreamDefaultController<Uint8Array>;
  /** Resolves the pull in flight; a body ended between pulls has none. */
  pulling: (() => void) | null;
}

export class MediaPipe {
  /**
   * One port per client: a tab's registry only knows the tickets that tab
   * minted, so a request answered by another tab's port dies as an unknown
   * ticket.
   */
  private readonly ports = new Map<string, PortEntry>();
  private readonly portWaiters = new Set<(adopted: string) => void>();
  private readonly sinks = new Map<number, ResponseSink>();
  /**
   * Every response body still streaming, held with its stream controller so an
   * idle one can be ended now: a sink exists only between a pull and its answer,
   * and a buffered media element may go a long time without pulling again.
   */
  private readonly bodies = new Map<number, BodyEntry>();
  /** The armed pull deadline per request, so a cancel can disarm its own. */
  private readonly pullTimers = new Map<number, ReturnType<typeof setTimeout>>();
  private nextRequestId = 1;
  private readonly brokerTimeoutMs: number;
  private readonly responseTimeoutMs: number;
  private readonly pullTimeoutMs: number;

  constructor(
    private readonly scope: MediaPipeScopeLike,
    options: MediaPipeOptions = {}
  ) {
    this.brokerTimeoutMs = options.brokerTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.responseTimeoutMs = options.responseTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.pullTimeoutMs = options.pullTimeoutMs ?? DEFAULT_PULL_TIMEOUT_MS;
  }

  /** The whole prefix is the pipe's: a malformed ticket is its 404, not the network's. */
  handles(url: URL): boolean {
    return url.origin === this.scope.location.origin && url.pathname.startsWith(STREAM_PATH_PREFIX);
  }

  /** Takes a client's end of a fresh channel, replacing whatever that client held. */
  adoptPort(port: MessagePortLike, clientId: string = ANONYMOUS_CLIENT): void {
    this.detachPort(clientId);
    const listener = (event: MessageEvent): void => this.onMessage(port, event);
    port.addEventListener('message', listener);
    port.start?.();
    // Insertion order is adoption order, which the anonymous fallback reads.
    this.ports.set(clientId, { port, listener });
    for (const waiter of [...this.portWaiters]) waiter(clientId);
  }

  /**
   * Asks every window client for a fresh channel, for a worker instance that
   * holds none. A terminated worker runs no `detachPort`, so the cursors its
   * bodies pinned — and the engine streams and content keys behind them — are
   * released only when the tab re-brokers, which serving a new port does.
   */
  async requestPorts(): Promise<void> {
    if (this.ports.size > 0) return;
    const clients = await this.scope.clients.matchAll({ type: 'window' });
    // A port adopted across the await already carries the tab's re-broker.
    if (this.ports.size > 0) return;
    this.askForPort(clients);
  }

  async respond(request: Request, clientId: string = ANONYMOUS_CLIENT): Promise<Response> {
    // The prefix is navigable, so a cross-site form POST reaches here; only a
    // GET may ever draw plaintext out of the pipe.
    if (request.method !== 'GET') return sealed(405);
    const ticket = ticketFromPath(new URL(request.url).pathname);
    if (ticket === null) return sealed(404);
    const range = request.headers.get('range');

    // A dead tab's port silently swallows `open` and the timeout is the only
    // signal; retry the open once against a freshly brokered port.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const port = await this.acquirePort(clientId);
      if (!port) break;
      const requestId = this.nextRequestId;
      this.nextRequestId += 1;
      const head = await this.open(port, requestId, ticket, range);
      // An open the tab answered late, or answered with a head that carries no
      // body, still left it holding a cursor and the stream that cursor pins.
      if (!head) {
        this.post(port, { type: 'cb:media:close', requestId });
        this.discardPort(port);
        continue;
      }
      // Only these two carry a body; `Response` throws on a body under a
      // null-body status, and the port that named the status is untrusted.
      if (head.status !== 200 && head.status !== 206) {
        this.post(port, { type: 'cb:media:close', requestId });
        return sealed(head.status, head.headers);
      }
      return sealed(head.status, head.headers, this.body(port, requestId));
    }
    return sealed(503);
  }

  private onMessage(port: MessagePortLike, event: MessageEvent): void {
    const response = asResponse(event.data);
    if (response === null) return;
    const sink = this.sinks.get(response.requestId);
    if (sink !== undefined) {
      // An id another client owns is not this port's to answer.
      if (sink.port === port) sink.deliver(response);
      return;
    }
    // Nothing is listening between a pull and its answer, so an unsolicited
    // failure — a revoked ticket — has to reach the body directly.
    if (response.type !== 'cb:media:error') return;
    if (this.bodies.get(response.requestId)?.port !== port) return;
    this.closeBody(response.requestId)?.controller.error(new Error(response.message));
  }

  private open(
    port: MessagePortLike,
    requestId: number,
    ticket: string,
    range: string | null
  ): Promise<MediaHeadResponse | null> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.sinks.delete(requestId);
        resolve(null);
      }, this.responseTimeoutMs);
      this.sinks.set(requestId, {
        port,
        deliver: (response) => {
          // An error answers the open as unusable — a dead port fails it now
          // rather than at the response deadline, so the retry re-brokers at once.
          if (response.type !== 'cb:media:head' && response.type !== 'cb:media:error') return;
          clearTimeout(timer);
          this.sinks.delete(requestId);
          resolve(response.type === 'cb:media:head' ? response : null);
        },
      });
      this.post(port, { type: 'cb:media:open', requestId, ticket, range });
    });
  }

  /** A zero high-water mark keeps exactly one window in flight: pull on demand. */
  private body(port: MessagePortLike, requestId: number): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>(
      {
        // `start` runs inside this constructor, so the controller is held before
        // the response can be read from.
        start: (controller) => void this.bodies.set(requestId, { port, controller, pulling: null }),
        pull: (controller) => this.pullWindow(port, requestId, controller),
        cancel: () => void this.closeBody(requestId),
      },
      { highWaterMark: 0 }
    );
  }

  /**
   * Forgets a body and everything keyed to its request, or answers null when
   * another path already ended it: the map entry is the token that makes ending
   * a body exactly-once. Disarming the pull deadline is part of that — left
   * armed it discards the port, taking every sibling body on it down too.
   */
  private takeBody(requestId: number): BodyEntry | null {
    const body = this.bodies.get(requestId);
    if (body === undefined) return null;
    this.bodies.delete(requestId);
    this.clearPull(requestId);
    this.sinks.delete(requestId);
    body.pulling?.();
    body.pulling = null;
    return body;
  }

  /** Takes a body and tells the tab to release the cursor and pin behind it. */
  private closeBody(requestId: number): BodyEntry | null {
    const body = this.takeBody(requestId);
    if (body !== null) this.post(body.port, { type: 'cb:media:close', requestId });
    return body;
  }

  private pullWindow(
    port: MessagePortLike,
    requestId: number,
    controller: ReadableStreamDefaultController<Uint8Array>
  ): Promise<void> {
    return new Promise<void>((resolve) => {
      const body = this.bodies.get(requestId);
      // Already ended out of band; the stream is settled and wants no window.
      if (body === undefined) {
        resolve();
        return;
      }
      body.pulling = resolve;
      const settle = (finish: () => void): void => {
        this.clearPull(requestId);
        this.sinks.delete(requestId);
        body.pulling = null;
        finish();
        resolve();
      };
      // A tab that died mid-stream swallows the pull; without this the body
      // never settles and the response hangs open forever.
      const timer = setTimeout(() => {
        settle(() => {
          this.closeBody(requestId)?.controller.error(new Error('media pull timed out'));
          this.discardPort(port);
        });
      }, this.pullTimeoutMs);
      this.pullTimers.set(requestId, timer);
      this.sinks.set(requestId, {
        port,
        deliver: (response) => {
          switch (response.type) {
            case 'cb:media:chunk':
              settle(() => controller.enqueue(new Uint8Array(response.chunk)));
              return;
            case 'cb:media:end':
              // A completed window sequence left the tab nothing to release.
              settle(() => this.takeBody(requestId)?.controller.close());
              return;
            case 'cb:media:error':
              settle(() =>
                this.closeBody(requestId)?.controller.error(new Error(response.message))
              );
              return;
            default:
              return;
          }
        },
      });
      this.post(port, { type: 'cb:media:pull', requestId });
    });
  }

  private async acquirePort(clientId: string): Promise<MessagePortLike | null> {
    const held = this.portFor(clientId);
    if (held) return held;
    const clients = await this.scope.clients.matchAll({ type: 'window' });
    // Only the tab that needs a port may re-broker: a tab that answers replaces
    // its channel, and the superseded broker drops the cursors of live bodies.
    // An unidentified client has no target, so it falls back to asking everyone.
    const owner = clients.filter((client) => client.id === clientId);
    this.askForPort(clientId !== ANONYMOUS_CLIENT && owner.length > 0 ? owner : clients);
    return this.waitForPort(clientId);
  }

  private askForPort(targets: readonly WindowClientLike[]): void {
    for (const client of targets) client.postMessage({ type: MEDIA_PORT_REQUEST });
  }

  /** Only an unidentified client may borrow a port, and only the newest offered. */
  private portFor(clientId: string): MessagePortLike | null {
    const own = this.ports.get(clientId);
    if (own) return own.port;
    if (clientId !== ANONYMOUS_CLIENT) return null;
    let newest: PortEntry | undefined;
    for (const entry of this.ports.values()) newest = entry;
    return newest?.port ?? null;
  }

  private waitForPort(clientId: string): Promise<MessagePortLike | null> {
    return new Promise((resolve) => {
      const waiter = (adopted: string): void => {
        if (adopted !== clientId && clientId !== ANONYMOUS_CLIENT) return;
        clearTimeout(timer);
        this.portWaiters.delete(waiter);
        resolve(this.portFor(clientId));
      };
      const timer = setTimeout(() => {
        this.portWaiters.delete(waiter);
        resolve(null);
      }, this.brokerTimeoutMs);
      this.portWaiters.add(waiter);
    });
  }

  private clearPull(requestId: number): void {
    const timer = this.pullTimers.get(requestId);
    if (timer === undefined) return;
    clearTimeout(timer);
    this.pullTimers.delete(requestId);
  }

  private post(port: MessagePortLike, message: MediaRequest): void {
    port.postMessage(message);
  }

  private discardPort(port: MessagePortLike): void {
    for (const [clientId, entry] of this.ports) {
      if (entry.port !== port) continue;
      this.detachPort(clientId);
      return;
    }
  }

  private detachPort(clientId: string): void {
    const entry = this.ports.get(clientId);
    if (!entry) return;
    this.ports.delete(clientId);
    // `MessagePort` has no close event, so this is the tab's only notice that
    // the bodies reading over this port are gone and their pins are free.
    // Posted before the port is disentangled, or it never leaves. Ending each
    // body here rather than at its next pull is what keeps an idle one — a
    // media element that has buffered enough — off the pull deadline.
    for (const [requestId, body] of [...this.bodies]) {
      if (body.port !== entry.port) continue;
      this.closeBody(requestId)?.controller.error(new Error(PORT_REPLACED));
    }
    entry.port.removeEventListener('message', entry.listener);
    entry.port.close();
    // What is left is an `open` still waiting on the dead port; failing it makes
    // the response re-broker and retry instead of waiting out its deadline.
    for (const [requestId, sink] of [...this.sinks]) {
      if (sink.port !== entry.port) continue;
      this.sinks.delete(requestId);
      sink.deliver({ type: 'cb:media:error', requestId, message: PORT_REPLACED });
    }
  }
}

/** Vault plaintext must never reach a cache, whatever headers the tab sent. */
function sealed(
  status: number,
  headers: Array<[string, string]> = [],
  body: BodyInit | null = null
): Response {
  const merged = new Headers();
  // `asResponse` proves the pairs are strings, not that they are legal header
  // tokens; a name or value `Headers` rejects must not fail the whole response.
  for (const [name, value] of headers) {
    try {
      merged.append(name, value);
    } catch {
      continue;
    }
  }
  merged.set('cache-control', 'no-store');
  // A ticket URL is same-origin and navigable, and the port that named the type
  // is untrusted input, so a body only ever renders under a clamped type.
  if (body !== null) {
    merged.set('content-type', safeMimeType(merged.get('content-type') ?? ''));
    merged.set('x-content-type-options', 'nosniff');
    merged.set('content-security-policy', "default-src 'none'; sandbox");
  }
  return new Response(body, { status, headers: merged });
}

/** A same-origin port is still untrusted input: anything off-shape is dropped. */
function asResponse(data: unknown): MediaResponse | null {
  if (typeof data !== 'object' || data === null) return null;
  const message = data as {
    type?: unknown;
    requestId?: unknown;
    status?: unknown;
    headers?: unknown;
    chunk?: unknown;
    message?: unknown;
  };
  const requestId = message.requestId;
  if (typeof requestId !== 'number') return null;

  switch (message.type) {
    case 'cb:media:head': {
      const { status, headers } = message;
      // Outside this range `Response` throws, which would kill the fetch handler.
      if (typeof status !== 'number' || !Number.isInteger(status)) return null;
      if (status < 200 || status > 599) return null;
      if (!isHeaderPairs(headers)) return null;
      return { type: 'cb:media:head', requestId, status, headers };
    }
    case 'cb:media:chunk':
      if (!(message.chunk instanceof ArrayBuffer)) return null;
      return { type: 'cb:media:chunk', requestId, chunk: message.chunk };
    case 'cb:media:end':
      return { type: 'cb:media:end', requestId };
    case 'cb:media:error':
      if (typeof message.message !== 'string') return null;
      return { type: 'cb:media:error', requestId, message: message.message };
    default:
      return null;
  }
}

function isHeaderPairs(value: unknown): value is Array<[string, string]> {
  return (
    Array.isArray(value) &&
    value.every(
      (pair) =>
        Array.isArray(pair) &&
        pair.length === 2 &&
        typeof pair[0] === 'string' &&
        typeof pair[1] === 'string'
    )
  );
}
