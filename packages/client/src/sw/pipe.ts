/**
 * The Service Worker end of the media byte pipe (blueprint/web-client.md
 * "Streaming media — the SW is a dumb pipe"). Nothing here survives a worker
 * kill, so a port that stops answering is re-brokered, not reported as a failure.
 */

import {
  MEDIA_PORT_REQUEST,
  STREAM_PATH_PREFIX,
  ticketFromPath,
  type MediaPortRequest,
  type MediaRequest,
  type MediaResponse,
  type MessagePortLike,
} from '../media/protocol.js';
import { safeMimeType } from '../media/range.js';

/** The subset of a window client the pipe drives (injectable). */
export interface WindowClientLike {
  /** Matches `FetchEventLike.clientId`, so a request can be aimed at one tab. */
  readonly id?: string;
  postMessage(message: unknown, transfer?: MessagePortLike[]): void;
}

/** The subset of `ServiceWorkerGlobalScope.clients` the pipe drives. */
export interface ClientsLike {
  matchAll(options: {
    type: 'window';
    includeUncontrolled?: boolean;
  }): Promise<readonly WindowClientLike[]>;
}

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

export class MediaPipe {
  /**
   * One port per client: a tab's registry only knows the tickets that tab
   * minted, so a request answered by another tab's port dies as an unknown
   * ticket.
   */
  private readonly ports = new Map<string, PortEntry>();
  private readonly portWaiters = new Set<(adopted: string) => void>();
  private readonly sinks = new Map<number, ResponseSink>();
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
      if (!head) {
        this.discardPort(port);
        continue;
      }
      if (head.status >= 300) return sealed(head.status, head.headers);
      return sealed(head.status, head.headers, this.body(port, requestId));
    }
    return sealed(503);
  }

  private onMessage(port: MessagePortLike, event: MessageEvent): void {
    const response = asResponse(event.data);
    if (response === null) return;
    const sink = this.sinks.get(response.requestId);
    // An unknown or already-settled id is stale traffic; another client's id is
    // not this port's to answer.
    if (sink?.port === port) sink.deliver(response);
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
          if (response.type !== 'cb:media:head') return;
          clearTimeout(timer);
          this.sinks.delete(requestId);
          resolve(response);
        },
      });
      this.post(port, { type: 'cb:media:open', requestId, ticket, range });
    });
  }

  /** A zero high-water mark keeps exactly one window in flight: pull on demand. */
  private body(port: MessagePortLike, requestId: number): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>(
      {
        pull: (controller) => this.pullWindow(port, requestId, controller),
        cancel: () => {
          // The pull this cancels leaves its timer armed, and that timer discards
          // the port — taking every other body streaming on it down too.
          this.clearPull(requestId);
          this.sinks.delete(requestId);
          this.post(port, { type: 'cb:media:close', requestId });
        },
      },
      { highWaterMark: 0 }
    );
  }

  private pullWindow(
    port: MessagePortLike,
    requestId: number,
    controller: ReadableStreamDefaultController<Uint8Array>
  ): Promise<void> {
    return new Promise<void>((resolve) => {
      const settle = (finish: () => void): void => {
        this.clearPull(requestId);
        this.sinks.delete(requestId);
        finish();
        resolve();
      };
      // A tab that died mid-stream swallows the pull; without this the body
      // never settles and the response hangs open forever.
      const timer = setTimeout(() => {
        settle(() => {
          this.discardPort(port);
          controller.error(new Error('media pull timed out'));
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
              settle(() => controller.close());
              return;
            case 'cb:media:error':
              settle(() => controller.error(new Error(response.message)));
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
    const targets = clientId !== ANONYMOUS_CLIENT && owner.length > 0 ? owner : clients;
    const ask: MediaPortRequest = { type: MEDIA_PORT_REQUEST };
    for (const client of targets) client.postMessage(ask);
    return this.waitForPort(clientId);
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
    entry.port.removeEventListener('message', entry.listener);
    entry.port.close();
    // Bodies still pulling on the dead port would hang forever; failing them
    // makes the media element re-request, which re-brokers and re-buffers.
    for (const [requestId, sink] of [...this.sinks]) {
      if (sink.port !== entry.port) continue;
      this.sinks.delete(requestId);
      sink.deliver({ type: 'cb:media:error', requestId, message: 'media port replaced' });
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
