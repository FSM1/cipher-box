/** The tab-side server for the media byte pipe, answering over a brokered `MessagePort`. */

import { errorMessage } from '../errorMessage.js';
import type { MessagePortLike } from '../portRelay.js';
import type { StreamHandle } from '../worker/protocol.js';
import { MEDIA_WINDOW_BYTES, type MediaRequest, type MediaResponse } from './protocol.js';
import { resolveMediaRequest } from './range.js';
import type { StreamRegistry } from './registry.js';

/** The engine capabilities the pipe needs; `EngineClient` satisfies them. */
export interface MediaReader {
  openContentStream(node: Uint8Array): Promise<StreamHandle>;
  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer>;
  closeStream(handle: StreamHandle): Promise<void>;
}

/**
 * A `<video>` closes a body before opening the range it seeks to, so a pin whose
 * count hits zero is held this long before its engine stream is released.
 */
const DEFAULT_PIN_LINGER_MS = 5000;

export interface MediaBrokerOptions {
  /** The plaintext window read per pull; defaults to `MEDIA_WINDOW_BYTES`. */
  windowBytes?: number;
  /** How long a ticket's engine stream outlives its last cursor. */
  lingerMs?: number;
}

/**
 * The one engine stream every response for a ticket reads against, opened on the
 * first pull — a ticket answered with a head and then abandoned costs no
 * resolve. Pinning per ticket rather than per request holds a single content
 * version across a whole playback, not merely one response (#948).
 */
interface Pin {
  readonly node: Uint8Array;
  stream: Promise<StreamHandle> | null;
  cursors: number;
  linger: ReturnType<typeof setTimeout> | null;
}

/** An open response body: the unread remainder of a resolved window. */
interface Cursor {
  readonly ticket: string;
  /** The mint-time window end, pulled in when a read proves the version is shorter. */
  end: number;
  offset: number;
  /** Reads chain onto this so two pulls can never straddle one cursor. */
  pump: Promise<void>;
}

export class MediaBroker {
  private readonly cursors = new Map<number, Cursor>();
  private readonly pins = new Map<string, Pin>();
  private readonly windowBytes: number;
  private readonly lingerMs: number;
  private port: MessagePortLike | null = null;
  private listener: ((event: MessageEvent) => void) | null = null;

  constructor(
    private readonly registry: StreamRegistry,
    private readonly reader: MediaReader,
    options: MediaBrokerOptions = {}
  ) {
    this.windowBytes = options.windowBytes ?? MEDIA_WINDOW_BYTES;
    this.lingerMs = options.lingerMs ?? DEFAULT_PIN_LINGER_MS;
  }

  /** The pipe carries one port; a fresh offer supersedes the port it replaces. */
  serve(port: MessagePortLike): void {
    this.close();
    const listener = (event: MessageEvent): void => {
      this.dispatch(port, event.data);
    };
    port.addEventListener('message', listener);
    port.start?.();
    this.port = port;
    this.listener = listener;
  }

  close(): void {
    if (this.port !== null && this.listener !== null) {
      this.port.removeEventListener('message', this.listener);
    }
    this.port = null;
    this.listener = null;
    for (const requestId of [...this.cursors.keys()]) this.drop(requestId);
    // A superseded port has no reader left to serve, so nothing lingers.
    for (const ticket of [...this.pins.keys()]) this.evict(ticket);
  }

  /** Forgets a cursor and gives up its share of the ticket's engine stream. */
  private drop(requestId: number): void {
    const cursor = this.cursors.get(requestId);
    if (cursor === undefined) return;
    this.cursors.delete(requestId);
    this.release(cursor.ticket);
  }

  private acquire(ticket: string, node: Uint8Array): void {
    const pin = this.pins.get(ticket);
    if (pin === undefined) {
      this.pins.set(ticket, { node, stream: null, cursors: 1, linger: null });
      return;
    }
    if (pin.linger !== null) clearTimeout(pin.linger);
    pin.linger = null;
    pin.cursors += 1;
  }

  private release(ticket: string): void {
    const pin = this.pins.get(ticket);
    if (pin === undefined) return;
    pin.cursors -= 1;
    if (pin.cursors > 0) return;
    pin.linger = setTimeout(() => this.evict(ticket), this.lingerMs);
  }

  /** Closes a ticket's engine stream. A pin re-acquired since is left alone. */
  private evict(ticket: string): void {
    const pin = this.pins.get(ticket);
    if (pin === undefined || pin.cursors > 0) return;
    if (pin.linger !== null) clearTimeout(pin.linger);
    this.pins.delete(ticket);
    void pin.stream?.then((handle) => this.reader.closeStream(handle)).catch(() => undefined);
  }

  /**
   * Forgets a ticket's engine stream after a failed open or read, so the next
   * pull re-opens rather than replaying the failure for every cursor sharing it.
   */
  private repin(ticket: string): void {
    const pin = this.pins.get(ticket);
    if (pin === undefined || pin.stream === null) return;
    const stream = pin.stream;
    pin.stream = null;
    void stream.then((handle) => this.reader.closeStream(handle)).catch(() => undefined);
  }

  private pinnedStream(ticket: string): Promise<StreamHandle> {
    const pin = this.pins.get(ticket);
    if (pin === undefined) return Promise.reject(new Error('the stream ticket was released'));
    pin.stream ??= this.reader.openContentStream(pin.node);
    return pin.stream;
  }

  private dispatch(port: MessagePortLike, data: unknown): void {
    const request = asRequest(data);
    if (request === null) return;
    switch (request.type) {
      case 'cb:media:open':
        this.open(port, request.requestId, request.ticket, request.range);
        return;
      case 'cb:media:pull':
        this.pull(port, request.requestId);
        return;
      case 'cb:media:close':
        this.drop(request.requestId);
        return;
    }
  }

  private open(
    port: MessagePortLike,
    requestId: number,
    ticket: string,
    range: string | null
  ): void {
    const postHead = (status: number, headers: Array<[string, string]>): void => {
      post(port, { type: 'cb:media:head', requestId, status, headers });
    };

    // A repeat id supersedes whatever it names, whatever this open resolves to.
    this.drop(requestId);

    const source = this.registry.lookup(ticket);
    if (source === undefined) {
      postHead(404, []);
      return;
    }

    const head = resolveMediaRequest(range, source.size, source.mimeType);
    if (head.status === 416) {
      postHead(head.status, head.headers);
      return;
    }

    this.acquire(ticket, source.node);
    this.cursors.set(requestId, {
      ticket,
      offset: head.window.offset,
      end: head.window.offset + head.window.length,
      pump: Promise.resolve(),
    });
    postHead(head.status, head.headers);
  }

  private pull(port: MessagePortLike, requestId: number): void {
    const cursor = this.cursors.get(requestId);
    if (cursor === undefined) return;
    cursor.pump = cursor.pump.then(() => this.pump(port, requestId, cursor));
  }

  /**
   * Whether this cursor still owns the request. A close or a superseding open
   * can land at any await, and answering off a dropped cursor would post another
   * stream's plaintext under this request id.
   */
  private isCurrent(requestId: number, cursor: Cursor): boolean {
    return this.cursors.get(requestId) === cursor;
  }

  private async pump(port: MessagePortLike, requestId: number, cursor: Cursor): Promise<void> {
    if (!this.isCurrent(requestId, cursor)) return;

    const remaining = cursor.end - cursor.offset;
    if (remaining <= 0) {
      this.drop(requestId);
      post(port, { type: 'cb:media:end', requestId });
      return;
    }

    const offset = cursor.offset;
    const length = Math.min(this.windowBytes, remaining);
    try {
      const handle = await this.pinnedStream(cursor.ticket);
      if (!this.isCurrent(requestId, cursor)) return;
      const chunk = await this.reader.readStream(handle, offset, length);
      if (!this.isCurrent(requestId, cursor)) {
        // Nobody will receive this window; wipe it rather than leave plaintext
        // for the collector (AGENTS.md 7 — this is its terminal owner).
        new Uint8Array(chunk).fill(0);
        return;
      }
      cursor.offset = offset + chunk.byteLength;
      // A short read means the live version is smaller than the head promised;
      // ending here is a clean EOF, where under-delivering content-length is a
      // network error to the media element.
      if (chunk.byteLength < length) cursor.end = cursor.offset;
      const response: MediaResponse = { type: 'cb:media:chunk', requestId, chunk };
      port.postMessage(response, [chunk]);
    } catch (error) {
      this.repin(cursor.ticket);
      if (!this.isCurrent(requestId, cursor)) return;
      this.drop(requestId);
      post(port, { type: 'cb:media:error', requestId, message: errorMessage(error) });
    }
  }
}

function post(port: MessagePortLike, response: MediaResponse): void {
  port.postMessage(response);
}

/** A same-origin port is still untrusted input: anything off-shape is dropped. */
function asRequest(data: unknown): MediaRequest | null {
  if (typeof data !== 'object' || data === null) return null;
  const message = data as {
    type?: unknown;
    requestId?: unknown;
    ticket?: unknown;
    range?: unknown;
  };
  const requestId = message.requestId;
  if (typeof requestId !== 'number') return null;

  if (message.type === 'cb:media:open') {
    const { ticket, range } = message;
    if (typeof ticket !== 'string') return null;
    if (typeof range !== 'string' && range !== null) return null;
    return { type: 'cb:media:open', requestId, ticket, range };
  }
  if (message.type === 'cb:media:pull') return { type: 'cb:media:pull', requestId };
  if (message.type === 'cb:media:close') return { type: 'cb:media:close', requestId };
  return null;
}
