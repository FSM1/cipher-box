/** The tab-side server for the media byte pipe, answering over a brokered `MessagePort`. */

import { engineErrorCode, isRecoverableEngineError } from '../correlatedTransport.js';
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

/** A read this broker gave up on, classified by the engine's code. */
export interface MediaFailure {
  readonly ticket: string;
  readonly message: string;
  /** See {@link isRecoverableEngineError}. */
  readonly recoverable: boolean;
}

export interface MediaBrokerOptions {
  /** The plaintext window read per pull. */
  windowBytes?: number;
  /** How long a ticket's engine stream outlives its last cursor. */
  lingerMs?: number;
  /** Told about every read this broker ends with an error. */
  onFailure?: (failure: MediaFailure) => void;
}

/**
 * The one engine stream every response for a ticket reads against, opened on the
 * first pull — a ticket answered with a head and then abandoned costs no
 * resolve. Pinning per ticket rather than per request holds a single content
 * version across a whole playback, not merely one response.
 */
interface Pin {
  stream: Promise<StreamHandle> | null;
  cursors: number;
  linger: ReturnType<typeof setTimeout> | null;
}

/** How a ticket's reading ended, for a holder that waited it out. */
export interface IdleOutcome {
  /** Whether a body ever claimed the ticket. */
  readonly read: boolean;
  /** Why this broker gave up on the last body, or `null` if it did not. */
  readonly failure: string | null;
}

/** A holder waiting for a ticket to stop being read. */
interface IdleWaiter {
  readonly resolve: (outcome: IdleOutcome) => void;
  readonly startWithinMs: number;
  /** Set once a body claims the ticket, which is what the deadline waits for. */
  read: boolean;
  failure: string | null;
  timer: ReturnType<typeof setTimeout> | null;
}

/** An open engine stream and the memo it came from, so a failure can drop it. */
interface Pinned {
  readonly handle: StreamHandle;
  readonly stream: Promise<StreamHandle>;
}

/** An open response body: the unread remainder of a resolved window. */
interface Cursor {
  readonly ticket: string;
  readonly node: Uint8Array;
  readonly pin: Pin;
  /**
   * The stream this body's first window came from. One response never spans two
   * of them: concatenating windows of two content versions under one
   * `Content-Range` is a tear the reader cannot detect.
   */
  bound: Promise<StreamHandle> | null;
  /** The mint-time window end, pulled in when a read proves the version is shorter. */
  end: number;
  offset: number;
  /** Reads chain onto this so two pulls can never straddle one cursor. */
  pump: Promise<void>;
}

export class MediaBroker {
  private readonly cursors = new Map<number, Cursor>();
  private readonly pins = new Map<string, Pin>();
  private readonly idleWaiters = new Map<string, Set<IdleWaiter>>();
  private readonly windowBytes: number;
  private readonly lingerMs: number;
  private readonly onFailure: ((failure: MediaFailure) => void) | null;
  private port: MessagePortLike | null = null;
  private listener: ((event: MessageEvent) => void) | null = null;

  constructor(
    private readonly registry: StreamRegistry,
    private readonly reader: MediaReader,
    options: MediaBrokerOptions = {}
  ) {
    this.windowBytes = options.windowBytes ?? MEDIA_WINDOW_BYTES;
    this.lingerMs = options.lingerMs ?? DEFAULT_PIN_LINGER_MS;
    this.onFailure = options.onFailure ?? null;
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
    this.cursors.clear();
    for (const pin of this.pins.values()) void this.discard(pin);
    this.pins.clear();
    // A replaced port is how a killed worker recovers: its bodies re-open on the
    // port that replaces this one, so waiters get a fresh deadline, not an end.
    for (const [ticket, waiters] of this.idleWaiters) {
      for (const waiter of waiters) this.arm(ticket, waiter);
    }
  }

  /**
   * Resolves once no response body is reading `ticket`, with how the reading
   * ended. A ticket is a bearer capability to plaintext, so its holder needs
   * this to know when dropping it can no longer cut a transfer short — and a
   * body that died after its first byte still went idle having been read, so
   * only the failure tells a short transfer from a whole one.
   *
   * @param startWithinMs how long to wait for a body to claim the ticket. A
   * claimed ticket has no deadline — a reader between windows is still reading.
   */
  whenIdle(ticket: string, startWithinMs: number): Promise<IdleOutcome> {
    return new Promise((resolve) => {
      const waiter: IdleWaiter = {
        resolve,
        startWithinMs,
        read: (this.pins.get(ticket)?.cursors ?? 0) > 0,
        failure: null,
        timer: null,
      };
      this.arm(ticket, waiter);
      const waiters = this.idleWaiters.get(ticket);
      if (waiters === undefined) this.idleWaiters.set(ticket, new Set([waiter]));
      else waiters.add(waiter);
    });
  }

  private arm(ticket: string, waiter: IdleWaiter): void {
    if (waiter.timer !== null) clearTimeout(waiter.timer);
    waiter.timer = setTimeout(() => this.expire(ticket, waiter), waiter.startWithinMs);
  }

  private expire(ticket: string, waiter: IdleWaiter): void {
    if ((this.pins.get(ticket)?.cursors ?? 0) > 0) {
      this.arm(ticket, waiter);
      return;
    }
    const waiters = this.idleWaiters.get(ticket);
    waiters?.delete(waiter);
    if (waiters?.size === 0) this.idleWaiters.delete(ticket);
    settle(waiter);
  }

  private settleIdle(ticket: string): void {
    const waiters = this.idleWaiters.get(ticket);
    if (waiters === undefined) return;
    this.idleWaiters.delete(ticket);
    for (const waiter of waiters) {
      if (waiter.timer !== null) clearTimeout(waiter.timer);
      settle(waiter);
    }
  }

  /**
   * Ends every body reading a revoked ticket and releases its engine stream. A
   * ticket is a bearer capability to plaintext, so withdrawing it must stop the
   * bytes already in flight, not merely the next request.
   */
  revoke(ticket: string): void {
    for (const [requestId, cursor] of [...this.cursors]) {
      if (cursor.ticket !== ticket) continue;
      this.cursors.delete(requestId);
      if (this.port !== null) {
        post(this.port, { type: 'cb:media:error', requestId, message: 'the stream was revoked' });
      }
    }
    this.settleIdle(ticket);
    const pin = this.pins.get(ticket);
    if (pin === undefined) return;
    this.pins.delete(ticket);
    void this.discard(pin);
  }

  /** Forgets a cursor and gives up its share of the ticket's engine stream. */
  private drop(requestId: number): void {
    const cursor = this.cursors.get(requestId);
    if (cursor === undefined) return;
    this.cursors.delete(requestId);
    cursor.pin.cursors -= 1;
    if (cursor.pin.cursors > 0) return;
    this.settleIdle(cursor.ticket);
    cursor.pin.linger = setTimeout(() => this.evict(cursor.ticket), this.lingerMs);
  }

  private acquire(ticket: string): Pin {
    for (const waiter of this.idleWaiters.get(ticket) ?? []) waiter.read = true;
    const held = this.pins.get(ticket);
    if (held === undefined) {
      const pin: Pin = { stream: null, cursors: 1, linger: null };
      this.pins.set(ticket, pin);
      return pin;
    }
    if (held.linger !== null) clearTimeout(held.linger);
    held.linger = null;
    held.cursors += 1;
    return held;
  }

  /** Closes a ticket's engine stream unless a cursor took the pin back. */
  private evict(ticket: string): void {
    const pin = this.pins.get(ticket);
    if (pin === undefined || pin.cursors > 0) return;
    this.pins.delete(ticket);
    void this.discard(pin);
  }

  /** Resolves when the engine has the stream back. */
  private release(stream: Promise<StreamHandle>): Promise<void> {
    return stream.then((handle) => this.reader.closeStream(handle)).catch(() => undefined);
  }

  private discard(pin: Pin): Promise<void> | null {
    if (pin.linger !== null) clearTimeout(pin.linger);
    pin.linger = null;
    const stream = pin.stream;
    pin.stream = null;
    return stream === null ? null : this.release(stream);
  }

  /**
   * Gives back every stream held by the linger alone, so a refusal at the
   * engine's open-stream ceiling has a slot to retry into. Resolves false when
   * there was nothing to give back.
   */
  private async reclaimIdle(): Promise<boolean> {
    const closing: Array<Promise<void>> = [];
    for (const [ticket, pin] of [...this.pins]) {
      if (pin.cursors > 0) continue;
      this.pins.delete(ticket);
      const closed = this.discard(pin);
      if (closed !== null) closing.push(closed);
    }
    if (closing.length === 0) return false;
    await Promise.all(closing);
    return true;
  }

  /** Drops a stream the pin still names, so the next pull opens a fresh one. */
  private forget(pin: Pin, stream: Promise<StreamHandle>): void {
    if (pin.stream !== stream) return;
    pin.stream = null;
    void this.release(stream);
  }

  private async openOnto(cursor: Cursor): Promise<Pinned> {
    const pin = cursor.pin;
    const stream = (pin.stream ??= this.reader.openContentStream(cursor.node));
    try {
      return { handle: await stream, stream };
    } catch (error) {
      // A rejected open must not be remembered, or every cursor on the ticket
      // replays it.
      this.forget(pin, stream);
      throw error;
    }
  }

  private async pinnedStream(cursor: Cursor): Promise<Pinned> {
    try {
      return await this.openOnto(cursor);
    } catch (error) {
      if (!isRecoverableEngineError(engineErrorCode(error))) throw error;
      if (!(await this.reclaimIdle())) throw error;
      // A close, a revoke, an eviction, or the reclaim itself can drop the pin
      // across the await. Every release path reaches a stream through `pins`, so
      // opening onto a pin no longer in it strands the handle and its content
      // key for the life of the worker.
      if (this.pins.get(cursor.ticket) !== cursor.pin) throw error;
      return this.openOnto(cursor);
    }
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

    const head = resolveMediaRequest(range, source.size, source);
    if (head.status === 416) {
      postHead(head.status, head.headers);
      return;
    }

    this.cursors.set(requestId, {
      ticket,
      node: source.node,
      pin: this.acquire(ticket),
      bound: null,
      offset: head.window.offset,
      end: head.window.offset + head.window.length,
      pump: Promise.resolve(),
    });
    postHead(head.status, head.headers);
  }

  private pull(port: MessagePortLike, requestId: number): void {
    const cursor = this.cursors.get(requestId);
    if (cursor === undefined) return;
    // A post onto a port that died mid-pump must not poison the chain: every
    // later pull would chain off a rejection and silently never run.
    cursor.pump = cursor.pump.then(() => this.pump(port, requestId, cursor)).catch(() => undefined);
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

    let pinned: Pinned;
    try {
      pinned = await this.pinnedStream(cursor);
    } catch (error) {
      this.fail(port, requestId, cursor, error);
      return;
    }
    if (!this.isCurrent(requestId, cursor)) return;

    cursor.bound ??= pinned.stream;
    if (cursor.bound !== pinned.stream) {
      this.fail(port, requestId, cursor, new Error('the content version changed mid-response'));
      return;
    }

    let chunk: ArrayBuffer;
    try {
      chunk = await this.reader.readStream(pinned.handle, offset, length);
    } catch (error) {
      // A handle the engine no longer knows is dead for every cursor sharing it,
      // so the ticket re-opens. Any other read failure leaves the pinned version
      // alone.
      if (engineErrorCode(error) === 'unknownStreamHandle') this.forget(cursor.pin, pinned.stream);
      this.fail(port, requestId, cursor, error);
      return;
    }

    // Past here the window is plaintext this broker owns outright, so every exit
    // either transfers it or wipes it (AGENTS.md 7).
    if (!this.isCurrent(requestId, cursor)) {
      new Uint8Array(chunk).fill(0);
      return;
    }
    // Read before the transfer detaches the buffer and zeroes its length.
    const delivered = chunk.byteLength;
    const response: MediaResponse = { type: 'cb:media:chunk', requestId, chunk };
    try {
      port.postMessage(response, [chunk]);
    } catch (error) {
      // A transfer that threw before detaching still leaves the window here;
      // one that detached reports zero bytes and needs no wipe.
      if (chunk.byteLength > 0) new Uint8Array(chunk).fill(0);
      this.fail(port, requestId, cursor, error);
      return;
    }
    cursor.offset = offset + delivered;
    // A short read means the live version is smaller than the head promised;
    // ending here is a clean EOF, where under-delivering content-length is a
    // network error to the media element.
    if (delivered < length) cursor.end = cursor.offset;
  }

  private fail(port: MessagePortLike, requestId: number, cursor: Cursor, error: unknown): void {
    if (!this.isCurrent(requestId, cursor)) return;
    const message = errorMessage(error);
    // Recorded before the drop, which is what settles the waiters.
    for (const waiter of this.idleWaiters.get(cursor.ticket) ?? []) waiter.failure = message;
    this.drop(requestId);
    post(port, { type: 'cb:media:error', requestId, message });
    this.onFailure?.({
      ticket: cursor.ticket,
      message,
      recoverable: isRecoverableEngineError(engineErrorCode(error)),
    });
  }
}

function settle(waiter: IdleWaiter): void {
  waiter.resolve({ read: waiter.read, failure: waiter.failure });
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
