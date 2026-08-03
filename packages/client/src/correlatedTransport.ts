/**
 * Shared request-correlation machinery for the two `EngineTransport`s
 * (`LocalTransport` over a worker, `BroadcastTransport` over a channel). Both
 * correlate responses to requests by a monotonic id and honor the same teardown
 * contract hardened in #728: a torn-down or dead transport **rejects** every
 * pending request instead of hanging.
 *
 * A subclass supplies only its readiness gate and its send primitive; this base
 * owns the pending map, the no-hang request skeleton, response settlement, the
 * terminal-failure latch, and the event fan-out. A gate may resolve with the
 * wire the send needs — a follower's read gate yields its private port.
 */

import type { EngineEventListener, EngineTransport } from './transport.js';
import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  StreamHandle,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

interface Pending {
  resolve: (result: unknown) => void;
  reject: (error: Error) => void;
}

/**
 * A rejected engine request. `code` is the engine's stable machine-readable
 * error code (the wasm host's camelCase `EngineError` variant name, e.g.
 * `'unknownNode'`, `'contentUnavailable'`) when the failure crossed from the
 * engine; absent for transport-level failures.
 */
export class EngineRequestError extends Error {
  readonly code?: string;

  constructor(message: string, code?: string) {
    super(message);
    this.name = 'EngineRequestError';
    this.code = code;
  }
}

/** Which of the engine's handle tables a step addresses. */
export type HandleKind = 'write' | 'stream';

/**
 * Refuses a step on a handle the refusing layer cannot serve, spelled exactly
 * like the engine's own unknown-handle error: a probing tab learns nothing a
 * legitimate one would not. Mirrors `EngineError::Unknown*Handle`.
 */
export function unknownHandle(kind: HandleKind): EngineRequestError {
  return new EngineRequestError(
    `unknown ${kind} handle`,
    kind === 'write' ? 'unknownWriteHandle' : 'unknownStreamHandle'
  );
}

/**
 * Delivers one event to every listener, isolating a throwing subscriber so it
 * cannot drop the event for the rest.
 */
export function fanOut(listeners: Iterable<EngineEventListener>, event: EventDescriptor): void {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch {
      // One throwing subscriber must not drop the event for the rest.
    }
  }
}

export abstract class CorrelatedTransport implements EngineTransport {
  private readonly pending = new Map<number, Pending>();
  private readonly listeners = new Set<EngineEventListener>();
  private nextId = 1;
  // A fatal message, transport error, or teardown latches this. Once set, every
  // request rejects here instead of dispatching and waiting for a response that
  // can never arrive.
  protected terminalError: Error | null = null;

  abstract start(secret: ArrayBuffer): Promise<void>;
  abstract command(command: CommandDescriptor, transfer: Transferable[]): Promise<void>;
  abstract beginWrite(target: WriteTarget, size: number): Promise<WriteHandle>;
  abstract pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void>;
  abstract commitWrite(handle: WriteHandle): Promise<bigint>;
  abstract abortWrite(handle: WriteHandle): Promise<void>;
  abstract snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor>;
  abstract siweChallenge(): Promise<string>;
  abstract download(node: Uint8Array): Promise<ArrayBuffer>;
  abstract openContentStream(node: Uint8Array): Promise<StreamHandle>;
  abstract readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer>;
  abstract closeStream(handle: StreamHandle): Promise<void>;
  abstract close(): void;

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Fans one engine event out to this transport's subscribers. */
  protected emit(event: EventDescriptor): void {
    fanOut(this.listeners, event);
  }

  /**
   * The no-hang request skeleton: short-circuit on `terminalError` before
   * awaiting the readiness gate, register the pending entry, then `send`. A
   * synchronous `send` failure deletes the pending entry before rejecting so it
   * is never stranded. Resolves with the response's result value (`undefined`
   * for a plain ack).
   */
  protected request<T, G = void>(
    readyGate: Promise<G>,
    send: (id: number, gate: G) => void
  ): Promise<T> {
    if (this.terminalError) return Promise.reject(this.terminalError);
    return readyGate.then(
      (gate) =>
        new Promise<T>((resolve, reject) => {
          if (this.terminalError) {
            reject(this.terminalError);
            return;
          }
          const id = this.nextId++;
          this.pending.set(id, { resolve: resolve as (result: unknown) => void, reject });
          try {
            send(id, gate);
          } catch (error) {
            this.pending.delete(id);
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        })
    );
  }

  /** The void-ack variant of [`request`](CorrelatedTransport.request). */
  protected dispatch(readyGate: Promise<void>, send: (id: number) => void): Promise<void> {
    return this.request<void>(readyGate, send);
  }

  /** Correlates a response to its request id, resolving or rejecting it. */
  protected settle(id: number, ok: boolean, error?: string, result?: unknown, code?: string): void {
    const pending = this.pending.get(id);
    if (!pending) return;
    this.pending.delete(id);
    if (ok) pending.resolve(result);
    else pending.reject(new EngineRequestError(error ?? 'engine request failed', code));
  }

  /**
   * Rejects every in-flight request without latching a terminal error, so the
   * transport stays usable. Used when leadership moves under a follower: the
   * requests bound to the departed leader reject retryably while the transport
   * awaits the next leader.
   */
  protected rejectPending(error: Error): void {
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }

  /** Latches terminal failure and rejects every in-flight request. */
  protected fail(error: Error): void {
    this.terminalError ??= error;
    this.rejectPending(error);
  }
}
