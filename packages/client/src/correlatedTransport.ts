/**
 * Shared request-correlation machinery for the two `EngineTransport`s
 * (`LocalTransport` over a worker, `BroadcastTransport` over a channel). Both
 * correlate responses to requests by a monotonic id and honor the same teardown
 * contract: a torn-down or dead transport **rejects** every pending request
 * instead of hanging.
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

/** The engine's stable code for a failure, or `undefined` for a transport fault. */
export function engineErrorCode(error: unknown): string | undefined {
  return error instanceof EngineRequestError ? error.code : undefined;
}

/**
 * Whether the same call can succeed once the caller frees the resource the
 * engine refused over — `tooManyStreams` is a ceiling, not a verdict
 * (`EngineError` in `crates/engine/src/facade.rs`). Every trust code is a
 * distinct string, so none of them can widen into this.
 */
export function isRecoverableEngineError(code: string | undefined): boolean {
  return code === 'tooManyStreams';
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
 * An `ArrayBuffer`'s length, or `null` for anything that is not one. Branding
 * by the `byteLength` getter rather than `instanceof`, which answers false for
 * a buffer minted in another realm — a worker's, a frame's — leaving a secret
 * that reached this list from there unscrubbed.
 */
const byteLengthOf = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')?.get;

function bufferLength(item: Transferable): number | null {
  try {
    return (byteLengthOf?.call(item) as number | undefined) ?? null;
  } catch {
    return null;
  }
}

/**
 * Scrubs the buffers a send would have transferred. A request that rejects
 * before its send leaves this frame their terminal owner — nothing detaches
 * them and no callee can reach them — so the plaintext is cleared here
 * (AGENTS.md 7). A transferred buffer reads as empty, so a send that did run
 * leaves this a no-op.
 */
function wipeTransfer(transfer: Transferable[] | undefined): void {
  for (const item of transfer ?? []) {
    const length = bufferLength(item);
    if (length !== null && length > 0) new Uint8Array(item as ArrayBuffer).fill(0);
  }
}

/**
 * Delivers one event to every listener, isolating a throwing subscriber so it
 * cannot drop the event for the rest.
 */
export function fanOut<TEvent>(listeners: Iterable<(event: TEvent) => void>, event: TEvent): void {
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
   *
   * `transfer` is what the send would have moved out of this realm; every route
   * to a rejection without it scrubs them ([`wipeTransfer`]).
   */
  protected request<T, G = void>(
    readyGate: Promise<G>,
    send: (id: number, gate: G) => void,
    transfer?: Transferable[]
  ): Promise<T> {
    if (this.terminalError) {
      wipeTransfer(transfer);
      return Promise.reject(this.terminalError);
    }
    return readyGate.then(
      (gate) =>
        new Promise<T>((resolve, reject) => {
          if (this.terminalError) {
            wipeTransfer(transfer);
            reject(this.terminalError);
            return;
          }
          const id = this.nextId++;
          this.pending.set(id, { resolve: resolve as (result: unknown) => void, reject });
          try {
            send(id, gate);
          } catch (error) {
            this.pending.delete(id);
            wipeTransfer(transfer);
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        }),
      (error: unknown) => {
        wipeTransfer(transfer);
        throw error;
      }
    );
  }

  /** The void-ack variant of [`request`](CorrelatedTransport.request). */
  protected dispatch(
    readyGate: Promise<void>,
    send: (id: number) => void,
    transfer?: Transferable[]
  ): Promise<void> {
    return this.request<void>(readyGate, send, transfer);
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
