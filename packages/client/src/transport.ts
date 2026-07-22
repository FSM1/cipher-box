/**
 * The facade transport seam (blueprint/web-client.md "The facade is
 * transport-agnostic").
 *
 * The facade talks to exactly one `EngineTransport`. This slice ships the
 * **local** transport (UI ↔ its own engine worker over `postMessage`, binary
 * payloads transferred). The leader-follower **broadcast** transport is the next
 * slice (#640) and slots in behind this same interface — the facade never
 * changes when leadership swaps the transport underneath it.
 */

import type {
  CommandDescriptor,
  EventDescriptor,
  WorkerMessage,
  WorkerRequest,
} from './worker/protocol.js';

/** A one-way engine → UI event subscriber. */
export type EngineEventListener = (event: EventDescriptor) => void;

export interface EngineTransport {
  /** Hands the login secret to the engine once (transferred, not copied). */
  start(secret: ArrayBuffer): Promise<void>;
  /** Sends one command; `transfer` lists any owned buffers to move, not copy. */
  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void>;
  /** Subscribes to the one-way event stream; returns an unsubscribe. */
  subscribe(listener: EngineEventListener): () => void;
  /** Tears the transport down; pending requests reject. */
  close(): void;
}

/** The subset of `Worker` the local transport drives (injectable for tests). */
export interface EngineWorkerLike {
  postMessage(message: WorkerRequest, transfer: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerMessage>) => void): void;
  addEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
  terminate(): void;
}

interface Pending {
  resolve: () => void;
  reject: (error: Error) => void;
}

/**
 * UI ↔ own engine worker over `postMessage`. Correlates responses to requests
 * by a monotonic request id, so concurrent calls answered in any order never
 * confuse — the id is assigned here and echoed by the worker, never derived from
 * anything the worker controls.
 */
export class LocalTransport implements EngineTransport {
  private readonly pending = new Map<number, Pending>();
  private readonly listeners = new Set<EngineEventListener>();
  private readonly ready: Promise<void>;
  private nextId = 1;
  private closed = false;
  // A fatal worker message, `error` event, or teardown latches this. Once set,
  // the worker is dead, so every request rejects here instead of posting and
  // waiting forever for a response that can never arrive.
  private terminalError: Error | null = null;
  // Settles `ready` on teardown so a request awaiting cold start before the
  // worker's `ready` rejects instead of hanging forever.
  private rejectReady!: (error: Error) => void;

  constructor(private readonly worker: EngineWorkerLike) {
    this.ready = new Promise<void>((resolveReady, rejectReady) => {
      this.rejectReady = rejectReady;
      this.worker.addEventListener('message', (event) => {
        const message = event.data;
        switch (message.type) {
          case 'ready':
            resolveReady();
            return;
          case 'response': {
            const pending = this.pending.get(message.id);
            if (!pending) return;
            this.pending.delete(message.id);
            if (message.ok) pending.resolve();
            else pending.reject(new Error(message.error));
            return;
          }
          case 'event':
            for (const listener of this.listeners) {
              try {
                listener(message.event);
              } catch {
                // One throwing subscriber must not drop the event for the rest.
              }
            }
            return;
          case 'fatal':
            rejectReady(new Error(message.error));
            this.fail(new Error(message.error));
            return;
        }
      });
      this.worker.addEventListener('error', (event) => {
        const error = new Error(event.message || 'engine worker error');
        rejectReady(error);
        this.fail(error);
      });
    });
    // A never-observed rejection would warn; the request path re-observes it.
    this.ready.catch(() => undefined);
  }

  start(secret: ArrayBuffer): Promise<void> {
    return this.request((id) => ({ type: 'start', id, secret }), [secret]);
  }

  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void> {
    return this.request((id) => ({ type: 'command', id, command }), transfer);
  }

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    const error = new Error('engine transport closed');
    // Reject `ready` first so a request parked on cold start unblocks with the
    // teardown error rather than hanging; `fail` then rejects in-flight requests.
    this.rejectReady(error);
    this.fail(error);
    this.worker.terminate();
  }

  private request(build: (id: number) => WorkerRequest, transfer: Transferable[]): Promise<void> {
    if (this.terminalError) return Promise.reject(this.terminalError);
    return this.ready.then(
      () =>
        new Promise<void>((resolve, reject) => {
          if (this.terminalError) {
            reject(this.terminalError);
            return;
          }
          const id = this.nextId++;
          this.pending.set(id, { resolve, reject });
          try {
            this.worker.postMessage(build(id), transfer);
          } catch (error) {
            // A synchronous post failure (detached buffer, bad transferable)
            // must not strand the pending entry.
            this.pending.delete(id);
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        })
    );
  }

  private fail(error: Error): void {
    this.terminalError ??= error;
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}
