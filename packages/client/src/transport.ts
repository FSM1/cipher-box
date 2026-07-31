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

import { CorrelatedTransport } from './correlatedTransport.js';
import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  WorkerMessage,
  WorkerRequest,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/** A one-way engine → UI event subscriber. */
export type EngineEventListener = (event: EventDescriptor) => void;

export interface EngineTransport {
  /** Hands the login secret to the engine once (transferred, not copied). */
  start(secret: ArrayBuffer): Promise<void>;
  /** Sends one command; `transfer` lists any owned buffers to move, not copy. */
  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void>;
  /** Opens a write handle for `size` plaintext bytes of streamed content. */
  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle>;
  /** Feeds the next slice to an open handle (the buffer is moved, not copied). */
  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void>;
  /** Closes the handle and journals its op; resolves with the durable op id. */
  commitWrite(handle: WriteHandle): Promise<bigint>;
  /** Abandons the handle, releasing its reservation and staged blocks. */
  abortWrite(handle: WriteHandle): Promise<void>;
  /** Reads a key-free snapshot of `folder` for a UI paint. */
  snapshot(folder: Uint8Array): Promise<SnapshotDescriptor>;
  /** Downloads one file node's plaintext through the verified read pipeline. */
  download(node: Uint8Array): Promise<ArrayBuffer>;
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

/**
 * UI ↔ own engine worker over `postMessage`. Correlates responses to requests
 * by a monotonic request id, so concurrent calls answered in any order never
 * confuse — the id is assigned here and echoed by the worker, never derived from
 * anything the worker controls.
 */
export class LocalTransport extends CorrelatedTransport {
  private readonly ready: Promise<void>;
  private closed = false;
  // Settles `ready` on teardown so a request awaiting cold start before the
  // worker's `ready` rejects instead of hanging forever.
  private rejectReady!: (error: Error) => void;

  constructor(private readonly worker: EngineWorkerLike) {
    super();
    this.ready = new Promise<void>((resolveReady, rejectReady) => {
      this.rejectReady = rejectReady;
      this.worker.addEventListener('message', (event) => {
        const message = event.data;
        switch (message.type) {
          case 'ready':
            resolveReady();
            return;
          case 'response':
            if (message.ok) this.settle(message.id, true, undefined, message.result);
            else this.settle(message.id, false, message.error, undefined, message.code);
            return;
          case 'event':
            this.emit(message.event);
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
    return this.dispatch(this.ready, (id) =>
      this.worker.postMessage({ type: 'start', id, secret }, [secret])
    );
  }

  command(command: CommandDescriptor, transfer: Transferable[]): Promise<void> {
    return this.dispatch(this.ready, (id) =>
      this.worker.postMessage({ type: 'command', id, command }, transfer)
    );
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    return this.request<WriteHandle>(this.ready, (id) =>
      this.worker.postMessage({ type: 'beginWrite', id, target, size }, [])
    );
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    return this.dispatch(this.ready, (id) =>
      this.worker.postMessage({ type: 'pushChunk', id, handle, chunk }, [chunk])
    );
  }

  commitWrite(handle: WriteHandle): Promise<bigint> {
    return this.request<bigint>(this.ready, (id) =>
      this.worker.postMessage({ type: 'commitWrite', id, handle }, [])
    );
  }

  abortWrite(handle: WriteHandle): Promise<void> {
    return this.dispatch(this.ready, (id) =>
      this.worker.postMessage({ type: 'abortWrite', id, handle }, [])
    );
  }

  snapshot(folder: Uint8Array): Promise<SnapshotDescriptor> {
    return this.request<SnapshotDescriptor>(this.ready, (id) =>
      this.worker.postMessage({ type: 'snapshot', id, folder }, [])
    );
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    return this.request<ArrayBuffer>(this.ready, (id) =>
      this.worker.postMessage({ type: 'download', id, node }, [])
    );
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
}
