/**
 * Test doubles for the leadership/broadcast unit suite. Excluded from the build
 * (tsconfig.build.json). These model the *behaviors* the real browser APIs give
 * us — an origin-exclusive lock and a same-origin broadcast bus that never
 * echoes to the sender — so unit tests can drive election, relaying, and
 * failover deterministically. The real-API coverage lives in the browser suite.
 */

import type { BroadcastChannelLike } from './broadcast.js';
import type { MessagePortLike } from './media/protocol.js';
import type { LockManagerLike, LockRequestCallback } from './leadership.js';
import type { PortCourier } from './portCourier.js';
import type { EngineEventListener, EngineTransport, EngineWorkerLike } from './transport.js';
import type { EngineHostLike } from './worker/engineHost.js';
import type {
  CommandDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  WorkerMessage,
  WriteHandle,
  WriteTarget,
} from './worker/protocol.js';

/**
 * The wasm-bindgen mirror-enum value tables (as `crates/wasm` exports them),
 * shared by the codec and worker test stubs.
 */
export const fakeWasmEnums = {
  NodeKind: { File: 0, Folder: 1 },
  PendingClass: { None: 0, Metadata: 1, Content: 2 },
  Permission: { Read: 0, Write: 1 },
  Staleness: { Fresh: 0, Reconciling: 1, Stale: 2, Offline: 3 },
  OpPhase: {
    DownloadStarted: 0,
    DownloadCompleted: 1,
    DownloadFailed: 2,
    UploadStarted: 3,
    UploadProgress: 4,
    UploadCompleted: 5,
    UploadFailed: 6,
    UploadCancelled: 7,
  },
  DeadLetterReason: {
    TargetGone: 0,
    DestinationGone: 1,
    DestinationInsideTarget: 2,
    SuffixExhausted: 3,
    Undecodable: 4,
    PayloadRefused: 5,
    AttemptsExhausted: 6,
    ContentUnrecoverable: 7,
  },
} as const;

/** A nonce inside the EIP-4361 class the engine enforces. */
export const FAKE_SIWE_NONCE = 'nonce123456789ab';

/** A minimal empty snapshot descriptor for transport-plumbing assertions. */
export function emptySnapshot(folder: Uint8Array = new Uint8Array(16)): SnapshotDescriptor {
  return {
    root: new Uint8Array(16),
    folder,
    folderName: '',
    children: [],
    ancestors: [],
    deadLetters: [],
    blocked: null,
    retainedRecords: 0,
    staleness: 'fresh',
  };
}

const notStubbed = (method: string): Promise<never> =>
  Promise.reject(new Error(`${method} not stubbed`));

/**
 * The base for every `EngineHostLike` double: a method a double does not
 * override rejects, so a new member of the interface lands here once instead of
 * in each double.
 */
export class StubEngineHost implements EngineHostLike {
  start(_secret: ArrayBuffer): Promise<void> {
    return notStubbed('start');
  }

  command(_command: CommandDescriptor): Promise<void> {
    return notStubbed('command');
  }

  beginWrite(_target: WriteTarget, _size: number): Promise<WriteHandle> {
    return notStubbed('beginWrite');
  }

  pushChunk(_handle: WriteHandle, _chunk: ArrayBuffer): Promise<void> {
    return notStubbed('pushChunk');
  }

  commitWrite(_handle: WriteHandle): Promise<bigint> {
    return notStubbed('commitWrite');
  }

  abortWrite(_handle: WriteHandle): Promise<void> {
    return notStubbed('abortWrite');
  }

  snapshot(_folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    return notStubbed('snapshot');
  }

  siweChallenge(): Promise<string> {
    return notStubbed('siweChallenge');
  }

  download(_node: Uint8Array): Promise<ArrayBuffer> {
    return notStubbed('download');
  }

  downloadRange(_node: Uint8Array, _offset: number, _length: number): Promise<ArrayBuffer> {
    return notStubbed('downloadRange');
  }

  nextEvent(): Promise<EventDescriptor | null> {
    return notStubbed('nextEvent');
  }
}

/** A same-origin broadcast bus: a posted message reaches every *other* channel. */
export class FakeBus {
  private readonly channels = new Set<FakeChannel>();

  channel(): FakeChannel {
    const channel = new FakeChannel(this, (c) => this.channels.delete(c));
    this.channels.add(channel);
    return channel;
  }

  deliver(from: FakeChannel, message: unknown): void {
    // Structured-clone semantics: the sender never receives its own post.
    for (const channel of this.channels) if (channel !== from) channel.receive(message);
  }
}

export class FakeChannel implements BroadcastChannelLike {
  private readonly listeners = new Set<(event: MessageEvent) => void>();
  private closed = false;

  constructor(
    private readonly bus: FakeBus,
    private readonly onClose: (channel: FakeChannel) => void
  ) {}

  postMessage(message: unknown): void {
    if (this.closed) return;
    // Deliver asynchronously, like a real BroadcastChannel.
    queueMicrotask(() => this.bus.deliver(this, structuredClone(message)));
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners.add(listener);
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners.delete(listener);
  }

  receive(message: unknown): void {
    if (this.closed) return;
    for (const listener of this.listeners) listener({ data: message } as MessageEvent);
  }

  close(): void {
    this.closed = true;
    this.onClose(this);
  }
}

/**
 * One end of a channel. Delivery is asynchronous and structured-cloned, like a
 * real `MessagePort`; `transferred` records what the sender asked to move, so a
 * test can tell a transfer from a copy.
 */
export class FakeChannelPort implements MessagePortLike {
  peer: FakeChannelPort | null = null;
  readonly transferred: unknown[][] = [];
  started = false;
  closed = false;
  private listeners: Array<(event: MessageEvent) => void> = [];

  postMessage(message: unknown, transfer?: Transferable[]): void {
    if (this.closed) return;
    this.transferred.push(transfer ? [...transfer] : []);
    const delivered = structuredClone(message);
    queueMicrotask(() => this.peer?.receive(delivered));
  }

  addEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners.push(listener);
  }

  removeEventListener(_type: 'message', listener: (event: MessageEvent) => void): void {
    this.listeners = this.listeners.filter((entry) => entry !== listener);
  }

  start(): void {
    this.started = true;
  }

  close(): void {
    this.closed = true;
  }

  receive(data: unknown): void {
    if (this.closed) return;
    for (const listener of [...this.listeners]) listener({ data } as MessageEvent);
  }
}

/**
 * An origin's worth of couriers: `connect` opens a real pair of linked ports and
 * hands the far end to the courier registered at that address.
 */
export class FakeCourierNetwork {
  private readonly inboxes = new Map<string, Set<(port: MessagePortLike) => void>>();

  courier(address: string): PortCourier {
    return {
      address: () => Promise.resolve(address),
      connect: (to) => Promise.resolve(this.open(to)),
      onPort: (handler) => {
        const handlers = this.inboxes.get(address) ?? new Set();
        handlers.add(handler);
        this.inboxes.set(address, handlers);
        return () => handlers.delete(handler);
      },
    };
  }

  private open(to: string): MessagePortLike {
    const near = new FakeChannelPort();
    const far = new FakeChannelPort();
    near.peer = far;
    far.peer = near;
    const handlers = this.inboxes.get(to);
    if (handlers) for (const handler of [...handlers]) handler(far);
    return near;
  }
}

/** A courier with no Service Worker behind it: every brokerage step refuses. */
export const brokenCourier: PortCourier = {
  address: () => Promise.reject(new Error('no broker')),
  connect: () => Promise.reject(new Error('no broker')),
  onPort: () => () => undefined,
};

interface Held {
  release: () => void;
  done: Promise<unknown>;
}

/** An origin-exclusive lock: at most one holder at a time, FIFO queue behind it. */
export class FakeLockManager implements LockManagerLike {
  private held: Held | null = null;
  private readonly queue: Array<() => void> = [];

  request(
    name: string,
    options: { signal?: AbortSignal; mode?: 'exclusive' },
    callback: LockRequestCallback
  ): Promise<unknown> {
    return new Promise<unknown>((resolveRequest, rejectRequest) => {
      const signal = options.signal;
      const grant = (): void => {
        if (signal?.aborted) {
          rejectRequest(new DOMException('aborted', 'AbortError'));
          this.next();
          return;
        }
        const done = Promise.resolve(callback({ name }));
        this.held = { release: () => undefined, done };
        void done.then(
          (value) => {
            this.held = null;
            resolveRequest(value);
            this.next();
          },
          (error) => {
            this.held = null;
            rejectRequest(error);
            this.next();
          }
        );
      };

      const enqueue = (): void => {
        this.queue.push(grant);
        if (!this.held) this.next();
      };

      if (signal) {
        signal.addEventListener('abort', () => {
          const index = this.queue.indexOf(grant);
          if (index >= 0) {
            this.queue.splice(index, 1);
            rejectRequest(new DOMException('aborted', 'AbortError'));
          }
        });
      }
      enqueue();
    });
  }

  private next(): void {
    if (this.held || this.queue.length === 0) return;
    const grant = this.queue.shift();
    grant?.();
  }
}

/** A minimal in-process EngineTransport for relay/orchestrator tests. */
export class FakeEngineTransport implements EngineTransport {
  readonly commands: CommandDescriptor[] = [];
  readonly snapshots: Array<Uint8Array | null> = [];
  readonly downloads: Uint8Array[] = [];
  siweChallenges = 0;
  readonly downloadRanges: Array<{ node: Uint8Array; offset: number; length: number }> = [];
  readonly beginWrites: Array<{ target: WriteTarget; size: number }> = [];
  readonly chunks: Array<{ handle: WriteHandle; chunk: ArrayBuffer }> = [];
  readonly commits: WriteHandle[] = [];
  readonly aborts: WriteHandle[] = [];
  started: ArrayBuffer[] = [];
  closed = false;
  /** What `beginWrite` hands back and what `commitWrite` resolves with. */
  writeHandle: WriteHandle = 1n;
  commitOpId = 42n;
  respond: (command: CommandDescriptor) => Promise<void> = () => Promise.resolve();
  respondSnapshot: (folder: Uint8Array | null) => Promise<SnapshotDescriptor> = (folder) =>
    Promise.resolve(emptySnapshot(folder ?? undefined));
  respondDownload: (node: Uint8Array) => Promise<ArrayBuffer> = () =>
    Promise.resolve(new ArrayBuffer(0));
  respondSiweChallenge: () => Promise<string> = () => Promise.resolve(FAKE_SIWE_NONCE);
  respondDownloadRange: (node: Uint8Array, offset: number, length: number) => Promise<ArrayBuffer> =
    (_node, _offset, length) => Promise.resolve(new ArrayBuffer(length));
  private readonly listeners = new Set<EngineEventListener>();

  start(secret: ArrayBuffer): Promise<void> {
    this.started.push(secret);
    return Promise.resolve();
  }

  command(command: CommandDescriptor): Promise<void> {
    this.commands.push(command);
    return this.respond(command);
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    this.beginWrites.push({ target, size });
    return Promise.resolve(this.writeHandle);
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    this.chunks.push({ handle, chunk });
    return Promise.resolve();
  }

  commitWrite(handle: WriteHandle): Promise<bigint> {
    this.commits.push(handle);
    return Promise.resolve(this.commitOpId);
  }

  abortWrite(handle: WriteHandle): Promise<void> {
    this.aborts.push(handle);
    return Promise.resolve();
  }

  snapshot(folder: Uint8Array | null): Promise<SnapshotDescriptor> {
    this.snapshots.push(folder);
    return this.respondSnapshot(folder);
  }

  siweChallenge(): Promise<string> {
    this.siweChallenges += 1;
    return this.respondSiweChallenge();
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    this.downloads.push(node);
    return this.respondDownload(node);
  }

  downloadRange(node: Uint8Array, offset: number, length: number): Promise<ArrayBuffer> {
    this.downloadRanges.push({ node, offset, length });
    return this.respondDownloadRange(node, offset, length);
  }

  subscribe(listener: EngineEventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit(event: EventDescriptor): void {
    for (const listener of this.listeners) listener(event);
  }

  close(): void {
    this.closed = true;
  }
}

/** A worker double that immediately reports `ready` and echoes responses. */
export class FakeEngineWorker implements EngineWorkerLike {
  readonly posted: unknown[] = [];
  terminated = false;
  private messageListeners: Array<(event: MessageEvent<WorkerMessage>) => void> = [];

  postMessage(message: { id?: number }): void {
    this.posted.push(message);
    if (typeof message.id === 'number') {
      queueMicrotask(() => this.emit({ type: 'response', id: message.id!, ok: true }));
    }
  }

  addEventListener(type: 'message' | 'error', listener: unknown): void {
    if (type === 'message')
      this.messageListeners.push(listener as (e: MessageEvent<WorkerMessage>) => void);
  }

  terminate(): void {
    this.terminated = true;
  }

  emit(message: WorkerMessage): void {
    for (const listener of this.messageListeners)
      listener({ data: message } as MessageEvent<WorkerMessage>);
  }

  ready(): void {
    this.emit({ type: 'ready' });
  }
}
