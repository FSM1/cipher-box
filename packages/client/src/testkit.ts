/**
 * Test doubles for the leadership/broadcast unit suite. Excluded from the build
 * (tsconfig.build.json). These model the *behaviors* the real browser APIs give
 * us — an origin-exclusive lock and a same-origin broadcast bus that never
 * echoes to the sender — so unit tests can drive election, relaying, and
 * failover deterministically. The real-API coverage lives in the browser suite.
 */

import type { BroadcastChannelLike } from './broadcast.js';
import type { LoginSecret } from './engineClient.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import type { LockManagerLike, LockRequestCallback } from './leadership.js';
import type { EngineEventListener, EngineTransport, EngineWorkerLike } from './transport.js';
import type { EngineHostLike } from './worker/engineHost.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  StreamHandle,
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
  PinMode: { Hosted: 0, External: 1, Dual: 2 },
  ByoKind: { Kubo: 0, Psa: 1, Pinata: 2 },
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
    ExternalPinFailed: 8,
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
    BaseSuperseded: 8,
    HeadTooLarge: 9,
  },
} as const;

/** A nonce inside the EIP-4361 class the engine enforces. */
export const FAKE_SIWE_NONCE = 'nonce123456789ab';

/** The account a test engine namespaces its durable stores under. */
export const TEST_ACCOUNT_ID = 'acct01';

/** What a `SecretSource` double re-derives for a failover promotion. */
export function fakeLoginSecret(bytes: number[] = [1]): LoginSecret {
  return { secret: Uint8Array.from(bytes).buffer, accountId: TEST_ACCOUNT_ID };
}

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
  start(_secret: ArrayBuffer, _accountId: string): Promise<void> {
    return notStubbed('start');
  }

  command(_command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
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

  openContentStream(_node: Uint8Array): Promise<StreamHandle> {
    return notStubbed('openContentStream');
  }

  readStream(_handle: StreamHandle, _offset: number, _length: number): Promise<ArrayBuffer> {
    return notStubbed('readStream');
  }

  closeStream(_handle: StreamHandle): Promise<void> {
    return notStubbed('closeStream');
  }

  nextEvent(): Promise<EventDescriptor | null> {
    return notStubbed('nextEvent');
  }
}

/**
 * A same-origin broadcast bus: a posted message reaches every *other* channel.
 * One bus is one origin, so it also carries that origin's lock manager.
 */
export class FakeBus {
  readonly locks = new FakeLockManager();
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
 * test can tell a transfer from a clone.
 */
export class FakeChannelPort implements MessagePortLike {
  peer: FakeChannelPort | null = null;
  readonly transferred: unknown[][] = [];
  /** Every message posted from this end, so a test can scan what the wire saw. */
  readonly posted: unknown[] = [];
  started = false;
  closed = false;
  private listeners: Array<(event: MessageEvent) => void> = [];

  postMessage(message: unknown, transfer?: Transferable[]): void {
    if (this.closed) return;
    this.posted.push(message);
    this.transferred.push(transfer ? [...transfer] : []);
    // Honors the transfer list, so a sender that reads a moved buffer afterwards
    // fails here exactly as it would against a real port.
    const delivered = structuredClone(message, transfer ? { transfer } : undefined);
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
  private readonly opened: FakeChannelPort[] = [];

  /** Every non-empty transfer list posted on this network's ports, in order. */
  get transfers(): unknown[][] {
    return this.opened.flatMap((port) => port.transferred.filter((list) => list.length > 0));
  }

  /** Every message posted on this network's ports, in order. */
  get messages(): unknown[] {
    return this.opened.flatMap((port) => port.posted);
  }

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
    this.opened.push(near, far);
    const handlers = this.inboxes.get(to);
    if (handlers) for (const handler of [...handlers]) handler(far);
    return near;
  }
}

/** One lock name's state: at most one holder, FIFO queue behind it. */
interface FakeLock {
  held: boolean;
  /** Settles the current holder's callback in failure (`fail`). */
  fail: ((error: Error) => void) | null;
  readonly queue: Array<() => void>;
}

/**
 * `navigator.locks` for the unit suite: one exclusive lock **per name**, FIFO
 * behind the holder, granted on a later turn like the real API — a tab's
 * presence lock and the engine election lock are separate names, and a queued
 * request is granted only when the holder lets go.
 */
export class FakeLockManager implements LockManagerLike {
  private readonly locks = new Map<string, FakeLock>();

  request(
    name: string,
    options: { signal?: AbortSignal; mode?: 'exclusive' },
    callback: LockRequestCallback
  ): Promise<unknown> {
    const lock = this.lock(name);
    return new Promise<unknown>((resolveRequest, rejectRequest) => {
      const signal = options.signal;
      const grant = (): void => {
        if (signal?.aborted) {
          rejectRequest(abortError());
          this.next(name);
          return;
        }
        lock.held = true;
        // Raced, not chained: a steal has to beat a holder that never settles.
        const stolen = new Promise<never>((_resolve, rejectHold) => {
          lock.fail = rejectHold;
        });
        void Promise.race([Promise.resolve(callback({ name })), stolen]).then(
          (value) => {
            lock.held = false;
            lock.fail = null;
            resolveRequest(value);
            this.next(name);
          },
          (error: unknown) => {
            lock.held = false;
            lock.fail = null;
            rejectRequest(error);
            this.next(name);
          }
        );
      };

      signal?.addEventListener('abort', () => {
        const index = lock.queue.indexOf(grant);
        if (index >= 0) {
          lock.queue.splice(index, 1);
          rejectRequest(abortError());
        }
      });
      lock.queue.push(grant);
      this.next(name);
    });
  }

  /** Settles this name's holder in failure, as a stolen lock does. */
  fail(name: string, error: Error): void {
    const lock = this.lock(name);
    // Silence here would let a fail-closed test assert a loss it never staged.
    if (!lock.fail) throw new Error(`no holder to fail for lock "${name}"`);
    lock.fail(error);
  }

  private lock(name: string): FakeLock {
    const existing = this.locks.get(name);
    if (existing) return existing;
    const created: FakeLock = { held: false, fail: null, queue: [] };
    this.locks.set(name, created);
    return created;
  }

  private next(name: string): void {
    const lock = this.lock(name);
    if (lock.held || lock.queue.length === 0) return;
    // A real grant never lands synchronously inside `request`.
    queueMicrotask(() => {
      if (lock.held) return;
      lock.queue.shift()?.();
    });
  }
}

export function abortError(): DOMException {
  return new DOMException('aborted', 'AbortError');
}

/** Renders bytes as one lowercase hex run, the form a leak scan searches. */
export function hex(bytes: Iterable<number>): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * Every byte and every string anywhere in a message, flattened so a leak scan
 * can search them: `bytesHex` catches payloads and node ids, `text` catches
 * names, routing keys and codes.
 */
export function collect(value: unknown): { bytesHex: string; text: string } {
  const found: number[] = [];
  const strings: string[] = [];
  const walk = (node: unknown): void => {
    if (node instanceof ArrayBuffer) for (const byte of new Uint8Array(node)) found.push(byte);
    else if (ArrayBuffer.isView(node)) {
      const view = new Uint8Array(node.buffer, node.byteOffset, node.byteLength);
      for (const byte of view) found.push(byte);
    } else if (typeof node === 'string') strings.push(node);
    // Counts and ids are values a scan has to see: a block count is a size proxy.
    else if (typeof node === 'number' || typeof node === 'bigint') strings.push(String(node));
    else if (Array.isArray(node)) for (const entry of node) walk(entry);
    // A container the scan cannot open is a blind spot that reads as clean, so
    // the keyed and set forms structured clone carries are opened too.
    else if (node instanceof Map)
      for (const [key, entry] of node) {
        walk(key);
        walk(entry);
      }
    else if (node instanceof Set) for (const entry of node) walk(entry);
    else if (node && typeof node === 'object') for (const entry of Object.values(node)) walk(entry);
  };
  walk(value);
  return { bytesHex: hex(found), text: strings.join(' ') };
}

/** A minimal in-process EngineTransport for relay/orchestrator tests. */
export class FakeEngineTransport implements EngineTransport {
  readonly commands: CommandDescriptor[] = [];
  readonly snapshots: Array<Uint8Array | null> = [];
  readonly downloads: Uint8Array[] = [];
  siweChallenges = 0;
  readonly opened: Uint8Array[] = [];
  readonly reads: Array<{ handle: StreamHandle; offset: number; length: number }> = [];
  readonly closedStreams: StreamHandle[] = [];
  readonly beginWrites: Array<{ target: WriteTarget; size: number }> = [];
  readonly chunks: Array<{ handle: WriteHandle; chunk: ArrayBuffer }> = [];
  readonly commits: WriteHandle[] = [];
  readonly aborts: WriteHandle[] = [];
  started: ArrayBuffer[] = [];
  closed = false;
  /** What `beginWrite` hands back and what `commitWrite` resolves with. */
  writeHandle: WriteHandle = 1n;
  /** What `openContentStream` hands back. */
  streamHandle: StreamHandle = 1n;
  commitOpId = 42n;
  respond: (command: CommandDescriptor) => Promise<CommandOutcomeDescriptor> = () =>
    Promise.resolve({ kind: 'done' });
  respondSnapshot: (folder: Uint8Array | null) => Promise<SnapshotDescriptor> = (folder) =>
    Promise.resolve(emptySnapshot(folder ?? undefined));
  respondDownload: (node: Uint8Array) => Promise<ArrayBuffer> = () =>
    Promise.resolve(new ArrayBuffer(0));
  respondSiweChallenge: () => Promise<string> = () => Promise.resolve(FAKE_SIWE_NONCE);
  respondReadStream: (
    handle: StreamHandle,
    offset: number,
    length: number
  ) => Promise<ArrayBuffer> = (_handle, _offset, length) =>
    Promise.resolve(new ArrayBuffer(length));
  private readonly listeners = new Set<EngineEventListener>();

  start(secret: ArrayBuffer): Promise<void> {
    this.started.push(secret);
    return Promise.resolve();
  }

  command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    this.commands.push(command);
    return this.respond(command);
  }

  beginWrite(target: WriteTarget, size: number): Promise<WriteHandle> {
    this.beginWrites.push({ target, size });
    return Promise.resolve(this.writeHandle);
  }

  pushChunk(handle: WriteHandle, chunk: ArrayBuffer): Promise<void> {
    // `LocalTransport` transfers the chunk into the worker; model that, so a
    // caller reading it afterwards fails here exactly as it would in a browser.
    this.chunks.push({ handle, chunk: structuredClone(chunk, { transfer: [chunk] }) });
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

  openContentStream(node: Uint8Array): Promise<StreamHandle> {
    this.opened.push(node);
    return Promise.resolve(this.streamHandle);
  }

  readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    this.reads.push({ handle, offset, length });
    return this.respondReadStream(handle, offset, length);
  }

  closeStream(handle: StreamHandle): Promise<void> {
    this.closedStreams.push(handle);
    return Promise.resolve();
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

  /** What the handle-minting requests answer with — every engine's counters start at 1. */
  streamHandle: StreamHandle = 1n;
  writeHandle: WriteHandle = 1n;

  postMessage(message: { id?: number; type?: string }, transfer: Transferable[] = []): void {
    // Honors the transfer list like a real worker, so a sender that keeps reading
    // a moved buffer fails here exactly as it would in a browser.
    this.posted.push(structuredClone(message, { transfer }));
    if (typeof message.id !== 'number') return;
    const id = message.id;
    const result = this.mint(message.type);
    queueMicrotask(() => this.emit({ type: 'response', id, ok: true, result }));
  }

  private mint(type: string | undefined): bigint | undefined {
    if (type === 'openContentStream') return this.streamHandle;
    if (type === 'beginWrite') return this.writeHandle;
    return undefined;
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
