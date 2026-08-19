import { describe, expect, it } from 'vitest';

import { emptySnapshot, FAKE_SIWE_NONCE, fakeWasmEnums, StubEngineHost } from '../testkit.js';
import { LocalTransport, type EngineWorkerLike } from '../transport.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm, WasmEngineHandle, WasmEvent } from './engineWasm.js';
import type {
  CommandDescriptor,
  CommandOutcomeDescriptor,
  EventDescriptor,
  SnapshotDescriptor,
  WorkerMessage,
  WorkerRequest,
  WriteTarget,
} from './protocol.js';
import { serveEngine, type WorkerScopeLike } from './serve.js';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

/** An in-memory scope↔worker pair wiring `serveEngine` to a `LocalTransport`. */
function loopback(): {
  scope: WorkerScopeLike;
  worker: EngineWorkerLike;
  toUi: Array<{ message: WorkerMessage; transfer?: Transferable[] }>;
} {
  const workerListeners: Array<(event: MessageEvent<WorkerRequest>) => void> = [];
  const uiListeners: Array<(event: MessageEvent<WorkerMessage>) => void> = [];
  const toUi: Array<{ message: WorkerMessage; transfer?: Transferable[] }> = [];

  const scope: WorkerScopeLike = {
    postMessage: (message, transfer) => {
      toUi.push({ message, transfer });
      queueMicrotask(() => {
        for (const listener of uiListeners)
          listener({ data: message } as MessageEvent<WorkerMessage>);
      });
    },
    addEventListener: (_type, listener) => workerListeners.push(listener),
  };
  const worker: EngineWorkerLike = {
    postMessage: (message) => {
      queueMicrotask(() => {
        for (const listener of workerListeners)
          listener({ data: message } as MessageEvent<WorkerRequest>);
      });
    },
    addEventListener: (type, listener) => {
      if (type === 'message')
        uiListeners.push(listener as (event: MessageEvent<WorkerMessage>) => void);
    },
    terminate: () => undefined,
  };
  return { scope, worker, toUi };
}

const SNAPSHOT: SnapshotDescriptor = {
  ...emptySnapshot(new Uint8Array(16).fill(2)),
  root: new Uint8Array(16).fill(1),
  deadLetters: [{ opId: 3n, reason: 'destinationGone' }],
  retainedRecords: 0,
};

class ReadHost extends StubEngineHost {
  readonly snapshots: Uint8Array[] = [];
  readonly downloads: Uint8Array[] = [];
  readonly opened: Uint8Array[] = [];
  readonly reads: Array<{ handle: bigint; offset: number; length: number }> = [];
  readonly closedStreams: bigint[] = [];
  readonly beginWrites: Array<{ target: WriteTarget; size: number }> = [];
  readonly chunks: Array<{ handle: bigint; bytes: number[] }> = [];
  readonly commits: bigint[] = [];
  readonly aborts: bigint[] = [];
  readonly commands: CommandDescriptor[] = [];
  respondSnapshot: () => Promise<SnapshotDescriptor> = () => Promise.resolve(SNAPSHOT);
  respondDownload: () => Promise<ArrayBuffer> = () =>
    Promise.resolve(new Uint8Array([9, 8, 7]).buffer);
  respondReadStream: () => Promise<ArrayBuffer> = () =>
    Promise.resolve(new Uint8Array([5, 4]).buffer);
  siweChallenges = 0;

  start(): Promise<void> {
    return Promise.resolve();
  }

  /** What the next `command` resolves with; a queued op answers with its id. */
  outcome: CommandOutcomeDescriptor = { kind: 'done' };

  command(command: CommandDescriptor): Promise<CommandOutcomeDescriptor> {
    this.commands.push(command);
    return Promise.resolve(this.outcome);
  }

  beginWrite(target: WriteTarget, size: number): Promise<bigint> {
    this.beginWrites.push({ target, size });
    return Promise.resolve(11n);
  }

  pushChunk(handle: bigint, chunk: ArrayBuffer): Promise<void> {
    this.chunks.push({ handle, bytes: [...new Uint8Array(chunk)] });
    return Promise.resolve();
  }

  commitWrite(handle: bigint): Promise<bigint> {
    this.commits.push(handle);
    return Promise.resolve(2048n);
  }

  abortWrite(handle: bigint): Promise<void> {
    this.aborts.push(handle);
    return Promise.resolve();
  }

  snapshot(folder: Uint8Array): Promise<SnapshotDescriptor> {
    this.snapshots.push(folder);
    return this.respondSnapshot();
  }

  siweChallenge(): Promise<string> {
    this.siweChallenges += 1;
    return Promise.resolve(FAKE_SIWE_NONCE);
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    this.downloads.push(node);
    return this.respondDownload();
  }

  openContentStream(node: Uint8Array): Promise<bigint> {
    this.opened.push(node);
    return Promise.resolve(11n);
  }

  readStream(handle: bigint, offset: number, length: number): Promise<ArrayBuffer> {
    this.reads.push({ handle, offset, length });
    return this.respondReadStream();
  }

  closeStream(handle: bigint): Promise<void> {
    this.closedStreams.push(handle);
    return Promise.resolve();
  }

  nextEvent(): Promise<EventDescriptor | null> {
    return new Promise<EventDescriptor | null>(() => undefined);
  }
}

describe('serveEngine read requests', () => {
  it('serves a snapshot read end to end over the transport', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const folder = new Uint8Array(16).fill(2);
    const view = await transport.snapshot(folder);
    expect(view).toEqual(SNAPSHOT);
    expect(host.snapshots).toEqual([folder]);
  });

  it('serves a download with the plaintext buffer in the transfer list', async () => {
    const { scope, worker, toUi } = loopback();
    serveEngine(scope, new ReadHost());
    const transport = new LocalTransport(worker);

    const content = await transport.download(new Uint8Array(16).fill(4));
    expect([...new Uint8Array(content)]).toEqual([9, 8, 7]);

    const response = toUi.find(
      (entry) => entry.message.type === 'response' && 'result' in entry.message
    );
    expect(response).toBeDefined();
    expect(response!.transfer).toEqual([content]);
  });

  it('serves a stream window with its args and the plaintext buffer transferred', async () => {
    const { scope, worker, toUi } = loopback();
    const host = new ReadHost();
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const node = new Uint8Array(16).fill(4);
    const handle = await transport.openContentStream(node);
    const content = await transport.readStream(handle, 1024, 2);
    await transport.closeStream(handle);

    expect([...new Uint8Array(content)]).toEqual([5, 4]);
    expect(host.opened).toEqual([node]);
    expect(host.reads).toEqual([{ handle, offset: 1024, length: 2 }]);
    expect(host.closedStreams).toEqual([handle]);

    const response = toUi.find(
      (entry) => entry.message.type === 'response' && (entry.transfer?.length ?? 0) > 0
    );
    expect(response).toBeDefined();
    expect(response!.transfer).toEqual([content]);
  });

  it('serves a SIWE challenge end to end over the transport', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    await expect(transport.siweChallenge()).resolves.toBe(FAKE_SIWE_NONCE);
    expect(host.siweChallenges).toBe(1);
  });

  it('maps a rejected read to a correlated error response with the stable code', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    // The wasm host rejects with an Error carrying the stable `code` property.
    host.respondSnapshot = () =>
      Promise.reject(Object.assign(new Error('unknown node'), { code: 'unknownNode' }));
    host.respondDownload = () =>
      Promise.reject(
        Object.assign(new Error('content unavailable: not published'), {
          code: 'contentUnavailable',
        })
      );
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    // The code crosses intact alongside the human-readable message.
    await expect(transport.snapshot(new Uint8Array(16))).rejects.toMatchObject({
      code: 'unknownNode',
      message: 'unknown node',
    });
    await expect(transport.download(new Uint8Array(16))).rejects.toMatchObject({
      code: 'contentUnavailable',
    });
    // The failures were per-request, never fatal: the next read still answers.
    await expect(transport.command({ kind: 'manualRefresh' }, [])).resolves.toEqual({
      kind: 'done',
    });
  });

  it('correlates concurrent command, snapshot, and download answered out of order', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    let releaseSnapshot!: () => void;
    host.respondSnapshot = () =>
      new Promise<SnapshotDescriptor>((resolve) => {
        releaseSnapshot = () => resolve(SNAPSHOT);
      });
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const settled: string[] = [];
    const snapshot = transport.snapshot(new Uint8Array(16)).then((view) => {
      settled.push('snapshot');
      return view;
    });
    const download = transport.download(new Uint8Array(16)).then((bytes) => {
      settled.push('download');
      return bytes;
    });
    const command = transport.command({ kind: 'manualRefresh' }, []).then(() => {
      settled.push('command');
    });

    // The download and command answer while the snapshot is still parked.
    await download;
    await command;
    expect(settled).toEqual(expect.arrayContaining(['download', 'command']));
    expect(settled).not.toContain('snapshot');

    releaseSnapshot();
    expect(await snapshot).toEqual(SNAPSHOT);
    expect([...new Uint8Array(await download)]).toEqual([9, 8, 7]);
  });
});

describe('serveEngine write requests', () => {
  it('routes every write step to the host and correlates its response', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const parent = new Uint8Array(16).fill(1);
    const handle = await transport.beginWrite({ parent, name: 'a.txt' }, 5);
    expect(handle).toBe(11n);
    expect(host.beginWrites).toEqual([{ target: { parent, name: 'a.txt' }, size: 5 }]);

    const chunk = new Uint8Array([1, 2, 3, 4, 5]).buffer;
    await expect(transport.pushChunk(handle, chunk)).resolves.toBeUndefined();
    expect(host.chunks).toEqual([{ handle: 11n, bytes: [1, 2, 3, 4, 5] }]);

    await expect(transport.commitWrite(handle)).resolves.toBe(2048n);
    expect(host.commits).toEqual([11n]);

    await expect(transport.abortWrite(11n)).resolves.toBeUndefined();
    expect(host.aborts).toEqual([11n]);
  });

  it('answers a version write and maps a rejected commit to its stable code', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    host.commitWrite = () =>
      Promise.reject(
        Object.assign(new Error('pushed 3 of 5 bytes'), { code: 'contentSizeMismatch' })
      );
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const node = new Uint8Array(16).fill(9);
    const handle = await transport.beginWrite({ node }, 5);
    expect(host.beginWrites).toEqual([{ target: { node }, size: 5 }]);

    await expect(transport.commitWrite(handle)).rejects.toMatchObject({
      code: 'contentSizeMismatch',
      message: 'pushed 3 of 5 bytes',
    });
    // Per-request, never fatal: the transport still serves the next call.
    await expect(transport.abortWrite(handle)).resolves.toBeUndefined();
  });

  it('applies pipelined chunks for one handle in arrival order', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    const applied: number[] = [];
    // Later chunks settle faster: unserialized they would overtake earlier ones,
    // scrambling the plaintext while every integrity check still passes.
    host.pushChunk = async (_handle, chunk) => {
      const seq = new Uint8Array(chunk)[0];
      await new Promise((resolve) => setTimeout(resolve, (4 - seq) * 5));
      applied.push(seq);
    };
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const handle = await transport.beginWrite({ node: new Uint8Array(16) }, 3);
    // Fired without awaiting, exactly as a UI pipelining an upload would.
    await Promise.all(
      [1, 2, 3].map((seq) => transport.pushChunk(handle, Uint8Array.of(seq).buffer))
    );

    expect(applied).toEqual([1, 2, 3]);
  });

  it('keeps distinct handles concurrent', async () => {
    const { scope, worker } = loopback();
    const host = new ReadHost();
    let releaseFirst!: () => void;
    host.pushChunk = (handle) =>
      handle === 11n ? new Promise<void>((resolve) => (releaseFirst = resolve)) : Promise.resolve();
    serveEngine(scope, host);
    const transport = new LocalTransport(worker);

    const parked = transport.pushChunk(11n, new ArrayBuffer(1));
    let parkedSettled = false;
    void parked.then(() => (parkedSettled = true));

    await expect(transport.pushChunk(12n, new ArrayBuffer(1))).resolves.toBeUndefined();
    expect(parkedSettled).toBe(false);

    releaseFirst();
    await parked;
  });
});

describe('serveEngine event pump over the real EngineHost', () => {
  it('streams renewalFailed and opProgress without turning the pump fatal', async () => {
    // The regression this guards: a renewalFailed engine event used to be an
    // unknown kind in `readEvent`, whose throw the pump escalated to `fatal`,
    // bricking the transport.
    const pumped: WasmEvent[] = [
      { kind: 'renewalFailed', routingKey: 'k51abc', detail: 'republish rejected' },
      {
        kind: 'opProgress',
        opId: 5n,
        node: new Uint8Array(16).fill(7),
        phase: 1,
        error: undefined,
      },
      { kind: 'snapshotUpdated' },
    ];
    const handle: WasmEngineHandle = {
      start: () => Promise.resolve(undefined),
      command: () => Promise.resolve({ kind: 'done', free: () => undefined }),
      beginWrite: () => Promise.resolve(1n),
      pushChunk: () => Promise.resolve(undefined),
      commitWrite: () => Promise.resolve(1n),
      abortWrite: () => Promise.resolve(undefined),
      snapshot: () => Promise.reject(new Error('unused')),
      siweChallenge: () => Promise.reject(new Error('unused')),
      download: () => Promise.reject(new Error('unused')),
      openContentStream: () => Promise.reject(new Error('unused')),
      readStream: () => Promise.reject(new Error('unused')),
      closeStream: () => Promise.reject(new Error('unused')),
      nextEvent: () =>
        pumped.length > 0
          ? Promise.resolve(pumped.shift())
          : new Promise<WasmEvent | undefined>(() => undefined),
    };
    const wasm = {
      EngineHandle: function EngineHandle() {
        return handle;
      },
      NodeId: { fromBytes: (bytes: Uint8Array) => ({ bytes }) },
      Command: { manualRefresh: () => ({}) },
      ...fakeWasmEnums,
    } as unknown as EngineWasm;

    const { scope, worker, toUi } = loopback();
    serveEngine(scope, new EngineHost(wasm, {}, { apiBaseUrl: 'https://api.example.test' }));
    const transport = new LocalTransport(worker);
    const received: EventDescriptor[] = [];
    transport.subscribe((event) => received.push(event));

    await tick();
    expect(received).toEqual([
      { kind: 'renewalFailed', routingKey: 'k51abc', detail: 'republish rejected' },
      {
        kind: 'opProgress',
        opId: 5n,
        node: new Uint8Array(16).fill(7),
        phase: 'downloadCompleted',
        blocksConfirmed: null,
        blocksTotal: null,
        error: null,
      },
      { kind: 'snapshotUpdated' },
    ]);
    expect(toUi.some((entry) => entry.message.type === 'fatal')).toBe(false);
    // The transport is alive: a post-event command still round-trips.
    await expect(transport.command({ kind: 'manualRefresh' }, [])).resolves.toEqual({
      kind: 'done',
    });
  });
});
