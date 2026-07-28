import { describe, expect, it } from 'vitest';

import { emptySnapshot, fakeWasmEnums } from '../testkit.js';
import { LocalTransport, type EngineWorkerLike } from '../transport.js';
import { EngineHost, type EngineHostLike } from './engineHost.js';
import type { EngineWasm, WasmEngineHandle, WasmEvent } from './engineWasm.js';
import type {
  EventDescriptor,
  SnapshotDescriptor,
  WorkerMessage,
  WorkerRequest,
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
  deadLetters: [3n],
  retainedRecords: 0,
};

class ReadHost implements EngineHostLike {
  readonly snapshots: Uint8Array[] = [];
  readonly downloads: Uint8Array[] = [];
  respondSnapshot: () => Promise<SnapshotDescriptor> = () => Promise.resolve(SNAPSHOT);
  respondDownload: () => Promise<ArrayBuffer> = () =>
    Promise.resolve(new Uint8Array([9, 8, 7]).buffer);

  start(): Promise<void> {
    return Promise.resolve();
  }

  command(): Promise<void> {
    return Promise.resolve();
  }

  snapshot(folder: Uint8Array): Promise<SnapshotDescriptor> {
    this.snapshots.push(folder);
    return this.respondSnapshot();
  }

  download(node: Uint8Array): Promise<ArrayBuffer> {
    this.downloads.push(node);
    return this.respondDownload();
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
    await expect(transport.command({ kind: 'manualRefresh' }, [])).resolves.toBeUndefined();
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
      command: () => Promise.resolve(undefined),
      snapshot: () => Promise.reject(new Error('unused')),
      download: () => Promise.reject(new Error('unused')),
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
    serveEngine(scope, new EngineHost(wasm, {}));
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
        error: null,
      },
      { kind: 'snapshotUpdated' },
    ]);
    expect(toUi.some((entry) => entry.message.type === 'fatal')).toBe(false);
    // The transport is alive: a post-event command still round-trips.
    await expect(transport.command({ kind: 'manualRefresh' }, [])).resolves.toBeUndefined();
  });
});
