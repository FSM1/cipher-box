import { describe, expect, it } from 'vitest';

import { emptySnapshot } from './testkit.js';
import { LocalTransport, type EngineWorkerLike } from './transport.js';
import type {
  EventDescriptor,
  SnapshotDescriptor,
  WorkerMessage,
  WorkerRequest,
} from './worker/protocol.js';

/** A worker stand-in: records posted requests, replays worker→UI messages. */
class FakeWorker implements EngineWorkerLike {
  posted: Array<{ message: WorkerRequest; transfer: Transferable[] }> = [];
  terminated = false;
  private messageListeners: Array<(event: MessageEvent<WorkerMessage>) => void> = [];
  private errorListeners: Array<(event: ErrorEvent) => void> = [];

  postMessage(message: WorkerRequest, transfer: Transferable[]): void {
    this.posted.push({ message, transfer });
  }

  addEventListener(type: 'message' | 'error', listener: unknown): void {
    if (type === 'message')
      this.messageListeners.push(listener as (e: MessageEvent<WorkerMessage>) => void);
    else this.errorListeners.push(listener as (e: ErrorEvent) => void);
  }

  terminate(): void {
    this.terminated = true;
  }

  emit(message: WorkerMessage): void {
    for (const listener of this.messageListeners)
      listener({ data: message } as MessageEvent<WorkerMessage>);
  }

  emitError(message: string): void {
    for (const listener of this.errorListeners) listener({ message } as ErrorEvent);
  }
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

describe('LocalTransport', () => {
  it('correlates a response to its request by id (round-trip)', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const pending = transport.command({ kind: 'manualRefresh' }, []);
    await tick();

    expect(worker.posted).toHaveLength(1);
    const { message } = worker.posted[0];
    expect(message.type).toBe('command');
    worker.emit({ type: 'response', id: message.id, ok: true });

    await expect(pending).resolves.toBeUndefined();
  });

  it('is out-of-order safe: later-issued request answered first still correlates', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const resolved: string[] = [];
    const first = transport
      .command({ kind: 'manualRefresh' }, [])
      .then(() => resolved.push('first'));
    const second = transport
      .command({ kind: 'delete', node: new Uint8Array(16) }, [])
      .then(() => resolved.push('second'));
    await tick();

    const [a, b] = worker.posted.map((entry) => entry.message.id);
    expect(a).not.toBe(b);
    // Answer the second request first, then the first.
    worker.emit({ type: 'response', id: b, ok: true });
    worker.emit({ type: 'response', id: a, ok: true });

    await Promise.all([first, second]);
    expect(resolved).toEqual(['second', 'first']);
  });

  it('rejects only the matching request on an error response', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const failing = transport.command({ kind: 'manualRefresh' }, []);
    const ok = transport.command({ kind: 'manualRefresh' }, []);
    await tick();
    const [idA, idB] = worker.posted.map((entry) => entry.message.id);

    worker.emit({
      type: 'response',
      id: idA,
      ok: false,
      error: 'command not implemented yet: manualRefresh',
      code: 'unimplemented',
    });
    worker.emit({ type: 'response', id: idB, ok: true });

    // The stable code crosses alongside the human-readable message.
    await expect(failing).rejects.toMatchObject({
      code: 'unimplemented',
      message: 'command not implemented yet: manualRefresh',
    });
    await expect(ok).resolves.toBeUndefined();
  });

  it('delivers events to subscribers in order, with no drops', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const received: EventDescriptor[] = [];
    transport.subscribe((event) => received.push(event));

    const sent: EventDescriptor[] = [
      { kind: 'snapshotUpdated' },
      { kind: 'stalenessChanged', staleness: 'stale' },
      { kind: 'deadLetter', opId: 7n },
      { kind: 'snapshotUpdated' },
    ];
    for (const event of sent) worker.emit({ type: 'event', event });

    expect(received).toEqual(sent);
  });

  it('resolves a snapshot request with its result payload', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const folder = new Uint8Array(16).fill(5);
    const pending = transport.snapshot(folder);
    await tick();

    const { message } = worker.posted[0];
    expect(message).toMatchObject({ type: 'snapshot', folder });
    const result: SnapshotDescriptor = {
      ...emptySnapshot(folder),
      deadLetters: [1n],
      staleness: 'stale',
    };
    worker.emit({ type: 'response', id: message.id, ok: true, result });

    await expect(pending).resolves.toEqual(result);
  });

  it('correlates interleaved command, snapshot, and download answered out of order', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const snapshotResult = emptySnapshot();
    const downloadResult = new Uint8Array([4, 5, 6]).buffer;

    const command = transport.command({ kind: 'manualRefresh' }, []);
    const snapshot = transport.snapshot(new Uint8Array(16));
    const download = transport.download(new Uint8Array(16));
    await tick();

    const [commandId, snapshotId, downloadId] = worker.posted.map((entry) => entry.message.id);
    // Answer in reverse issue order; each promise must get its own value.
    worker.emit({ type: 'response', id: downloadId, ok: true, result: downloadResult });
    worker.emit({ type: 'response', id: snapshotId, ok: true, result: snapshotResult });
    worker.emit({ type: 'response', id: commandId, ok: true });

    await expect(command).resolves.toBeUndefined();
    await expect(snapshot).resolves.toEqual(snapshotResult);
    expect([...new Uint8Array(await download)]).toEqual([4, 5, 6]);
  });

  it('rejects only the matching read on an error response', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const failing = transport.download(new Uint8Array(16));
    const ok = transport.snapshot(new Uint8Array(16));
    await tick();
    const [idA, idB] = worker.posted.map((entry) => entry.message.id);

    worker.emit({
      type: 'response',
      id: idA,
      ok: false,
      error: 'content unavailable: pending',
      code: 'contentUnavailable',
    });
    worker.emit({ type: 'response', id: idB, ok: true, result: emptySnapshot() });

    await expect(failing).rejects.toMatchObject({ code: 'contentUnavailable' });
    await expect(ok).resolves.toMatchObject({ staleness: 'fresh' });
  });

  it('delivers renewalFailed and opProgress events to subscribers', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const received: EventDescriptor[] = [];
    transport.subscribe((event) => received.push(event));

    const sent: EventDescriptor[] = [
      { kind: 'renewalFailed', routingKey: 'k51abc', detail: 'republish rejected' },
      {
        kind: 'opProgress',
        opId: null,
        node: new Uint8Array(16),
        phase: 'downloadStarted',
        error: null,
      },
    ];
    for (const event of sent) worker.emit({ type: 'event', event });

    expect(received).toEqual(sent);
  });

  it('transfers the secret buffer on start', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const secret = new Uint8Array([1, 2, 3, 4]).buffer;
    void transport.start(secret);
    await tick();

    const posted = worker.posted[0];
    expect(posted.message.type).toBe('start');
    expect(posted.transfer).toEqual([secret]);
  });

  it('latches terminal failure on fatal: in-flight and later requests both reject, not hang', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const inFlight = transport.command({ kind: 'manualRefresh' }, []);
    await tick();
    worker.emit({ type: 'fatal', error: 'engine construction failed' });

    // The request outstanding at fatal time rejects.
    await expect(inFlight).rejects.toThrow('engine construction failed');

    // A request issued after fatal rejects promptly rather than posting to the
    // dead worker and waiting forever for a response.
    const postFatal = transport.command({ kind: 'manualRefresh' }, []);
    await expect(postFatal).rejects.toThrow('engine construction failed');
  });

  it('keeps fanning out an event after a subscriber throws', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const received: string[] = [];
    transport.subscribe(() => received.push('first'));
    transport.subscribe(() => {
      throw new Error('subscriber boom');
    });
    transport.subscribe(() => received.push('third'));

    worker.emit({ type: 'event', event: { kind: 'snapshotUpdated' } });

    expect(received).toEqual(['first', 'third']);
  });

  it('does not strand a pending entry when postMessage throws synchronously', async () => {
    const worker = new FakeWorker();
    worker.postMessage = () => {
      throw new DOMException('detached ArrayBuffer', 'DataCloneError');
    };
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const failing = transport.command({ kind: 'manualRefresh' }, []);

    await expect(failing).rejects.toThrow('detached ArrayBuffer');
    // A later post succeeds and correlates, proving no id/pending was stranded.
    worker.postMessage = FakeWorker.prototype.postMessage;
    const ok = transport.command({ kind: 'manualRefresh' }, []);
    await tick();
    const posted = worker.posted.at(-1);
    expect(posted).toBeDefined();
    worker.emit({ type: 'response', id: posted!.message.id, ok: true });
    await expect(ok).resolves.toBeUndefined();
  });

  it('rejects pending requests when the worker errors', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const pending = transport.command({ kind: 'manualRefresh' }, []);
    await tick();
    worker.emitError('worker crashed');

    await expect(pending).rejects.toThrow('worker crashed');
  });

  it('rejects pending requests and terminates the worker on close', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: false });

    const pending = transport.command({ kind: 'manualRefresh' }, []);
    await tick();
    transport.close();

    await expect(pending).rejects.toThrow('closed');
    expect(worker.terminated).toBe(true);
  });

  it('surfaces the storage-persistence grant the worker reports at startup', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    worker.emit({ type: 'ready', storagePersisted: true });

    await expect(transport.storagePersisted).resolves.toBe(true);
  });

  it('reports storage as not persisted when the worker never reaches ready', async () => {
    const worker = new FakeWorker();
    const transport = new LocalTransport(worker);
    transport.close();

    await expect(transport.storagePersisted).resolves.toBe(false);
  });
});
