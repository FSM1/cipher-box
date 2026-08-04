import { afterEach, describe, expect, it } from 'vitest';

import { MediaBroker, type MediaBrokerOptions, type MediaReader } from './broker.js';
import { EngineRequestError } from '../correlatedTransport.js';
import type { StreamHandle } from '../worker/protocol.js';
import type { MediaRequest, MediaResponse } from './protocol.js';
import { StreamRegistry } from './registry.js';

const NODE = new Uint8Array([1, 2, 3, 4]);
const OTHER_NODE = new Uint8Array([5, 6, 7, 8]);
const WINDOW = 4;

/** Deterministic plaintext so a reassembled range can be compared byte for byte. */
const plaintext = (size: number): Uint8Array =>
  Uint8Array.from({ length: size }, (_, index) => (index * 7 + 3) % 251);

interface ReadCall {
  offset: number;
  length: number;
}

class FakeReader implements MediaReader {
  readonly calls: ReadCall[] = [];
  readonly opens: Uint8Array[] = [];
  readonly closes: StreamHandle[] = [];
  concurrent = 0;
  maxConcurrent = 0;
  /** Set to make reads reject. */
  failure: Error | null = null;
  /** Set below the registered size to model a version that shrank after the ticket was minted. */
  liveSize: number | null = null;
  /** The engine's open-stream ceiling; opening past it refuses like the real one. */
  ceiling = Number.POSITIVE_INFINITY;
  /** Fires inside `closeStream`, to land a broker call mid-reclaim. */
  onClose: (() => void) | null = null;
  private nextHandle = 1n;
  private readonly live = new Set<StreamHandle>();

  constructor(private readonly bytes: Uint8Array) {}

  /** Handles the engine still holds — a stranded one never reaches zero. */
  get liveCount(): number {
    return this.live.size;
  }

  async openContentStream(node: Uint8Array): Promise<StreamHandle> {
    this.opens.push(node);
    // A real open resolves, gates, and fetches the root manifest; it suspends.
    await flush();
    if (this.live.size >= this.ceiling) {
      throw new EngineRequestError('too many read streams are already open', 'tooManyStreams');
    }
    const handle = this.nextHandle++;
    this.live.add(handle);
    return handle;
  }

  async readStream(handle: StreamHandle, offset: number, length: number): Promise<ArrayBuffer> {
    if (!this.live.has(handle)) throw new Error('unknown stream handle');
    this.calls.push({ offset, length });
    this.concurrent += 1;
    this.maxConcurrent = Math.max(this.maxConcurrent, this.concurrent);
    try {
      // A real ranged read suspends; unserialized pulls would overlap here.
      await flush();
      if (this.failure) throw this.failure;
      const end = Math.min(offset + length, this.liveSize ?? this.bytes.length);
      return this.bytes.slice(offset, Math.max(offset, end)).buffer as ArrayBuffer;
    } finally {
      this.concurrent -= 1;
    }
  }

  closeStream(handle: StreamHandle): Promise<void> {
    this.closes.push(handle);
    this.live.delete(handle);
    const hook = this.onClose;
    this.onClose = null;
    hook?.();
    return Promise.resolve();
  }
}

const flush = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

async function waitFor(predicate: () => boolean, label: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await flush();
  }
  throw new Error(`timed out waiting for ${label}`);
}

interface Harness {
  reader: FakeReader;
  registry: StreamRegistry;
  broker: MediaBroker;
  send: (request: MediaRequest) => void;
  received: MediaResponse[];
  ticket: string;
  close: () => void;
}

const openHarnesses: Array<() => void> = [];

/** Zero linger by default, so a released pin evicts on the next flush. */
function harness(size: number, options: MediaBrokerOptions = {}): Harness {
  const reader = new FakeReader(plaintext(size));
  let minted = 0;
  const registry = new StreamRegistry('https://vault.example', () => `ticket-${++minted}`);
  registry.register({ node: NODE, size, mimeType: 'video/mp4' });
  const broker = new MediaBroker(registry, reader, {
    windowBytes: WINDOW,
    lingerMs: 0,
    ...options,
  });

  const channel = new MessageChannel();
  const received: MediaResponse[] = [];
  channel.port2.addEventListener('message', (event) => {
    received.push(event.data as MediaResponse);
  });
  channel.port2.start();
  broker.serve(channel.port1);

  const close = (): void => {
    broker.close();
    channel.port1.close();
    channel.port2.close();
  };
  openHarnesses.push(close);

  return {
    reader,
    registry,
    broker,
    received,
    ticket: 'ticket-1',
    send: (request) => channel.port2.postMessage(request),
    close,
  };
}

const bodyOf = (received: MediaResponse[]): Uint8Array => {
  const chunks = received.filter((message) => message.type === 'cb:media:chunk');
  const total = chunks.reduce((sum, message) => sum + message.chunk.byteLength, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const message of chunks) {
    out.set(new Uint8Array(message.chunk), at);
    at += message.chunk.byteLength;
  }
  return out;
};

const kinds = (received: MediaResponse[]): string[] => received.map((message) => message.type);

afterEach(() => {
  for (const close of openHarnesses.splice(0)) close();
});

describe('MediaBroker', () => {
  it('reassembles a 206 range from windowed reads', async () => {
    const size = 20;
    const h = harness(size);

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: 'bytes=3-12' });
    await waitFor(() => h.received.length === 1, 'head');
    for (let pull = 0; pull < 4; pull += 1) {
      h.send({ type: 'cb:media:pull', requestId: 1 });
      await waitFor(() => h.received.length === pull + 2, `chunk ${pull}`);
    }

    const head = h.received[0];
    expect(head).toMatchObject({ type: 'cb:media:head', status: 206 });
    expect(head.type === 'cb:media:head' ? head.headers : []).toContainEqual([
      'content-range',
      `bytes 3-12/${size}`,
    ]);
    expect(kinds(h.received)).toEqual([
      'cb:media:head',
      'cb:media:chunk',
      'cb:media:chunk',
      'cb:media:chunk',
      'cb:media:end',
    ]);
    expect(bodyOf(h.received)).toEqual(plaintext(size).slice(3, 13));
    // Window-aligned from the range start, and never wider than the window.
    expect(h.reader.calls).toEqual([
      { offset: 3, length: 4 },
      { offset: 7, length: 4 },
      { offset: 11, length: 2 },
    ]);
  });

  it('pins one engine stream for the whole body and releases it at the end', async () => {
    const size = 20;
    const h = harness(size);

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    await waitFor(() => h.received.length === 1, 'head');
    for (let pull = 0; pull < 6; pull += 1) {
      h.send({ type: 'cb:media:pull', requestId: 1 });
      await flush();
    }
    await waitFor(() => kinds(h.received).includes('cb:media:end'), 'end');
    await waitFor(() => h.reader.closes.length === 1, 'stream released');

    expect(bodyOf(h.received)).toEqual(plaintext(size));
    // One open however many windows the body took: no per-window resolve, and
    // no window that could come from a different content version.
    expect(h.reader.opens).toEqual([NODE]);
    expect(h.reader.calls).toHaveLength(5);
    expect(h.reader.closes).toEqual([1n]);
  });

  it('shares one engine stream across concurrent responses for a ticket', async () => {
    const h = harness(20);

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: 'bytes=0-3' });
    h.send({ type: 'cb:media:open', requestId: 2, ticket: h.ticket, range: 'bytes=8-11' });
    await waitFor(() => h.received.length === 2, 'heads');
    h.send({ type: 'cb:media:pull', requestId: 1 });
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(
      () => h.received.filter((message) => message.type === 'cb:media:chunk').length === 2,
      'both chunks'
    );

    // The second range pays no resolve and no root-manifest fetch of its own.
    expect(h.reader.opens).toEqual([NODE]);
    expect(h.reader.closes).toEqual([]);
  });

  it('holds the pin across a seek that closes its body before opening the next', async () => {
    const h = harness(20, { lingerMs: 10_000 });

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => h.received.length === 2, 'first chunk');
    h.send({ type: 'cb:media:close', requestId: 1 });
    await flush();

    h.send({ type: 'cb:media:open', requestId: 2, ticket: h.ticket, range: 'bytes=8-11' });
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(() => h.received.length === 4, 'seeked chunk');

    // One version for the whole playback, not one per Range request.
    expect(h.reader.opens).toEqual([NODE]);
    expect(h.reader.closes).toEqual([]);
    expect(h.reader.calls).toEqual([
      { offset: 0, length: 4 },
      { offset: 8, length: 4 },
    ]);
  });

  it('releases the pin once its last cursor drops and nothing re-opens it', async () => {
    const h = harness(20);

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => h.received.length === 2, 'first chunk');
    h.send({ type: 'cb:media:close', requestId: 1 });

    await waitFor(() => h.reader.closes.length === 1, 'stream released');
    expect(h.reader.closes).toEqual([1n]);
  });

  it('re-opens a ticket whose handle the engine forgot', async () => {
    const h = harness(20, { lingerMs: 10_000 });
    h.reader.failure = new EngineRequestError('unknown stream handle', 'unknownStreamHandle');

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => kinds(h.received).includes('cb:media:error'), 'error');

    h.reader.failure = null;
    h.send({ type: 'cb:media:open', requestId: 2, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(
      () => h.received.filter((message) => message.type === 'cb:media:chunk').length === 1,
      'chunk after recovery'
    );

    expect(h.reader.opens).toEqual([NODE, NODE]);
  });

  it('keeps the pinned version when one cursor of a ticket fails its read', async () => {
    const h = harness(20, { lingerMs: 10_000 });

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: 'bytes=0-3' });
    h.send({ type: 'cb:media:open', requestId: 2, ticket: h.ticket, range: 'bytes=8-11' });
    await waitFor(() => h.received.length === 2, 'heads');

    h.reader.failure = new Error('gateway unreachable');
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => kinds(h.received).includes('cb:media:error'), 'error');

    h.reader.failure = null;
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(
      () => h.received.filter((message) => message.type === 'cb:media:chunk').length === 1,
      'the other cursor still reads'
    );

    // Re-opening under the surviving body would tear its response across two
    // content versions.
    expect(h.reader.opens).toEqual([NODE]);
    expect(h.reader.closes).toEqual([]);
  });

  it('refuses to finish a body whose stream was replaced under it', async () => {
    const h = harness(20, { lingerMs: 10_000 });

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:open', requestId: 2, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(
      () => h.received.filter((message) => message.type === 'cb:media:chunk').length === 1,
      'the second body reads its first window'
    );

    // A leadership swap retires the handle; the cursor that notices re-opens
    // the ticket, which must not silently continue the body already in flight.
    h.reader.failure = new EngineRequestError('unknown stream handle', 'unknownStreamHandle');
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => kinds(h.received).includes('cb:media:error'), 'the first body errors');

    h.reader.failure = null;
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(
      () => h.received.filter((message) => message.type === 'cb:media:error').length === 2,
      'the second body errors rather than splicing two versions'
    );
    // The ticket re-opened, but no window of the new stream reached the body
    // that had already delivered one from the old.
    expect(h.reader.opens).toEqual([NODE, NODE]);
    expect(h.reader.calls).toEqual([
      { offset: 0, length: 4 },
      { offset: 0, length: 4 },
    ]);
  });

  it('ends every body of a revoked ticket and releases its stream', async () => {
    const h = harness(20, { lingerMs: 10_000 });

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => h.received.length === 2, 'first chunk');

    h.broker.revoke(h.ticket);
    await waitFor(() => h.reader.closes.length === 1, 'stream released');

    h.send({ type: 'cb:media:pull', requestId: 1 });
    await flush();
    expect(kinds(h.received)).toEqual(['cb:media:head', 'cb:media:chunk', 'cb:media:error']);
    expect(h.reader.calls).toHaveLength(1);
  });

  it('reclaims the streams only the linger holds when the engine refuses at its ceiling', async () => {
    const h = harness(20, { lingerMs: 10_000 });

    // A first playback leaves its stream pinned by the linger alone.
    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => h.received.length === 2, 'first chunk');
    h.send({ type: 'cb:media:close', requestId: 1 });
    await flush();

    h.registry.register({ node: OTHER_NODE, size: 20, mimeType: 'video/mp4' });
    h.reader.ceiling = 1;
    h.send({ type: 'cb:media:open', requestId: 2, ticket: 'ticket-2', range: null });
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(
      () => h.received.filter((message) => message.type === 'cb:media:chunk').length === 2,
      'chunk past the ceiling'
    );

    // The idle pin was given back and the refused open retried into its slot.
    expect(h.reader.closes).toEqual([1n]);
    expect(h.reader.opens).toEqual([NODE, OTHER_NODE, OTHER_NODE]);
  });

  it('strands no engine stream when its ticket is revoked during the reclaim', async () => {
    const h = harness(20, { lingerMs: 10_000 });

    h.send({ type: 'cb:media:open', requestId: 1, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 1 });
    await waitFor(() => h.received.length === 2, 'first chunk');
    h.send({ type: 'cb:media:close', requestId: 1 });
    await flush();

    h.registry.register({ node: OTHER_NODE, size: 20, mimeType: 'video/mp4' });
    h.reader.ceiling = 1;
    // The revoke lands between giving the idle stream back and retrying the open.
    h.reader.onClose = () => h.broker.revoke('ticket-2');
    h.send({ type: 'cb:media:open', requestId: 2, ticket: 'ticket-2', range: null });
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await waitFor(() => h.reader.closes.length === 1, 'the idle stream was reclaimed');
    await flush();

    // The retry was refused rather than opening onto a pin nothing can release.
    expect(h.reader.opens).toEqual([NODE, OTHER_NODE]);
    expect(h.reader.liveCount).toBe(0);
  });

  it('answers an unknown ticket with a 404 head and reads nothing', async () => {
    const h = harness(16);

    h.send({ type: 'cb:media:open', requestId: 5, ticket: 'not-a-ticket', range: null });
    await waitFor(() => h.received.length === 1, 'head');
    h.send({ type: 'cb:media:pull', requestId: 5 });
    await flush();

    expect(h.received).toEqual([{ type: 'cb:media:head', requestId: 5, status: 404, headers: [] }]);
    expect(h.reader.calls).toEqual([]);
  });

  it('answers an unsatisfiable range with a 416 head and opens no stream', async () => {
    const h = harness(16);

    h.send({ type: 'cb:media:open', requestId: 2, ticket: h.ticket, range: 'bytes=99-' });
    await waitFor(() => h.received.length === 1, 'head');
    h.send({ type: 'cb:media:pull', requestId: 2 });
    await flush();

    const head = h.received[0];
    expect(head).toMatchObject({ type: 'cb:media:head', status: 416 });
    expect(head.type === 'cb:media:head' ? head.headers : []).toContainEqual([
      'content-range',
      'bytes */16',
    ]);
    expect(h.received).toHaveLength(1);
    expect(h.reader.calls).toEqual([]);
  });

  it('ends a zero-length window without reading', async () => {
    const h = harness(0);

    h.send({ type: 'cb:media:open', requestId: 3, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 3 });
    await waitFor(() => h.received.length === 2, 'end');

    expect(kinds(h.received)).toEqual(['cb:media:head', 'cb:media:end']);
    expect(h.received[0]).toMatchObject({ type: 'cb:media:head', status: 200 });
    expect(h.reader.calls).toEqual([]);
  });

  it('stops reading once the stream is closed mid-body', async () => {
    const h = harness(20);

    h.send({ type: 'cb:media:open', requestId: 4, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 4 });
    await waitFor(() => h.received.length === 2, 'first chunk');

    h.send({ type: 'cb:media:close', requestId: 4 });
    await flush();
    h.send({ type: 'cb:media:pull', requestId: 4 });
    await flush();

    expect(h.reader.calls).toEqual([{ offset: 0, length: 4 }]);
    expect(kinds(h.received)).toEqual(['cb:media:head', 'cb:media:chunk']);
  });

  it('reports a read failure as cb:media:error and drops the stream', async () => {
    const h = harness(20);
    h.reader.failure = new Error('gateway unreachable');

    h.send({ type: 'cb:media:open', requestId: 6, ticket: h.ticket, range: null });
    h.send({ type: 'cb:media:pull', requestId: 6 });
    await waitFor(() => h.received.length === 2, 'error');
    h.send({ type: 'cb:media:pull', requestId: 6 });
    await flush();

    expect(h.received[1]).toEqual({
      type: 'cb:media:error',
      requestId: 6,
      message: 'gateway unreachable',
    });
    expect(h.reader.calls).toHaveLength(1);
  });

  it('serializes back-to-back pulls into sequential non-overlapping reads', async () => {
    const h = harness(20);

    h.send({ type: 'cb:media:open', requestId: 7, ticket: h.ticket, range: null });
    await waitFor(() => h.received.length === 1, 'head');
    h.send({ type: 'cb:media:pull', requestId: 7 });
    h.send({ type: 'cb:media:pull', requestId: 7 });
    await waitFor(() => h.received.length === 3, 'two chunks');

    expect(h.reader.maxConcurrent).toBe(1);
    expect(h.reader.calls).toEqual([
      { offset: 0, length: 4 },
      { offset: 4, length: 4 },
    ]);
    expect(bodyOf(h.received)).toEqual(plaintext(20).slice(0, 8));
  });

  it('ends cleanly when a read comes back short of the window it asked for', async () => {
    const h = harness(20);
    // The head promised 20 bytes; the live version only has 6.
    h.reader.liveSize = 6;

    h.send({ type: 'cb:media:open', requestId: 9, ticket: h.ticket, range: null });
    await waitFor(() => h.received.length === 1, 'head');
    for (let pull = 0; pull < 3; pull += 1) {
      h.send({ type: 'cb:media:pull', requestId: 9 });
      await flush();
    }
    await waitFor(() => h.received.length === 4, 'end');

    expect(kinds(h.received)).toEqual([
      'cb:media:head',
      'cb:media:chunk',
      'cb:media:chunk',
      'cb:media:end',
    ]);
    expect(bodyOf(h.received)).toEqual(plaintext(20).slice(0, 6));
    // Advanced by what arrived, and stopped there instead of re-reading past it.
    expect(h.reader.calls).toEqual([
      { offset: 0, length: 4 },
      { offset: 4, length: 4 },
    ]);
  });

  it('ignores an unknown requestId and a malformed message', async () => {
    const h = harness(20);

    h.send({ type: 'cb:media:pull', requestId: 99 });
    h.send({ type: 'cb:media:close', requestId: 99 });
    h.send({ type: 'cb:media:open', requestId: 1, ticket: 42 } as unknown as MediaRequest);
    h.send('nonsense' as unknown as MediaRequest);
    await flush();

    expect(h.received).toEqual([]);
    expect(h.reader.calls).toEqual([]);
  });

  it('drops open streams when a new port supersedes the old one', async () => {
    const h = harness(20);

    h.send({ type: 'cb:media:open', requestId: 8, ticket: h.ticket, range: null });
    await waitFor(() => h.received.length === 1, 'head');

    const next = new MessageChannel();
    const later: MediaResponse[] = [];
    next.port2.addEventListener('message', (event) => later.push(event.data as MediaResponse));
    next.port2.start();
    h.broker.serve(next.port1);

    h.send({ type: 'cb:media:pull', requestId: 8 });
    next.port2.postMessage({ type: 'cb:media:pull', requestId: 8 });
    await flush();

    expect(h.received).toHaveLength(1);
    expect(later).toEqual([]);
    expect(h.reader.calls).toEqual([]);
    next.port1.close();
    next.port2.close();
  });
});
