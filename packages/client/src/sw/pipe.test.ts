import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  MediaPortRequest,
  MediaRequest,
  MediaResponse,
  MessagePortLike,
} from '../media/protocol.js';
import { MediaPipe, type ClientsLike, type MediaPipeScopeLike } from './pipe.js';

const ORIGIN = 'https://vault.example';
const TIMEOUTS = { brokerTimeoutMs: 1000, responseTimeoutMs: 100, pullTimeoutMs: 2000 };

type Reply = (message: MediaRequest, port: FakePort) => void;

class FakePort implements MessagePortLike {
  readonly sent: MediaRequest[] = [];
  closed = false;
  started = false;
  private listeners: Array<(event: MessageEvent) => void> = [];

  constructor(private readonly reply?: Reply) {}

  postMessage(message: unknown): void {
    this.sent.push(message as MediaRequest);
    this.reply?.(message as MediaRequest, this);
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

  deliver(response: MediaResponse): void {
    this.deliverRaw(response);
  }

  /** Delivers whatever a version-skewed or hostile port might post. */
  deliverRaw(data: unknown): void {
    for (const listener of [...this.listeners]) {
      listener({ data } as unknown as MessageEvent);
    }
  }

  countOf(type: MediaRequest['type']): number {
    return this.sent.filter((message) => message.type === type).length;
  }
}

class FakeScope implements MediaPipeScopeLike {
  readonly brokered: MediaPortRequest[] = [];
  readonly location = { origin: ORIGIN };
  readonly clients: ClientsLike = {
    matchAll: async () => [
      { postMessage: (message: MediaPortRequest): void => void this.brokered.push(message) },
      { postMessage: (message: MediaPortRequest): void => void this.brokered.push(message) },
    ],
  };
}

const bufferOf = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

/** A port that answers `open` with a 206 head and drains `chunks` on pull. */
function streamingPort(chunks: Uint8Array[]): FakePort {
  const queue = [...chunks];
  return new FakePort((message, port) => {
    if (message.type === 'cb:media:open') {
      port.deliver({
        type: 'cb:media:head',
        requestId: message.requestId,
        ok: true,
        status: 206,
        headers: [['content-type', 'video/mp4']],
      });
      return;
    }
    if (message.type !== 'cb:media:pull') return;
    const next = queue.shift();
    port.deliver(
      next
        ? { type: 'cb:media:chunk', requestId: message.requestId, chunk: bufferOf(next) }
        : { type: 'cb:media:end', requestId: message.requestId }
    );
  });
}

/** A port that answers `open` with a 200 head and then swallows every pull. */
function stalledPort(): FakePort {
  return new FakePort((message, port) => {
    if (message.type !== 'cb:media:open') return;
    port.deliver({
      type: 'cb:media:head',
      requestId: message.requestId,
      ok: true,
      status: 200,
      headers: [],
    });
  });
}

const streamRequest = (ticket = 'tkt', range: string | null = 'bytes=0-4'): Request =>
  new Request(`${ORIGIN}/stream/${ticket}`, {
    headers: range === null ? undefined : { range },
  });

afterEach(() => {
  vi.useRealTimers();
});

describe('MediaPipe.handles', () => {
  it('claims only same-origin stream paths', () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);

    expect(pipe.handles(new URL(`${ORIGIN}/stream/tkt`))).toBe(true);
    expect(pipe.handles(new URL(`${ORIGIN}/files/tkt`))).toBe(false);
    expect(pipe.handles(new URL(`${ORIGIN}/`))).toBe(false);
    expect(pipe.handles(new URL('https://evil.example/stream/tkt'))).toBe(false);
  });
});

describe('MediaPipe.respond', () => {
  it('streams every chunk of a 206 through in order', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])]);
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest());

    expect(response.status).toBe(206);
    expect(response.headers.get('content-type')).toBe('video/mp4');
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    const open = port.sent.find((message) => message.type === 'cb:media:open');
    expect(open).toMatchObject({ ticket: 'tkt', range: 'bytes=0-4' });
  });

  it('forwards an absent Range header as null', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([]);
    pipe.adoptPort(port);

    await pipe.respond(streamRequest('tkt', null));

    expect(port.sent[0]).toMatchObject({ type: 'cb:media:open', range: null });
  });

  it('pulls one window at a time, on demand', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest());
    expect(port.countOf('cb:media:pull')).toBe(0);

    const reader = response.body?.getReader();
    await reader?.read();
    await Promise.resolve();
    expect(port.countOf('cb:media:pull')).toBe(1);

    await reader?.read();
    await Promise.resolve();
    expect(port.countOf('cb:media:pull')).toBe(2);
  });

  it('posts close when the response body is cancelled', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1])]);
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest());
    await response.body?.cancel();

    expect(port.sent.some((message) => message.type === 'cb:media:close')).toBe(true);
  });

  it('errors the response body when the port reports a read failure', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = new FakePort((message, self) => {
      if (message.type === 'cb:media:open') {
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
          ok: true,
          status: 200,
          headers: [],
        });
        return;
      }
      if (message.type === 'cb:media:pull') {
        self.deliver({ type: 'cb:media:error', requestId: message.requestId, message: 'boom' });
      }
    });
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest());
    const reader = response.body?.getReader();

    await expect(reader?.read()).rejects.toThrow('boom');
  });

  it('turns a not-ok head into a bodiless response and never pulls', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = new FakePort((message, self) => {
      if (message.type !== 'cb:media:open') return;
      self.deliver({
        type: 'cb:media:head',
        requestId: message.requestId,
        ok: false,
        status: 404,
        headers: [],
      });
    });
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest('unknown'));

    expect(response.status).toBe(404);
    expect(response.body).toBeNull();
    expect(port.countOf('cb:media:pull')).toBe(0);
  });

  it('answers 405 for a non-GET and never opens a stream for it', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1])]);
    pipe.adoptPort(port);

    for (const method of ['POST', 'HEAD']) {
      const response = await pipe.respond(new Request(`${ORIGIN}/stream/tkt`, { method }));
      expect(response.status).toBe(405);
      expect(response.body).toBeNull();
    }

    expect(port.sent).toEqual([]);
    // The prefix stays the pipe's, so a non-GET never falls through to the network.
    expect(pipe.handles(new URL(`${ORIGIN}/stream/tkt`))).toBe(true);
  });

  it('errors the body and discards the port when a pull outlives its own timeout', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    // The tab died mid-stream: the head arrived, no pull ever will.
    const stalled = stalledPort();
    pipe.adoptPort(stalled);

    const response = await pipe.respond(streamRequest());
    const drained = response.arrayBuffer().catch((error: unknown) => (error as Error).message);

    // A pull outlives the `open` budget by design; only its own knob fires it.
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs);
    expect(stalled.closed).toBe(false);
    await vi.advanceTimersByTimeAsync(TIMEOUTS.pullTimeoutMs);

    expect(await drained).toBe('media pull timed out');
    expect(stalled.closed).toBe(true);
  });

  it('answers 404 for a stream path carrying no ticket', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([]);
    pipe.adoptPort(port);

    const response = await pipe.respond(new Request(`${ORIGIN}/stream/`));

    expect(response.status).toBe(404);
    expect(port.sent).toEqual([]);
  });

  it('re-brokers a fresh port and retries the open when a port goes silent', async () => {
    vi.useFakeTimers();
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);
    const dead = new FakePort();
    pipe.adoptPort(dead);

    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs);

    expect(dead.closed).toBe(true);
    expect(scope.brokered).toEqual([{ type: 'cb:media:needPort' }, { type: 'cb:media:needPort' }]);

    const live = streamingPort([new Uint8Array([7, 8])]);
    pipe.adoptPort(live);
    const response = await pending;
    vi.useRealTimers();

    expect(response.status).toBe(206);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([7, 8]));
    expect(live.countOf('cb:media:open')).toBe(1);
  });

  it('gives up with 503 when the re-brokered port is silent too', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(new FakePort());

    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs);
    const second = new FakePort();
    pipe.adoptPort(second);
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs);

    const response = await pending;
    expect(response.status).toBe(503);
    expect(second.countOf('cb:media:open')).toBe(1);
  });

  it('answers 503 when no tab offers a port within the broker timeout', async () => {
    vi.useFakeTimers();
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);

    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(TIMEOUTS.brokerTimeoutMs);

    const response = await pending;
    expect(response.status).toBe(503);
    expect(scope.brokered).toHaveLength(2);
  });
});

describe('MediaPipe.adoptPort', () => {
  it('closes the port it replaces and starts the new one', () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const first = new FakePort();
    const second = new FakePort();

    pipe.adoptPort(first);
    pipe.adoptPort(second);

    expect(first.closed).toBe(true);
    expect(second.closed).toBe(false);
    expect(second.started).toBe(true);
  });

  it('fails a body still pulling on a port that gets replaced', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    // The stream is live but stuck: the head arrived, the pull is unanswered.
    const stalled = stalledPort();
    pipe.adoptPort(stalled);

    const response = await pipe.respond(streamRequest());
    const drained = response.arrayBuffer();
    await Promise.resolve();
    pipe.adoptPort(new FakePort());

    await expect(drained).rejects.toThrow(/media port replaced/);
  });

  it('ignores a response for an unknown request id', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([9])]);
    pipe.adoptPort(port);

    expect(() => port.deliver({ type: 'cb:media:end', requestId: 4242 })).not.toThrow();

    const response = await pipe.respond(streamRequest());
    expect(response.status).toBe(206);
  });
});

describe('MediaPipe client routing', () => {
  it('serves each client from its own port', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const a = streamingPort([new Uint8Array([1, 1])]);
    const b = streamingPort([new Uint8Array([2, 2])]);
    pipe.adoptPort(a, 'client-a');
    pipe.adoptPort(b, 'client-b');

    const fromA = await pipe.respond(streamRequest('ticket-a'), 'client-a');
    const fromB = await pipe.respond(streamRequest('ticket-b'), 'client-b');

    expect(new Uint8Array(await fromA.arrayBuffer())).toEqual(new Uint8Array([1, 1]));
    expect(new Uint8Array(await fromB.arrayBuffer())).toEqual(new Uint8Array([2, 2]));
    // A ticket only ever reaches the registry that minted it.
    expect(a.sent.filter((message) => message.type === 'cb:media:open')).toMatchObject([
      { ticket: 'ticket-a' },
    ]);
    expect(b.sent.filter((message) => message.type === 'cb:media:open')).toMatchObject([
      { ticket: 'ticket-b' },
    ]);
  });

  it('falls back to the newest port for a client it holds none for', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const a = streamingPort([new Uint8Array([1])]);
    const b = streamingPort([new Uint8Array([2])]);
    pipe.adoptPort(a, 'client-a');
    pipe.adoptPort(b, 'client-b');

    const response = await pipe.respond(streamRequest(), 'client-never-seen');

    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([2]));
    expect(a.countOf('cb:media:open')).toBe(0);
  });

  it('closes only the port of the client being replaced', () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const a = streamingPort([]);
    const b = streamingPort([]);
    pipe.adoptPort(a, 'client-a');
    pipe.adoptPort(b, 'client-b');

    pipe.adoptPort(streamingPort([]), 'client-a');

    expect(a.closed).toBe(true);
    expect(b.closed).toBe(false);
  });

  it('fails the replaced client body while another client keeps streaming', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const stalled = stalledPort();
    const live = streamingPort([new Uint8Array([5])]);
    pipe.adoptPort(stalled, 'client-a');
    pipe.adoptPort(live, 'client-b');

    const stuck = await pipe.respond(streamRequest(), 'client-a');
    const drained = stuck.arrayBuffer();
    await Promise.resolve();
    pipe.adoptPort(new FakePort(), 'client-a');

    await expect(drained).rejects.toThrow(/media port replaced/);
    const response = await pipe.respond(streamRequest(), 'client-b');
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([5]));
  });

  it('drops a discarded client port instead of retrying it', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const live = streamingPort([new Uint8Array([3])]);
    const dead = new FakePort();
    pipe.adoptPort(live, 'client-live');
    pipe.adoptPort(dead, 'client-dead');

    const pending = pipe.respond(streamRequest(), 'client-dead');
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs);
    const response = await pending;
    vi.useRealTimers();

    expect(dead.closed).toBe(true);
    expect(dead.countOf('cb:media:open')).toBe(1);
    // The dead client's entry is gone, so the retry falls back to a live port.
    expect(response.status).toBe(206);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([3]));
  });
});

describe('MediaPipe port-message validation', () => {
  const headPort = (head: (requestId: number) => unknown): FakePort =>
    new FakePort((message, port) => {
      if (message.type !== 'cb:media:open') return;
      port.deliverRaw(head(message.requestId));
    });

  it.each([
    { case: 'a status outside the HTTP range', ok: true, status: 999, headers: [] },
    { case: 'a status that is not an integer', ok: true, status: 200.5, headers: [] },
    { case: 'headers that are not string pairs', ok: true, status: 200, headers: 'video/mp4' },
    { case: 'headers holding a malformed pair', ok: true, status: 200, headers: [['only']] },
    { case: 'an ok flag that is not a boolean', ok: 'yes', status: 200, headers: [] },
  ])('never builds a response from a head with $case', async (head) => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(
      headPort((requestId) => ({
        type: 'cb:media:head',
        requestId,
        ok: head.ok,
        status: head.status,
        headers: head.headers,
      }))
    );

    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(
      TIMEOUTS.responseTimeoutMs * 2 + TIMEOUTS.brokerTimeoutMs + 1
    );

    await expect(pending).resolves.toMatchObject({ status: 503 });
  });

  it('drops a chunk whose payload is not an ArrayBuffer', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = new FakePort((message, self) => {
      if (message.type === 'cb:media:open') {
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
          ok: true,
          status: 200,
          headers: [],
        });
        return;
      }
      if (message.type !== 'cb:media:pull') return;
      self.deliverRaw({ type: 'cb:media:chunk', requestId: message.requestId, chunk: 64 });
      self.deliver({
        type: 'cb:media:chunk',
        requestId: message.requestId,
        chunk: bufferOf(new Uint8Array([9])),
      });
    });
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest());
    const first = await response.body?.getReader().read();

    // A number would have become that many zero bytes of fabricated plaintext.
    expect(first?.value).toEqual(new Uint8Array([9]));
  });

  it('drops an error whose message is not a string', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = new FakePort((message, self) => {
      if (message.type === 'cb:media:open') {
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
          ok: true,
          status: 200,
          headers: [],
        });
        return;
      }
      if (message.type !== 'cb:media:pull') return;
      self.deliverRaw({ type: 'cb:media:error', requestId: message.requestId, message: { a: 1 } });
      self.deliver({ type: 'cb:media:end', requestId: message.requestId });
    });
    pipe.adoptPort(port);

    const response = await pipe.respond(streamRequest());

    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array());
  });
});

describe('MediaPipe cache policy', () => {
  it('marks every status it synthesizes no-store', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(new FakePort());

    const rejected = await pipe.respond(new Request(`${ORIGIN}/stream/tkt`, { method: 'POST' }));
    const ticketless = await pipe.respond(new Request(`${ORIGIN}/stream/`));
    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(
      TIMEOUTS.responseTimeoutMs * 2 + TIMEOUTS.brokerTimeoutMs + 1
    );
    const unavailable = await pending;

    expect([rejected.status, ticketless.status, unavailable.status]).toEqual([405, 404, 503]);
    for (const response of [rejected, ticketless, unavailable]) {
      expect(response.headers.get('cache-control')).toBe('no-store');
    }
  });

  it('marks a forwarded head no-store even when the tab omitted it', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(streamingPort([]));

    const streamed = await pipe.respond(streamRequest());

    expect(streamed.headers.get('cache-control')).toBe('no-store');
    expect(streamed.headers.get('content-type')).toBe('video/mp4');
  });

  it('marks a not-ok head no-store', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(
      new FakePort((message, self) => {
        if (message.type !== 'cb:media:open') return;
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
          ok: false,
          status: 404,
          headers: [],
        });
      })
    );

    const response = await pipe.respond(streamRequest('unknown'));

    expect(response.status).toBe(404);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });
});
