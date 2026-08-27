import { afterEach, describe, expect, it, vi } from 'vitest';

import type { MediaPortRequest } from '../media/protocol.js';
import { FakePort } from './testDoubles.js';
import type { ClientsLike } from './clients.js';
import { MediaPipe, type MediaPipeScopeLike } from './pipe.js';

const ORIGIN = 'https://vault.example';
const TIMEOUTS = { brokerTimeoutMs: 1000, responseTimeoutMs: 100, pullTimeoutMs: 2000 };

class FakeScope implements MediaPipeScopeLike {
  readonly brokered: MediaPortRequest[] = [];
  /** Which tab each request was aimed at, so scoping is observable. */
  readonly brokeredTo: string[] = [];
  readonly location = { origin: ORIGIN };
  readonly clients: ClientsLike = {
    matchAll: async () =>
      ['tab-a', 'tab-b'].map((id) => ({
        id,
        postMessage: (message: MediaPortRequest): void => {
          this.brokered.push(message);
          this.brokeredTo.push(id);
        },
      })),
  };
}

const bufferOf = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

/** A port that answers `open` with a 206 head and drains `chunks` on pull. */
/** A tab whose registry never minted the ticket under request. */
function unknownTicketPort(): FakePort {
  return new FakePort((message, port) => {
    if (message.type !== 'cb:media:open') return;
    port.deliver({ type: 'cb:media:head', requestId: message.requestId, status: 404, headers: [] });
  });
}

function streamingPort(chunks: Uint8Array[]): FakePort {
  const queue = [...chunks];
  return new FakePort((message, port) => {
    if (message.type === 'cb:media:open') {
      port.deliver({
        type: 'cb:media:head',
        requestId: message.requestId,
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
      status: 200,
      headers: [],
    });
  });
}

/** Streams one window and then sits between pulls, as a buffered element does. */
async function idleBody(
  pipe: MediaPipe,
  port: FakePort,
  clientId?: string
): Promise<{ reader: ReadableStreamDefaultReader<Uint8Array>; requestId: number }> {
  const response = await pipe.respond(streamRequest(), clientId);
  const reader = response.body!.getReader();
  expect((await reader.read()).value).toEqual(new Uint8Array([1]));
  const open = port.sent.find((message) => message.type === 'cb:media:open')!;
  return { reader, requestId: open.requestId };
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

  it('leaves the port open when a cancelled body outlives its pull deadline', async () => {
    vi.useFakeTimers();
    try {
      const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
      const stalled = stalledPort();
      pipe.adoptPort(stalled);

      const response = await pipe.respond(streamRequest());
      const reader = response.body?.getReader();
      void reader?.read();
      await Promise.resolve();
      await reader?.cancel();

      // The pull this cancelled left a deadline armed; firing it must not take
      // the port down under the bodies still streaming on it.
      await vi.advanceTimersByTimeAsync(TIMEOUTS.pullTimeoutMs * 2);

      expect(stalled.closed).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('errors the response body when the port reports a read failure', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = new FakePort((message, self) => {
      if (message.type === 'cb:media:open') {
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
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

  it('turns an error-status head into a bodiless response and never pulls', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = new FakePort((message, self) => {
      if (message.type !== 'cb:media:open') return;
      self.deliver({
        type: 'cb:media:head',
        requestId: message.requestId,
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

  it('closes the cursor of an open it gave up waiting for', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    // The tab answers the open after the pipe stopped listening, so it is left
    // holding a cursor and the engine stream that cursor pins.
    const silent = new FakePort();
    pipe.adoptPort(silent);

    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs);

    const open = silent.sent.find((message) => message.type === 'cb:media:open');
    expect(silent.sent).toContainEqual({ type: 'cb:media:close', requestId: open!.requestId });

    await vi.advanceTimersByTimeAsync(TIMEOUTS.brokerTimeoutMs);
    expect((await pending).status).toBe(503);
  });

  it('keeps a port that refused an open, asking its engine nothing twice', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    // The tab reached its engine and its engine refused — opening the stream is
    // what frames the head, so this arrives instead of one.
    const refusing = new FakePort((message, self) => {
      if (message.type !== 'cb:media:open') return;
      self.deliver({
        type: 'cb:media:error',
        requestId: message.requestId,
        message: 'too many read streams are already open',
      });
    });
    pipe.adoptPort(refusing);

    const response = await pipe.respond(streamRequest());

    expect(response.status).toBe(503);
    expect(refusing.countOf('cb:media:open')).toBe(1);
    expect(refusing.closed).toBe(false);
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

  it('asks only the tab that needs a port, leaving other tabs brokered', async () => {
    vi.useFakeTimers();
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);

    const pending = pipe.respond(streamRequest(), 'tab-b');
    await vi.advanceTimersByTimeAsync(TIMEOUTS.brokerTimeoutMs);
    await pending;
    vi.useRealTimers();

    expect(scope.brokeredTo).toEqual(['tab-b']);
  });

  it('asks every tab when the request carries no client identity', async () => {
    vi.useFakeTimers();
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);

    const pending = pipe.respond(streamRequest());
    await vi.advanceTimersByTimeAsync(TIMEOUTS.brokerTimeoutMs);
    await pending;
    vi.useRealTimers();

    expect(scope.brokeredTo).toEqual(['tab-a', 'tab-b']);
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

describe('MediaPipe idle bodies', () => {
  it('ends an idle body as soon as the tab withdraws the stream', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    pipe.adoptPort(port);
    const { reader, requestId } = await idleBody(pipe, port);

    // What `MediaBroker.revoke` posts: unsolicited, with no pull in flight.
    port.deliver({ type: 'cb:media:error', requestId, message: 'the stream was revoked' });

    // No timers advanced: the body must not wait out the pull deadline.
    await expect(reader.read()).rejects.toThrow('the stream was revoked');
    expect(port.sent).toContainEqual({ type: 'cb:media:close', requestId });
  });

  it('ends an idle body as soon as its port is replaced', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    pipe.adoptPort(port, 'tab-a');
    const { reader } = await idleBody(pipe, port, 'tab-a');

    pipe.adoptPort(new FakePort(), 'tab-a');

    await expect(reader.read()).rejects.toThrow(/media port replaced/);
  });

  it('ignores an unsolicited error posted on a port that owns no such body', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const own = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    const other = new FakePort();
    pipe.adoptPort(own, 'tab-a');
    pipe.adoptPort(other, 'tab-b');
    const { reader, requestId } = await idleBody(pipe, own, 'tab-a');

    other.deliver({ type: 'cb:media:error', requestId, message: 'not yours to fail' });

    expect((await reader.read()).value).toEqual(new Uint8Array([2]));
  });

  it('ignores an unsolicited error for a body that already ended', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    pipe.adoptPort(port);
    const { reader, requestId } = await idleBody(pipe, port);
    await reader.cancel();

    expect(() =>
      port.deliver({ type: 'cb:media:error', requestId, message: 'too late' })
    ).not.toThrow();
    expect(port.countOf('cb:media:close')).toBe(1);
  });

  it('retries the open as soon as the port it was sent on is replaced', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const silent = new FakePort();
    pipe.adoptPort(silent, 'tab-a');

    const pending = pipe.respond(streamRequest(), 'tab-a');
    // Flushes the open onto the port without spending any of its deadline.
    await vi.advanceTimersByTimeAsync(0);
    const live = streamingPort([new Uint8Array([7])]);
    pipe.adoptPort(live, 'tab-a');

    const response = await pending;
    expect(response.status).toBe(206);
    expect(silent.countOf('cb:media:open')).toBe(1);
    expect(live.countOf('cb:media:open')).toBe(1);
    // The replaced port hosts a cursor and the engine stream behind it; the
    // release has to reach it before the port is closed.
    expect(silent.countOf('cb:media:close')).toBe(1);
  });
});

describe('MediaPipe.requestPorts', () => {
  it('asks every window client to re-broker when the worker holds no port', async () => {
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);

    await pipe.requestPorts();

    expect(scope.brokeredTo).toEqual(['tab-a', 'tab-b']);
  });

  it('asks nobody while it holds a port, leaving a paused body its cursor', async () => {
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);
    const port = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    pipe.adoptPort(port, 'tab-a');
    const { reader } = await idleBody(pipe, port, 'tab-a');

    await pipe.requestPorts();

    expect(scope.brokered).toEqual([]);
    expect(port.countOf('cb:media:close')).toBe(0);
    expect((await reader.read()).value).toEqual(new Uint8Array([2]));
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

  it('closes the tab-side cursor of every body still reading on a replaced port', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    // Two windows deep, so the body is live but between pulls when the port dies.
    const port = streamingPort([new Uint8Array([1]), new Uint8Array([2])]);
    pipe.adoptPort(port, 'tab-a');

    const response = await pipe.respond(streamRequest(), 'tab-a');
    const reader = response.body!.getReader();
    await reader.read();
    expect(port.countOf('cb:media:close')).toBe(0);

    pipe.adoptPort(new FakePort(), 'tab-a');

    const open = port.sent.find((message) => message.type === 'cb:media:open');
    expect(port.sent).toContainEqual({ type: 'cb:media:close', requestId: open!.requestId });
  });

  it('leaves nothing to close once the body has ended', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const port = streamingPort([new Uint8Array([1])]);
    pipe.adoptPort(port, 'tab-a');

    const response = await pipe.respond(streamRequest(), 'tab-a');
    await response.arrayBuffer();
    pipe.adoptPort(new FakePort(), 'tab-a');

    expect(port.countOf('cb:media:close')).toBe(0);
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

  it('asks the other tabs when a navigation lands on a port that never minted the ticket', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    // A save is a navigation, which carries no client id, so the pipe borrows
    // the newest port — the tab that opened last, not the one that saved.
    const owner = streamingPort([new Uint8Array([7, 7])]);
    const stranger = unknownTicketPort();
    pipe.adoptPort(owner, 'tab-a');
    pipe.adoptPort(stranger, 'tab-b');

    const response = await pipe.respond(streamRequest());

    expect(response.status).toBe(206);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([7, 7]));
    expect(stranger.countOf('cb:media:open')).toBe(1);
    expect(owner.countOf('cb:media:open')).toBe(1);
  });

  it('answers a navigation 404 when no tab minted the ticket', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const a = unknownTicketPort();
    const b = unknownTicketPort();
    pipe.adoptPort(a, 'tab-a');
    pipe.adoptPort(b, 'tab-b');

    const response = await pipe.respond(streamRequest());

    expect(response.status).toBe(404);
    expect(a.countOf('cb:media:open')).toBe(1);
    expect(b.countOf('cb:media:open')).toBe(1);
  });

  it('keeps an identified client to its own port, whatever another tab holds', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    const other = streamingPort([new Uint8Array([9])]);
    const own = unknownTicketPort();
    pipe.adoptPort(own, 'tab-a');
    pipe.adoptPort(other, 'tab-b');

    const response = await pipe.respond(streamRequest(), 'tab-a');

    // The fan-out is for navigations alone; a named client that does not know
    // its own ticket gets its own answer.
    expect(response.status).toBe(404);
    expect(other.countOf('cb:media:open')).toBe(0);
  });

  it('re-brokers to the owning tab instead of borrowing another client port', async () => {
    vi.useFakeTimers();
    const scope = new FakeScope();
    const pipe = new MediaPipe(scope, TIMEOUTS);
    const b = streamingPort([new Uint8Array([2])]);
    pipe.adoptPort(b, 'tab-b');

    const pending = pipe.respond(streamRequest(), 'tab-a');
    await vi.advanceTimersByTimeAsync(TIMEOUTS.brokerTimeoutMs);
    const response = await pending;
    vi.useRealTimers();

    // Tab B's registry never minted tab A's ticket, so its port cannot answer.
    expect(b.countOf('cb:media:open')).toBe(0);
    expect(scope.brokeredTo).toEqual(['tab-a']);
    expect(response.status).toBe(503);
  });

  it('keeps a client waiting when an unrelated client offers a port', async () => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);

    const pending = pipe.respond(streamRequest(), 'tab-a');
    await vi.advanceTimersByTimeAsync(TIMEOUTS.brokerTimeoutMs / 2);
    const other = streamingPort([new Uint8Array([9])]);
    pipe.adoptPort(other, 'tab-b');
    await vi.advanceTimersByTimeAsync(1);
    expect(other.countOf('cb:media:open')).toBe(0);

    const own = streamingPort([new Uint8Array([4])]);
    pipe.adoptPort(own, 'tab-a');
    const response = await pending;
    vi.useRealTimers();

    expect(response.status).toBe(206);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([4]));
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
    pipe.adoptPort(live, 'tab-a');
    pipe.adoptPort(dead, 'tab-b');

    const pending = pipe.respond(streamRequest(), 'tab-b');
    await vi.advanceTimersByTimeAsync(TIMEOUTS.responseTimeoutMs + TIMEOUTS.brokerTimeoutMs);
    const response = await pending;
    vi.useRealTimers();

    expect(dead.closed).toBe(true);
    expect(dead.countOf('cb:media:open')).toBe(1);
    // The retry re-brokers its own tab rather than answering off another's port.
    expect(live.countOf('cb:media:open')).toBe(0);
    expect(response.status).toBe(503);
  });
});

describe('MediaPipe port-message validation', () => {
  const headPort = (head: (requestId: number) => unknown): FakePort =>
    new FakePort((message, port) => {
      if (message.type !== 'cb:media:open') return;
      port.deliverRaw(head(message.requestId));
    });

  it.each([
    { case: 'a status outside the HTTP range', status: 999, headers: [] },
    { case: 'a status that is not an integer', status: 200.5, headers: [] },
    { case: 'a status that is not a number', status: '200', headers: [] },
    { case: 'headers that are not string pairs', status: 200, headers: 'video/mp4' },
    { case: 'headers holding a malformed pair', status: 200, headers: [['only']] },
  ])('never builds a response from a head with $case', async (head) => {
    vi.useFakeTimers();
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(
      headPort((requestId) => ({
        type: 'cb:media:head',
        requestId,
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

describe('MediaPipe response headers', () => {
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

  it('marks an error-status head no-store', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(
      new FakePort((message, self) => {
        if (message.type !== 'cb:media:open') return;
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
          status: 404,
          headers: [],
        });
      })
    );

    const response = await pipe.respond(streamRequest('unknown'));

    expect(response.status).toBe(404);
    expect(response.headers.get('cache-control')).toBe('no-store');
  });

  it('hardens a body head the port left executable', async () => {
    const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
    pipe.adoptPort(
      new FakePort((message, self) => {
        if (message.type !== 'cb:media:open') return;
        self.deliver({
          type: 'cb:media:head',
          requestId: message.requestId,
          status: 200,
          headers: [['content-type', 'text/html']],
        });
      })
    );

    const response = await pipe.respond(streamRequest());

    expect(response.headers.get('content-type')).toBe('application/octet-stream');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
  });

  const dispositions: Array<[string, string, string]> = [
    [
      'serves the shape the tab mints',
      "attachment; filename*=UTF-8''notes.md",
      "attachment; filename*=UTF-8''notes.md",
    ],
    [
      'serves a percent-encoded name',
      "attachment; filename*=UTF-8''notes%20%C3%A9.md",
      "attachment; filename*=UTF-8''notes%20%C3%A9.md",
    ],
    ['serves a bare attachment', 'attachment', 'attachment'],
    ['drops a truncated percent escape', "attachment; filename*=UTF-8''name%", 'attachment'],
    ['drops a non-hex percent escape', "attachment; filename*=UTF-8''name%ZZ", 'attachment'],
    ['drops a second parameter', "attachment; filename*=UTF-8''a.md; foo=bar", 'attachment'],
    ['drops an unencoded name', 'attachment; filename="a b.md"', 'attachment'],
    ['refuses to render inline', 'inline', 'attachment'],
  ];

  for (const [name, sent, served] of dispositions) {
    it(name, async () => {
      const pipe = new MediaPipe(new FakeScope(), TIMEOUTS);
      pipe.adoptPort(
        new FakePort((message, self) => {
          if (message.type !== 'cb:media:open') return;
          self.deliver({
            type: 'cb:media:head',
            requestId: message.requestId,
            status: 200,
            headers: [
              ['content-type', 'video/mp4'],
              ['content-disposition', sent],
            ],
          });
        })
      );

      const response = await pipe.respond(streamRequest());

      expect(response.headers.get('content-disposition')).toBe(served);
    });
  }
});
