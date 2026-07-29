import { describe, expect, it } from 'vitest';

import { BroadcastTransport } from './broadcastTransport.js';
import { EngineRequestError } from './correlatedTransport.js';
import { LeaderRelay } from './leaderRelay.js';
import { emptySnapshot, FakeBus, FakeEngineTransport } from './testkit.js';
import type { EventDescriptor, SnapshotDescriptor } from './worker/protocol.js';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

function wire(): { engine: FakeEngineTransport; relay: LeaderRelay; follower: BroadcastTransport } {
  const bus = new FakeBus();
  const engine = new FakeEngineTransport();
  const relay = new LeaderRelay(bus.channel(), engine);
  const follower = new BroadcastTransport(bus.channel(), 'follower-1');
  return { engine, relay, follower };
}

describe('broadcast transport ↔ leader relay', () => {
  it('routes a follower command to the leader engine and correlates the response', async () => {
    const { engine, follower } = wire();
    await follower.command({ kind: 'delete', node: new Uint8Array(16) }, []);
    expect(engine.commands.map((c) => c.kind)).toEqual(['delete']);
  });

  it('takes no secret: start just awaits a live leader, wire carries only a hello', async () => {
    const bus = new FakeBus();
    const posted: unknown[] = [];
    const leaderChannel = bus.channel();
    leaderChannel.addEventListener('message', (event) => posted.push(event.data));
    // A relay makes a leader "present" so start resolves.
    new LeaderRelay(leaderChannel, new FakeEngineTransport());
    const follower = new BroadcastTransport(bus.channel(), 'f');

    // The keyless follower transport receives no secret at all — `start` has no
    // secret parameter; it resolves once a leader beacon arrives.
    await follower.start();

    // The only thing the follower put on the wire is its self-announcing hello.
    const followerPosts = posted.filter(
      (m) => (m as { clientId?: string }).clientId === 'f'
    ) as Array<{ type: string }>;
    expect(followerPosts.map((m) => m.type)).toEqual(['cb:hello']);
  });

  it('never echoes the leader secret onto any leader→follower message (structural)', async () => {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();

    // The sentinel *is* the leader's key material: 32 distinctive secret bytes
    // actually handed to the leader engine. It must never ride the keyless
    // leader→follower wire — not on an event, not in a response error string.
    const sentinel = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
    await engine.start(sentinel.buffer.slice(0));

    new LeaderRelay(bus.channel(), engine);

    // Capture everything the leader broadcasts to followers (events + responses).
    const leaderPosts: unknown[] = [];
    const spy = bus.channel();
    spy.addEventListener('message', (event) => leaderPosts.push(event.data));

    const follower = new BroadcastTransport(bus.channel(), 'f');
    await follower.start();

    // A command whose engine handling rejects: the relay forwards the failure as
    // a `cb:response` error string — a real leak vector for secret bytes bleeding
    // into an error message. A hygienic engine rejects with a generic message.
    engine.respond = () => Promise.reject(new Error('command failed'));
    await follower.command({ kind: 'manualRefresh' }, []).catch(() => undefined);

    // Plus every EventDescriptor variant, including the byte- and string-bearing
    // ones the relay forwards verbatim.
    engine.respond = () => Promise.resolve();
    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'stalenessChanged', staleness: 'stale' });
    engine.emit({ kind: 'withheldUpdateEscalation', ipnsName: new Uint8Array([1, 2, 3]) });
    engine.emit({ kind: 'deadLetter', opId: 9n, reason: 'undecodable' });
    engine.emit({ kind: 'attributableAbuse', description: 'abuse' });
    await tick();

    // Serialize every leader post (bytes as csv, bigint as string) and assert the
    // secret never rode along. A relay that echoed the leader's key material into
    // an event or error string would surface the sentinel here and fail.
    const serialize = (value: unknown): string =>
      JSON.stringify(value, (_key, v) =>
        v instanceof Uint8Array ? [...v].join(',') : typeof v === 'bigint' ? v.toString() : v
      );
    const sentinelCsv = [...sentinel].join(',');
    const leaked = leaderPosts.some((message) => serialize(message).includes(sentinelCsv));
    expect(leaked).toBe(false);
    // Sanity: the leader actually broadcast the failure response + events we drove
    // — the error-string wire field the sentinel could have leaked through is live.
    const errorResponses = leaderPosts.filter(
      (m) =>
        (m as { type?: string; ok?: boolean }).type === 'cb:response' && !(m as { ok?: boolean }).ok
    );
    expect(errorResponses.length).toBe(1);
    expect(leaderPosts.length).toBeGreaterThanOrEqual(6);
  });

  it('shares an upload chunk as a Blob and rebuilds identical bytes on the leader', async () => {
    const { engine, follower } = wire();
    const bytes = Uint8Array.from({ length: 512 }, (_, i) => (i * 13 + 7) & 0xff);

    const node = new Uint8Array(16).fill(3);
    const handle = await follower.beginWrite({ node }, bytes.byteLength);
    expect(handle).toBe(engine.writeHandle);
    expect(engine.beginWrites).toEqual([{ target: { node }, size: 512 }]);

    await follower.pushChunk(handle, bytes.buffer.slice(0));
    expect(engine.chunks).toHaveLength(1);
    expect([...new Uint8Array(engine.chunks[0].chunk)]).toEqual([...bytes]);
    expect(engine.chunks[0].handle).toBe(handle);

    await expect(follower.commitWrite(handle)).resolves.toBe(engine.commitOpId);
    expect(engine.commits).toEqual([handle]);
  });

  it('propagates a write rejection to the follower with the stable code', async () => {
    const { engine, follower } = wire();
    engine.commitWrite = () =>
      Promise.reject(new EngineRequestError('pushed 3 of 5 bytes', 'contentSizeMismatch'));
    engine.pushChunk = () =>
      Promise.reject(new EngineRequestError('no such handle', 'unknownWriteHandle'));

    await expect(follower.pushChunk(1n, new ArrayBuffer(1))).rejects.toMatchObject({
      code: 'unknownWriteHandle',
    });
    await expect(follower.commitWrite(1n)).rejects.toMatchObject({
      code: 'contentSizeMismatch',
      message: 'pushed 3 of 5 bytes',
    });
    // The abort path stays usable after a failed commit.
    await expect(follower.abortWrite(1n)).resolves.toBeUndefined();
    expect(engine.aborts).toEqual([1n]);
  });

  it('fans engine events out to the follower in emission order', async () => {
    const { engine, follower } = wire();
    const received: EventDescriptor[] = [];
    follower.subscribe((event) => received.push(event));
    await tick(); // let the follower register with the leader

    const sent: EventDescriptor[] = [
      { kind: 'snapshotUpdated' },
      { kind: 'deadLetter', opId: 3n, reason: 'payloadRefused' },
      { kind: 'stalenessChanged', staleness: 'stale' },
    ];
    for (const event of sent) engine.emit(event);
    await tick();

    expect(received).toEqual(sent);
  });

  it('rejects in-flight and later commands once the follower transport closes', async () => {
    const { engine, follower } = wire();
    engine.respond = () => new Promise(() => undefined); // never settles
    const inFlight = follower.command({ kind: 'manualRefresh' }, []);
    await tick();
    follower.close();

    await expect(inFlight).rejects.toThrow('closed');
    await expect(follower.command({ kind: 'manualRefresh' }, [])).rejects.toThrow('closed');
  });

  it('folds follower focus into the union and forwards a refresh hint', async () => {
    const { engine, follower } = wire();
    const before = engine.commands.length;
    follower.reportFocus(new Uint8Array([0xaa, 0xbb]));
    await tick();

    const hints = engine.commands.slice(before).filter((c) => c.kind === 'manualRefresh');
    expect(hints.length).toBe(1);
  });

  it('round-trips a follower snapshot through the leader engine', async () => {
    const { engine, follower } = wire();
    const view: SnapshotDescriptor = {
      root: new Uint8Array(16).fill(1),
      folder: new Uint8Array(16).fill(2),
      children: [
        {
          id: new Uint8Array(16).fill(3),
          name: 'photo.jpg',
          kind: 'file',
          size: 1024n,
          mtime: null,
          pending: 'content',
          deadLetter: false,
          contentVersion: 9_007_199_254_740_993n,
        },
      ],
      ancestors: [{ id: new Uint8Array(16).fill(1), name: '' }],
      deadLetters: [{ opId: 7n, reason: 'suffixExhausted' }],
      blocked: null,
      retainedRecords: 0,
      staleness: 'reconciling',
    };
    engine.respondSnapshot = () => Promise.resolve(view);

    const folder = new Uint8Array(16).fill(2);
    // Structured clone across the bus must preserve bytes and bigints intact.
    await expect(follower.snapshot(folder)).resolves.toEqual(view);
    expect(engine.snapshots).toEqual([folder]);
  });

  it('serves a follower download as a Blob and rebuilds identical bytes', async () => {
    const { engine, follower } = wire();
    const plaintext = Uint8Array.from({ length: 64 }, (_, i) => (i * 11 + 5) & 0xff);
    engine.respondDownload = () => Promise.resolve(plaintext.buffer.slice(0));

    const node = new Uint8Array(16).fill(6);
    const content = await follower.download(node);
    expect([...new Uint8Array(content)]).toEqual([...plaintext]);
    expect(engine.downloads).toEqual([node]);
  });

  it('propagates a read rejection back to the follower with the stable code', async () => {
    const { engine, follower } = wire();
    engine.respondSnapshot = () =>
      Promise.reject(new EngineRequestError('unknown node', 'unknownNode'));
    engine.respondDownload = () =>
      Promise.reject(new EngineRequestError('content unavailable: pending', 'contentUnavailable'));

    // The code crosses the broadcast wire alongside the human-readable message.
    await expect(follower.snapshot(new Uint8Array(16))).rejects.toMatchObject({
      code: 'unknownNode',
      message: 'unknown node',
    });
    await expect(follower.download(new Uint8Array(16))).rejects.toMatchObject({
      code: 'contentUnavailable',
    });
  });

  it('rejects a forged read response bearing a wrong or absent leader token', async () => {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();
    engine.respondSnapshot = () => new Promise(() => undefined); // the real leader never answers
    new LeaderRelay(bus.channel(), engine);
    const follower = new BroadcastTransport(bus.channel(), 'f');
    await follower.start();

    const pending = follower.snapshot(new Uint8Array(16));
    let settled = false;
    void pending.then(
      () => (settled = true),
      () => (settled = true)
    );
    await tick();

    const forgedView: SnapshotDescriptor = emptySnapshot();
    const attacker = bus.channel();
    attacker.postMessage({
      type: 'cb:response',
      token: 'forged-token',
      clientId: 'f',
      requestId: 1,
      ok: true,
      result: forgedView,
    });
    attacker.postMessage({
      type: 'cb:response',
      clientId: 'f',
      requestId: 1,
      ok: true,
      result: forgedView,
    });
    await tick();

    expect(settled).toBe(false);
  });

  it('rejects an in-flight read retryably when the leader steps down', async () => {
    const bus = new FakeBus();
    const engineA = new FakeEngineTransport();
    engineA.respondSnapshot = () => new Promise(() => undefined); // leader A never answers
    const relayA = new LeaderRelay(bus.channel(), engineA);
    const follower = new BroadcastTransport(bus.channel(), 'f');
    await follower.start();

    const inFlight = follower.snapshot(new Uint8Array(16));
    await tick();
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // A read issued with no leader parks, then resolves against the next leader.
    const queued = follower.snapshot(new Uint8Array(16).fill(4));
    const engineB = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engineB);
    await expect(queued).resolves.toMatchObject({ staleness: 'fresh' });
    expect(engineB.snapshots).toHaveLength(1);
  });

  it('re-arms on leadership change: an in-flight command rejects retryably, later commands await the next leader (P1-3)', async () => {
    const bus = new FakeBus();
    const engineA = new FakeEngineTransport();
    engineA.respond = () => new Promise(() => undefined); // leader A never answers
    const relayA = new LeaderRelay(bus.channel(), engineA);
    const follower = new BroadcastTransport(bus.channel(), 'f');
    await follower.start(); // leader A present

    const inFlight = follower.command({ kind: 'manualRefresh' }, []);
    await tick();

    // Leader A steps down: the in-flight command rejects retryably, never hangs.
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // A command issued while no leader is present parks on the re-armed gate.
    const queued = follower.command({ kind: 'manualRefresh' }, []);
    let settled = false;
    void queued.then(
      () => (settled = true),
      () => (settled = true)
    );
    await tick();
    expect(settled).toBe(false);

    // A fresh leader is elected → the queued command resolves against it.
    const engineB = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engineB);
    await queued;
    expect(engineB.commands.map((c) => c.kind)).toEqual(['manualRefresh']);
  });

  it('rejects a forged response/event bearing a wrong or absent leader token (P1-4)', async () => {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();
    engine.respond = () => new Promise(() => undefined); // the real leader never answers
    new LeaderRelay(bus.channel(), engine);
    const follower = new BroadcastTransport(bus.channel(), 'f');
    await follower.start();

    const pending = follower.command({ kind: 'manualRefresh' }, []);
    let settled = false;
    void pending.then(
      () => (settled = true),
      () => (settled = true)
    );
    await tick();

    // A same-origin attacker forges an ok response for the follower's request —
    // once with a wrong token, once with none. Neither may settle the command.
    const attacker = bus.channel();
    attacker.postMessage({
      type: 'cb:response',
      token: 'forged-token',
      clientId: 'f',
      requestId: 1,
      ok: true,
    });
    attacker.postMessage({ type: 'cb:response', clientId: 'f', requestId: 1, ok: true });

    // A forged event with a wrong token must not reach subscribers either.
    const events: EventDescriptor[] = [];
    follower.subscribe((event) => events.push(event));
    attacker.postMessage({
      type: 'cb:event',
      token: 'forged-token',
      event: { kind: 'snapshotUpdated' },
    });
    await tick();

    expect(settled).toBe(false);
    expect(events).toEqual([]);
  });
});
