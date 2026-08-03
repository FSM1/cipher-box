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

    const handle = await follower.beginWrite({ node: new Uint8Array(16) }, 5);
    await expect(follower.pushChunk(handle, new ArrayBuffer(1))).rejects.toMatchObject({
      code: 'unknownWriteHandle',
    });
    await expect(follower.commitWrite(handle)).rejects.toMatchObject({
      code: 'contentSizeMismatch',
      message: 'pushed 3 of 5 bytes',
    });
    // The abort path stays usable after a failed commit.
    await expect(follower.abortWrite(handle)).resolves.toBeUndefined();
    expect(engine.aborts).toEqual([handle]);
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
      folderName: 'holiday',
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

  it('carries a rootless follower snapshot to the leader as no folder at all', async () => {
    const { engine, follower } = wire();
    // A follower that has not named a folder asks for the vault root; `null`
    // must survive the structured clone rather than arrive as a seeded id.
    await expect(follower.snapshot(null)).resolves.toEqual(emptySnapshot());
    expect(engine.snapshots).toEqual([null]);
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

  it('serves a follower SIWE challenge off the leader engine', async () => {
    const { engine, follower } = wire();
    engine.respondSiweChallenge = () => Promise.resolve('leaderNonce12345');

    await expect(follower.siweChallenge()).resolves.toBe('leaderNonce12345');
    expect(engine.siweChallenges).toBe(1);
  });

  it('serves a follower downloadRange as a Blob and rebuilds the window bytes', async () => {
    const { engine, follower } = wire();
    const file = Uint8Array.from({ length: 256 }, (_, i) => (i * 3 + 1) & 0xff);
    engine.respondDownloadRange = (_node, offset, length) =>
      Promise.resolve(file.slice(offset, offset + length).buffer);

    const node = new Uint8Array(16).fill(6);
    const window = await follower.downloadRange(node, 64, 32);
    expect([...new Uint8Array(window)]).toEqual([...file.slice(64, 96)]);
    // A dropped or clamped offset slices the wrong plaintext with every
    // integrity check still passing.
    expect(engine.downloadRanges).toEqual([{ node, offset: 64, length: 32 }]);
  });

  it('rejects an in-flight downloadRange retryably when the leader steps down', async () => {
    const bus = new FakeBus();
    const engineA = new FakeEngineTransport();
    engineA.respondDownloadRange = () => new Promise(() => undefined); // leader A never answers
    const relayA = new LeaderRelay(bus.channel(), engineA);
    const follower = new BroadcastTransport(bus.channel(), 'f');
    await follower.start();

    const inFlight = follower.downloadRange(new Uint8Array(16), 0, 8);
    await tick();
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // The next leader serves the retry, so the swap costs a retry, never a hang.
    const engineB = new FakeEngineTransport();
    engineB.respondDownloadRange = () => Promise.resolve(new Uint8Array([1, 2]).buffer);
    new LeaderRelay(bus.channel(), engineB);
    const retried = await follower.downloadRange(new Uint8Array(16), 0, 2);
    expect([...new Uint8Array(retried)]).toEqual([1, 2]);
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

describe('leader relay write handles', () => {
  function bench(): { bus: FakeBus; engine: FakeEngineTransport; relay: LeaderRelay } {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();
    const relay = new LeaderRelay(bus.channel(), engine);
    return { bus, engine, relay };
  }

  const chunk = (seq: number): ArrayBuffer => Uint8Array.of(seq).buffer;
  const node = (fill: number): Uint8Array => new Uint8Array(16).fill(fill);

  it('applies pipelined chunks for one handle in send order', async () => {
    const { bus, engine } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1');
    const applied: number[] = [];
    // Later chunks settle faster: unserialized they would overtake earlier ones,
    // scrambling the plaintext while every integrity check still passes.
    engine.pushChunk = async (_handle, bytes) => {
      const seq = new Uint8Array(bytes)[0];
      await new Promise((resolve) => setTimeout(resolve, (4 - seq) * 5));
      applied.push(seq);
    };

    const handle = await follower.beginWrite({ node: node(3) }, 3);
    // Fired without awaiting, exactly as a UI pipelining an upload would.
    await Promise.all([1, 2, 3].map((seq) => follower.pushChunk(handle, chunk(seq))));

    expect(applied).toEqual([1, 2, 3]);
  });

  it('keeps distinct handles concurrent', async () => {
    const { bus, engine } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1');
    let releaseFirst!: () => void;
    engine.pushChunk = (handle) =>
      handle === 1n ? new Promise<void>((resolve) => (releaseFirst = resolve)) : Promise.resolve();

    engine.writeHandle = 1n;
    const first = await follower.beginWrite({ node: node(1) }, 1);
    engine.writeHandle = 2n;
    const second = await follower.beginWrite({ node: node(2) }, 1);

    const parked = follower.pushChunk(first, chunk(1));
    let parkedSettled = false;
    void parked.then(() => (parkedSettled = true));

    await expect(follower.pushChunk(second, chunk(2))).resolves.toBeUndefined();
    expect(parkedSettled).toBe(false);

    releaseFirst();
    await parked;
  });

  it('rejects a write step against a handle the sender does not own', async () => {
    const { bus, engine } = bench();
    const owner = new BroadcastTransport(bus.channel(), 'owner');
    const other = new BroadcastTransport(bus.channel(), 'other');
    const handle = await owner.beginWrite({ node: node(4) }, 4);

    await expect(other.pushChunk(handle, chunk(9))).rejects.toMatchObject({
      code: 'unknownWriteHandle',
    });
    await expect(other.abortWrite(handle)).rejects.toMatchObject({ code: 'unknownWriteHandle' });
    await expect(other.commitWrite(handle)).rejects.toMatchObject({ code: 'unknownWriteHandle' });

    // Nothing reached the engine, and the owner still drives its own handle.
    expect(engine.chunks).toEqual([]);
    expect(engine.aborts).toEqual([]);
    expect(engine.commits).toEqual([]);
    await expect(owner.pushChunk(handle, chunk(1))).resolves.toBeUndefined();
  });

  it('aborts a departing client handles and leaves the other client alone', async () => {
    const { bus, engine } = bench();
    const leaving = new BroadcastTransport(bus.channel(), 'leaving');
    const staying = new BroadcastTransport(bus.channel(), 'staying');
    engine.writeHandle = 1n;
    const orphan = await leaving.beginWrite({ node: node(1) }, 4);
    engine.writeHandle = 2n;
    const kept = await staying.beginWrite({ node: node(2) }, 4);

    leaving.close(); // posts `cb:bye`
    await tick();

    expect(engine.aborts).toEqual([orphan]);
    await expect(staying.pushChunk(kept, chunk(1))).resolves.toBeUndefined();
    expect(engine.chunks.map((entry) => entry.handle)).toEqual([kept]);
  });

  it('releases every open handle when the leader steps down', async () => {
    const { bus, engine, relay } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1');
    const handle = await follower.beginWrite({ node: node(5) }, 4);

    relay.close();
    await tick();

    expect(engine.aborts).toEqual([handle]);
  });
});
