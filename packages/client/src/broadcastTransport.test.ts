import { describe, expect, it } from 'vitest';

import { BroadcastTransport } from './broadcastTransport.js';
import { EngineRequestError } from './correlatedTransport.js';
import { LeaderRelay, type LeaderRelayOptions } from './leaderRelay.js';
import { unavailableCourier } from './portCourier.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import {
  emptySnapshot,
  FakeBus,
  FakeChannelPort,
  FakeCourierNetwork,
  FakeEngineTransport,
} from './testkit.js';
import type { EventDescriptor, SnapshotDescriptor } from './worker/protocol.js';

const after = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const tick = (): Promise<void> => after(0);

function wire(): {
  bus: FakeBus;
  ports: FakeCourierNetwork;
  engine: FakeEngineTransport;
  relay: LeaderRelay;
  follower: BroadcastTransport;
} {
  const bus = new FakeBus();
  const ports = new FakeCourierNetwork();
  const engine = new FakeEngineTransport();
  const relay = new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
  const follower = new BroadcastTransport(bus.channel(), 'follower-1', ports.courier('follower-1'));
  return { bus, ports, engine, relay, follower };
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
    const ports = new FakeCourierNetwork();
    const leaderChannel = bus.channel();
    leaderChannel.addEventListener('message', (event) => posted.push(event.data));
    // A relay makes a leader "present" so start resolves.
    new LeaderRelay(leaderChannel, new FakeEngineTransport(), ports.courier('leader'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));

    // The keyless follower transport receives no secret at all — `start` has no
    // secret parameter; it resolves once a leader beacon arrives.
    await follower.start();
    await tick(); // let the eager read-port rendezvous land on the wire too

    // The only thing the follower put on the wire is its self-announcing hello.
    const followerPosts = posted.filter(
      (m) => (m as { clientId?: string }).clientId === 'f'
    ) as Array<{ type: string }>;
    expect(followerPosts.map((m) => m.type)).toEqual(['cb:hello', 'cb:portWanted']);
  });

  it('never echoes the leader secret onto any leader→follower message (structural)', async () => {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();

    // The sentinel *is* the leader's key material: 32 distinctive secret bytes
    // actually handed to the leader engine. It must never ride the keyless
    // leader→follower wire — not on an event, not in a result error string.
    const sentinel = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
    await engine.start(sentinel.buffer.slice(0));

    const ports = new FakeCourierNetwork();
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));

    // Capture both leader→follower wires: the channel (events) and the port.
    const leaderPosts: unknown[] = [];
    const spy = bus.channel();
    spy.addEventListener('message', (event) => leaderPosts.push(event.data));

    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await follower.start();

    // A command whose engine handling rejects: the relay forwards the failure as
    // a `cb:portResult` error string — a real leak vector for secret bytes
    // bleeding into an error message. A hygienic engine rejects generically.
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
    const sent = [...leaderPosts, ...ports.messages];
    expect(sent.some((message) => serialize(message).includes(sentinelCsv))).toBe(false);
    // Sanity: the failing command's error string actually crossed a wire, so the
    // field the sentinel could have leaked through is live.
    const errorResults = ports.messages.filter(
      (m) =>
        (m as { type?: string; ok?: boolean }).type === 'cb:portResult' &&
        !(m as { ok?: boolean }).ok
    );
    expect(errorResults.length).toBe(1);
    expect(leaderPosts.length).toBeGreaterThanOrEqual(5);
  });

  it('moves an upload chunk over the private port and rebuilds identical bytes on the leader', async () => {
    const { engine, follower, ports } = wire();
    const bytes = Uint8Array.from({ length: 512 }, (_, i) => (i * 13 + 7) & 0xff);

    const node = new Uint8Array(16).fill(3);
    const handle = await follower.beginWrite({ node }, bytes.byteLength);
    expect(handle).toBe(engine.writeHandle);
    expect(engine.beginWrites).toEqual([{ target: { node }, size: 512 }]);

    const chunk = bytes.buffer.slice(0);
    await follower.pushChunk(handle, chunk);
    expect(engine.chunks).toHaveLength(1);
    expect([...new Uint8Array(engine.chunks[0].chunk)]).toEqual([...bytes]);
    expect(engine.chunks[0].handle).toBe(handle);
    // Transferred, not cloned: the plaintext leaves the follower's heap rather
    // than being copied into every same-origin context.
    expect(chunk.byteLength).toBe(0);
    expect(ports.transfers.some((list) => list[0] === chunk)).toBe(true);

    await expect(follower.commitWrite(handle)).resolves.toBe(engine.commitOpId);
    expect(engine.commits).toEqual([handle]);
  });

  it('keeps upload plaintext and command arguments off the channel', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));

    // A same-origin context that opened the engine channel and does nothing else.
    const observed: unknown[] = [];
    const eavesdropper = bus.channel();
    eavesdropper.addEventListener('message', (event) => observed.push(event.data));

    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    const plaintext = Uint8Array.from({ length: 64 }, (_, i) => (i * 29 + 13) & 0xff);
    const handle = await follower.beginWrite(
      { parent: new Uint8Array(16), name: 'payslip.pdf' },
      64
    );
    await follower.pushChunk(handle, plaintext.buffer.slice(0));
    await follower.commitWrite(handle);
    await follower.command(
      { kind: 'rename', node: new Uint8Array(16), newName: 'tax-return.pdf' },
      []
    );
    await tick();

    // Election and rendezvous only: no write step, no command, no arguments.
    expect([...new Set(observed.map((m) => (m as { type: string }).type))].sort()).toEqual([
      'cb:hello',
      'cb:leader',
      'cb:portHost',
      'cb:portWanted',
    ]);
    const serialized = JSON.stringify(observed, (_key, value: unknown) =>
      value instanceof Uint8Array ? [...value] : value
    );
    expect(serialized).not.toContain('payslip.pdf');
    expect(serialized).not.toContain('tax-return.pdf');
    for (const byte of plaintext.slice(0, 8)) expect(serialized).not.toContain(`,${byte},`);
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

  it('serves a follower download over the private port and rebuilds identical bytes', async () => {
    const { engine, follower, ports } = wire();
    const plaintext = Uint8Array.from({ length: 64 }, (_, i) => (i * 11 + 5) & 0xff);
    engine.respondDownload = () => Promise.resolve(plaintext.buffer.slice(0));

    const node = new Uint8Array(16).fill(6);
    const content = await follower.download(node);
    expect([...new Uint8Array(content)]).toEqual([...plaintext]);
    expect(engine.downloads).toEqual([node]);
    // The buffer moves rather than being cloned: the leader's copy is detached,
    // so the plaintext leaves its heap instead of lingering there.
    const moved = ports.transfers.at(-1)?.[0] as ArrayBuffer;
    expect(moved).toBeInstanceOf(ArrayBuffer);
    expect(moved.byteLength).toBe(0);
  });

  it('serves a follower SIWE challenge off the leader engine', async () => {
    const { engine, follower } = wire();
    engine.respondSiweChallenge = () => Promise.resolve('leaderNonce12345');

    await expect(follower.siweChallenge()).resolves.toBe('leaderNonce12345');
    expect(engine.siweChallenges).toBe(1);
  });

  it('serves a follower stream window over the private port and rebuilds the window bytes', async () => {
    const { engine, follower } = wire();
    const file = Uint8Array.from({ length: 256 }, (_, i) => (i * 3 + 1) & 0xff);
    engine.respondReadStream = (_handle, offset, length) =>
      Promise.resolve(file.slice(offset, offset + length).buffer);

    const node = new Uint8Array(16).fill(6);
    const handle = await follower.openContentStream(node);
    const window = await follower.readStream(handle, 64, 32);
    await follower.closeStream(handle);

    expect([...new Uint8Array(window)]).toEqual([...file.slice(64, 96)]);
    // A dropped or clamped offset slices the wrong plaintext with every
    // integrity check still passing.
    expect(engine.opened).toEqual([node]);
    expect(engine.reads).toEqual([{ handle, offset: 64, length: 32 }]);
    expect(engine.closedStreams).toEqual([handle]);
  });

  it('refuses a stream handle the asking follower does not own', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    const owner = new BroadcastTransport(bus.channel(), 'owner', ports.courier('owner'));
    const other = new BroadcastTransport(bus.channel(), 'other', ports.courier('other'));
    await owner.start();
    await other.start();

    const handle = await owner.openContentStream(new Uint8Array(16));
    // A handle is a capability: the relay binds it to the tab that opened it.
    await expect(other.readStream(handle, 0, 8)).rejects.toMatchObject({
      code: 'unknownStreamHandle',
    });
    expect(engine.reads).toEqual([]);
  });

  it('rejects an in-flight stream read retryably when the leader steps down', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engineA = new FakeEngineTransport();
    engineA.respondReadStream = () => new Promise(() => undefined); // leader A never answers
    const relayA = new LeaderRelay(bus.channel(), engineA, ports.courier('leaderA'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await follower.start();

    const handle = await follower.openContentStream(new Uint8Array(16));
    const inFlight = follower.readStream(handle, 0, 8);
    await tick();
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // The next leader serves the retry, so the swap costs a retry, never a hang.
    const engineB = new FakeEngineTransport();
    engineB.respondReadStream = () => Promise.resolve(new Uint8Array([1, 2]).buffer);
    new LeaderRelay(bus.channel(), engineB, ports.courier('leaderB'));
    const reopened = await follower.openContentStream(new Uint8Array(16));
    const retried = await follower.readStream(reopened, 0, 2);
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

  it('keeps every read result off the channel: a second context sees only rendezvous traffic', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    const plaintext = Uint8Array.from({ length: 96 }, (_, i) => (i * 17 + 9) & 0xff);
    engine.respondReadStream = (_handle, offset, length) =>
      Promise.resolve(plaintext.slice(offset, offset + length).buffer);
    engine.respondSnapshot = () => Promise.resolve(emptySnapshot(new Uint8Array(16).fill(8)));
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));

    // A same-origin context that opened the engine channel and does nothing else.
    const observed: unknown[] = [];
    const eavesdropper = bus.channel();
    eavesdropper.addEventListener('message', (event) => observed.push(event.data));

    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await follower.snapshot(new Uint8Array(16));
    const handle = await follower.openContentStream(new Uint8Array(16).fill(6));
    for (let offset = 0; offset < 96; offset += 32) {
      await follower.readStream(handle, offset, 32);
    }
    await follower.closeStream(handle);
    await tick();

    // Election and rendezvous only — every read result rode the private port.
    expect(observed.length).toBeGreaterThan(0);
    expect([...new Set(observed.map((m) => (m as { type: string }).type))].sort()).toEqual([
      'cb:hello',
      'cb:leader',
      'cb:portHost',
      'cb:portWanted',
    ]);
    const serialized = JSON.stringify(observed, (_key, value: unknown) =>
      value instanceof Uint8Array ? [...value] : value
    );
    for (const byte of plaintext.slice(0, 8)) expect(serialized).not.toContain(`,${byte},`);
  });

  it('settles nothing on a port that never greeted with the active leader token', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    engine.respond = () => new Promise(() => undefined); // the real leader never answers
    engine.respondSnapshot = () => Promise.resolve(emptySnapshot(new Uint8Array(16).fill(2)));
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'), {
      portTimeoutMs: 40,
    });
    await follower.start();

    // An impostor answers the rendezvous with its own address, then forges both a
    // greeting and results. Request ids are shared with commands and writes, so a
    // follower that took an ungreeted result would settle those too.
    ports.courier('impostor').onPort((port) => {
      port.addEventListener('message', () => {
        port.postMessage({ type: 'cb:portReady', token: 'forged-token' });
        port.postMessage({ type: 'cb:portReady' });
        for (let requestId = 1; requestId <= 4; requestId += 1) {
          port.postMessage({ type: 'cb:portResult', requestId, ok: true });
        }
      });
      port.start?.();
    });
    const attacker = bus.channel();
    attacker.addEventListener('message', (event) => {
      if ((event.data as { type?: string }).type !== 'cb:portWanted') return;
      attacker.postMessage({ type: 'cb:portHost', token: 'forged-token', address: 'impostor' });
      attacker.postMessage({ type: 'cb:portHost', address: 'impostor' });
    });

    const command = follower.command({ kind: 'manualRefresh' }, []);
    let commandSettled = false;
    void command.then(
      () => (commandSettled = true),
      () => (commandSettled = true)
    );

    // The forged host is ignored, so the read reaches the real leader's engine,
    // and the forged results settled nothing on the way.
    await expect(follower.snapshot(new Uint8Array(16))).resolves.toMatchObject({
      folder: new Uint8Array(16).fill(2),
    });
    expect(commandSettled).toBe(false);
  });

  /**
   * The honest limit of the token gate: it is broadcast on the channel, so it
   * bounds accidental and passive delivery, never a same-origin context that
   * bothered to read the beacon. Recorded so the guarantee is not overstated.
   */
  it('adopts a port greeting with the real broadcast token, whoever sent it', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    new LeaderRelay(bus.channel(), new FakeEngineTransport(), ports.courier('leader'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'), {
      portTimeoutMs: 40,
    });

    // The impostor reads the leadership token off the channel and replays it.
    let stolen: string | undefined;
    const attacker = bus.channel();
    attacker.addEventListener('message', (event) => {
      const message = event.data as { type?: string; token?: string };
      if (message.type === 'cb:leader') stolen = message.token;
      if (message.type !== 'cb:portWanted') return;
      attacker.postMessage({ type: 'cb:portHost', token: stolen, address: 'impostor' });
    });
    ports.courier('impostor').onPort((port) => {
      port.addEventListener('message', () => {
        port.postMessage({ type: 'cb:portReady', token: stolen });
        port.postMessage({
          type: 'cb:portResult',
          requestId: 1,
          ok: true,
          result: emptySnapshot(new Uint8Array(16).fill(9)),
        });
      });
      port.start?.();
    });
    await follower.start();

    await expect(follower.snapshot(new Uint8Array(16))).resolves.toMatchObject({
      folder: new Uint8Array(16).fill(9),
    });
  });

  it('rejects a read whose port the leader detached under a live leadership', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await follower.snapshot(null); // brokers and adopts the port

    engine.respondSnapshot = () => new Promise(() => undefined); // never answers
    const inFlight = follower.snapshot(null);
    await tick();
    // A `cb:bye` any same-origin context can post makes the leader drop that port.
    // Without a closing notice the read would wait on a wire that is gone.
    bus.channel().postMessage({ type: 'cb:bye', clientId: 'f' });
    await expect(inFlight).rejects.toThrow(/retry/);

    // The next read re-brokers against the same live leader.
    engine.respondSnapshot = (folder) => Promise.resolve(emptySnapshot(folder ?? undefined));
    await expect(follower.snapshot(null)).resolves.toMatchObject({ staleness: 'fresh' });
  });

  it('wipes a read window nobody can receive rather than leaving the plaintext behind', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await follower.snapshot(null); // brokers and adopts the port

    const plaintext = Uint8Array.of(1, 2, 3, 4);
    let release!: () => void;
    engine.respondDownload = async () => {
      await new Promise<void>((resolve) => (release = resolve));
      return plaintext.buffer;
    };

    // Awaited only after the wipe, so the rejection is handled from the outset.
    const settled = expect(follower.download(new Uint8Array(16).fill(1))).rejects.toThrow(/retry/);
    await tick();
    // Any same-origin context can post this; the leader then drops the port the
    // window was going to be transferred down.
    bus.channel().postMessage({ type: 'cb:bye', clientId: 'f' });
    await tick();
    release();
    await settled;
    await tick();

    expect([...plaintext]).toEqual([0, 0, 0, 0]);
  });

  it('reclaims a dialed port that never named the follower behind it', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    new LeaderRelay(bus.channel(), new FakeEngineTransport(), ports.courier('leader'), {
      namingTimeoutMs: 5,
    });

    // Any same-origin context can dial the leader; one that never names itself
    // would otherwise sit in the relay for the rest of the leadership.
    const squatter = (await ports.courier('squatter').connect('leader')) as FakeChannelPort;
    await new Promise((resolve) => setTimeout(resolve, 25));

    expect(squatter.peer!.closed).toBe(true);
  });

  it('fails a read closed when no port can be brokered, never falling back to the channel', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine, unavailableCourier);
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'), {
      portTimeoutMs: 20,
    });
    await follower.start();

    await expect(follower.snapshot(new Uint8Array(16))).rejects.toThrow(/no port host/);
    expect(engine.snapshots).toEqual([]);
  });

  it('re-brokers a read port after the follower that held it left', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    const first = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await first.snapshot(null);
    first.close(); // posts `cb:bye`, so the leader reclaims that port
    await tick();

    const second = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await expect(second.snapshot(null)).resolves.toMatchObject({ staleness: 'fresh' });
    expect(engine.snapshots).toHaveLength(2);
  });

  it('rejects an in-flight read retryably when the leader steps down', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engineA = new FakeEngineTransport();
    engineA.respondSnapshot = () => new Promise(() => undefined); // leader A never answers
    const relayA = new LeaderRelay(bus.channel(), engineA, ports.courier('leaderA'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
    await follower.start();

    const inFlight = follower.snapshot(new Uint8Array(16));
    await tick();
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // A read issued with no leader parks, then resolves against the next leader.
    const queued = follower.snapshot(new Uint8Array(16).fill(4));
    const engineB = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engineB, ports.courier('leaderB'));
    await expect(queued).resolves.toMatchObject({ staleness: 'fresh' });
    expect(engineB.snapshots).toHaveLength(1);
  });

  it('notifies an adopted read port that it is closing when the leader steps down', async () => {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();
    const near = new FakeChannelPort();
    const far = new FakeChannelPort();
    near.peer = far;
    far.peer = near;

    let deliver: ((port: MessagePortLike) => void) | null = null;
    const courier: PortCourier = {
      address: () => Promise.resolve('leader'),
      connect: () => Promise.reject(new Error('unused')),
      onPort: (handler) => {
        deliver = handler;
        return () => (deliver = null);
      },
    };

    const relay = new LeaderRelay(bus.channel(), engine, courier);
    deliver!(far);
    far.receive({ type: 'cb:portHello', clientId: 'f' }); // named, so it outlives the naming timeout
    await tick();

    const seen: string[] = [];
    near.addEventListener('message', (event) => seen.push((event.data as { type: string }).type));
    relay.close();
    await tick();

    expect(seen).toContain('cb:portClosed');
  });

  it('re-arms on leadership change: an in-flight command rejects retryably, later commands await the next leader (P1-3)', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engineA = new FakeEngineTransport();
    engineA.respond = () => new Promise(() => undefined); // leader A never answers
    const relayA = new LeaderRelay(bus.channel(), engineA, ports.courier('leaderA'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
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
    new LeaderRelay(bus.channel(), engineB, ports.courier('leaderB'));
    await queued;
    expect(engineB.commands.map((c) => c.kind)).toEqual(['manualRefresh']);
  });

  it('rejects a forged response/event bearing a wrong or absent leader token (P1-4)', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    engine.respond = () => new Promise(() => undefined); // the real leader never answers
    new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    const follower = new BroadcastTransport(bus.channel(), 'f', ports.courier('f'));
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

/**
 * Drives a relay over a raw named port, without a `BroadcastTransport` in the
 * way: the test speaks the wire itself, so it can post a malformed or forged
 * step and read exactly what the relay answered.
 */
async function portBench(options: LeaderRelayOptions = {}): Promise<{
  bus: FakeBus;
  ports: FakeCourierNetwork;
  engine: FakeEngineTransport;
  relay: LeaderRelay;
  /** The relay's end: `receive` injects a follower step, `posted` records replies. */
  leaderPort: FakeChannelPort;
}> {
  const bus = new FakeBus();
  const ports = new FakeCourierNetwork();
  const engine = new FakeEngineTransport();
  const relay = new LeaderRelay(bus.channel(), engine, ports.courier('leader'), options);
  return { bus, ports, engine, relay, leaderPort: await dialLeader(ports, 'f1') };
}

/** Dials the relay a fresh named port, returning the relay's end of it. */
async function dialLeader(ports: FakeCourierNetwork, clientId: string): Promise<FakeChannelPort> {
  const dialled = (await ports.courier(clientId).connect('leader')) as FakeChannelPort;
  const leaderPort = dialled.peer!;
  leaderPort.receive({ type: 'cb:portHello', clientId });
  return leaderPort;
}

/** What the relay posted down a port, by wire type. */
function replies(port: FakeChannelPort, type: string): Array<Record<string, unknown>> {
  return (port.posted as Array<Record<string, unknown>>).filter((m) => m.type === type);
}

describe('leader relay write handles', () => {
  function bench(): {
    bus: FakeBus;
    ports: FakeCourierNetwork;
    engine: FakeEngineTransport;
    relay: LeaderRelay;
  } {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    const relay = new LeaderRelay(bus.channel(), engine, ports.courier('leader'));
    return { bus, ports, engine, relay };
  }

  const chunk = (seq: number): ArrayBuffer => Uint8Array.of(seq).buffer;
  const node = (fill: number): Uint8Array => new Uint8Array(16).fill(fill);

  it('applies pipelined chunks for one handle in send order', async () => {
    const { bus, ports, engine } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1', ports.courier('f1'));
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
    const { bus, ports, engine } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1', ports.courier('f1'));
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
    const { bus, ports, engine } = bench();
    const owner = new BroadcastTransport(bus.channel(), 'owner', ports.courier('owner'));
    const other = new BroadcastTransport(bus.channel(), 'other', ports.courier('other'));
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
    const { bus, ports, engine } = bench();
    const leaving = new BroadcastTransport(bus.channel(), 'leaving', ports.courier('leaving'));
    const staying = new BroadcastTransport(bus.channel(), 'staying', ports.courier('staying'));
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

  it('keeps serving a live follower after a cb:bye it never sent', async () => {
    const { bus, ports, engine } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1', ports.courier('f1'));
    await follower.beginWrite({ node: node(1) }, 4);

    // Any same-origin context can forge this. It costs the tab its open handles,
    // but must not refuse every handle it asks for afterwards.
    bus.channel().postMessage({ type: 'cb:bye', clientId: 'f1' });
    await tick();

    engine.writeHandle = 2n;
    await expect(follower.beginWrite({ node: node(2) }, 4)).resolves.toBe(2n);
  });

  it('releases rather than strands a handle minted for a client that left mid-mint', async () => {
    const { bus, engine, leaderPort } = await portBench();
    let releaseMint!: (handle: bigint) => void;
    engine.beginWrite = () => new Promise((resolve) => (releaseMint = resolve));

    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    await tick();
    // Any same-origin context can post this; the mint is still in flight, so the
    // release sweep runs against a table the handle has not landed in yet.
    bus.channel().postMessage({ type: 'cb:bye', clientId: 'f1' });
    await tick();
    releaseMint(7n);
    await tick();

    expect(engine.aborts).toEqual([7n]);
    // The departed client's port went with it, so nothing was answered down it.
    expect(replies(leaderPort, 'cb:portResult')).toEqual([]);
  });

  it('releases both planes of a handle minted for a follower that re-brokered mid-mint', async () => {
    const { engine, ports, leaderPort } = await portBench();
    let mintWrite!: (handle: bigint) => void;
    let mintStream!: (handle: bigint) => void;
    engine.beginWrite = () => new Promise((resolve) => (mintWrite = resolve));
    engine.openContentStream = () => new Promise((resolve) => (mintStream = resolve));

    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 2,
      stream: { kind: 'openContentStream', node: node(2) },
    });
    await tick();

    // The same live tab re-brokers — its port timed out, or the sweep took it —
    // so neither handle can ever reach the entry it was asked for.
    const rebrokered = await dialLeader(ports, 'f1');
    await tick();
    mintWrite(7n);
    mintStream(8n);
    await tick();

    // The staging reservation and the pinned content version, with the key
    // resident alongside it, are both released rather than stranded.
    expect(engine.aborts).toEqual([7n]);
    expect(engine.closedStreams).toEqual([8n]);
    expect(replies(leaderPort, 'cb:portResult')).toEqual([]);

    // The tab is still served on the port it now holds.
    engine.openContentStream = () => Promise.resolve(9n);
    rebrokered.receive({
      type: 'cb:portStream',
      requestId: 1,
      stream: { kind: 'openContentStream', node: node(3) },
    });
    await tick();
    expect(replies(rebrokered, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 1, ok: true, result: 9n })
    );
  });

  it('wipes a transferred chunk it drops for a malformed request', async () => {
    const { engine, leaderPort } = await portBench();
    const plaintext = Uint8Array.of(5, 6, 7, 8);

    // No `requestId`, so nothing can be answered — but the chunk already crossed
    // by transfer, leaving the relay its last owner.
    leaderPort.receive({
      type: 'cb:portWrite',
      write: { kind: 'pushChunk', handle: 1n, chunk: plaintext.buffer },
    });
    await tick();

    expect([...plaintext]).toEqual([0, 0, 0, 0]);
    expect(engine.chunks).toEqual([]);
  });

  it('wipes an upload chunk it refuses rather than leaving the plaintext behind', async () => {
    const { engine, leaderPort } = await portBench();
    const plaintext = Uint8Array.of(9, 8, 7, 6);

    // A step on a handle this port never opened: the chunk was already
    // transferred into the leader, so the relay is its last owner.
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'pushChunk', handle: 4n, chunk: plaintext.buffer },
    });
    await tick();

    expect([...plaintext]).toEqual([0, 0, 0, 0]);
    expect(engine.chunks).toEqual([]);
  });

  it('wipes an upload chunk the worker never took, having rejected before the post', async () => {
    const { engine, leaderPort } = await portBench();
    engine.writeHandle = 5n;
    // A dead worker rejects without ever transferring the buffer on, so the
    // relay is still holding the plaintext when the step settles.
    engine.pushChunk = () => Promise.reject(new Error('engine transport closed'));
    const plaintext = Uint8Array.of(4, 3, 2, 1);

    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    await tick();
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 2,
      write: { kind: 'pushChunk', handle: 5n, chunk: plaintext.buffer },
    });
    await tick();

    expect(replies(leaderPort, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 2, ok: false })
    );
    expect([...plaintext]).toEqual([0, 0, 0, 0]);
  });

  it('releases every open handle when the leader steps down', async () => {
    const { bus, ports, engine, relay } = bench();
    const follower = new BroadcastTransport(bus.channel(), 'f1', ports.courier('f1'));
    const handle = await follower.beginWrite({ node: node(5) }, 4);

    relay.close();
    await tick();

    expect(engine.aborts).toEqual([handle]);
  });
});

describe('leader relay follower liveness', () => {
  const node = (fill: number): Uint8Array => new Uint8Array(16).fill(fill);
  // Two sweeps' worth of silence at `livenessMisses: 1`.
  const REAPED = 30;

  it('reclaims the handles and port of a follower that died without a cb:bye', async () => {
    const { engine, leaderPort } = await portBench({ livenessIntervalMs: 5, livenessMisses: 1 });
    engine.writeHandle = 3n;
    engine.streamHandle = 4n;
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 2,
      stream: { kind: 'openContentStream', node: node(2) },
    });
    await tick();

    // The tab is gone: it answers no probe and sends no farewell.
    await after(REAPED);

    // The pinned content version — and the key resident with it — is released,
    // as is the write handle's staging reservation and the port itself.
    expect(engine.closedStreams).toEqual([4n]);
    expect(engine.aborts).toEqual([3n]);
    expect(replies(leaderPort, 'cb:portClosed')).toHaveLength(1);
    expect(leaderPort.closed).toBe(true);
  });

  it('never reclaims a live but quiet follower that answers the probe', async () => {
    const { engine, leaderPort } = await portBench({ livenessIntervalMs: 5, livenessMisses: 1 });
    engine.streamHandle = 4n;
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 1,
      stream: { kind: 'openContentStream', node: node(2) },
    });
    await tick();

    // A tab mid-playback issues no new request for a while, but answers every
    // probe from its message handler — tearing it down would drop the playback.
    leaderPort.peer!.addEventListener('message', (event) => {
      if ((event.data as { type?: string }).type === 'cb:portPing') {
        leaderPort.receive({ type: 'cb:portPong' });
      }
    });
    await after(REAPED);

    expect(engine.closedStreams).toEqual([]);
    expect(leaderPort.closed).toBe(false);
    // The stream it opened still serves it.
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 2,
      stream: { kind: 'readStream', handle: 4n, offset: 0, length: 8 },
    });
    await tick();
    expect(engine.reads).toEqual([{ handle: 4n, offset: 0, length: 8 }]);
  });

  it('never probes a port that has not named the follower behind it', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    new LeaderRelay(bus.channel(), new FakeEngineTransport(), ports.courier('leader'), {
      namingTimeoutMs: 40,
      livenessIntervalMs: 5,
      livenessMisses: 1,
    });

    // The naming timeout owns an unnamed port; the sweep must leave it alone
    // rather than reclaim it under a `clientId` it does not have.
    const squatter = (await ports.courier('squatter').connect('leader')) as FakeChannelPort;
    await after(REAPED);
    expect(squatter.peer!.posted).toEqual([]);
    expect(squatter.peer!.closed).toBe(false);
  });

  it('stops probing once the leader steps down', async () => {
    const { relay, leaderPort } = await portBench({ livenessIntervalMs: 5, livenessMisses: 4 });
    relay.close();
    await after(REAPED);

    expect(replies(leaderPort, 'cb:portPing')).toEqual([]);
  });
});
