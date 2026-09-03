import { describe, expect, it } from 'vitest';

import { presenceLockName } from './broadcast.js';
import {
  BroadcastTransport,
  EngineHeldElsewhereError,
  type BroadcastTransportOptions,
} from './broadcastTransport.js';
import { EngineRequestError } from './correlatedTransport.js';
import { LeaderRelay, type LeaderRelayOptions } from './leaderRelay.js';
import { unavailableCourier } from './portCourier.js';
import type { MessagePortLike, PortCourier } from './portRelay.js';
import {
  byoSettings,
  emptySnapshot,
  FakeBus,
  FakeChannelPort,
  FakeCourierNetwork,
  FakeEngineTransport,
  collect,
  hex,
  TEST_ACCOUNT_ID,
} from './testkit.js';
import type { EngineTransport } from './transport.js';
import type {
  BinDescriptor,
  CommandDescriptor,
  EventDescriptor,
  OpenedStream,
  SnapshotDescriptor,
} from './worker/protocol.js';

const after = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const tick = (): Promise<void> => after(0);

function relayOn(
  bus: FakeBus,
  transport: EngineTransport,
  courier: PortCourier,
  options?: LeaderRelayOptions
): LeaderRelay {
  return new LeaderRelay(bus.channel(), transport, courier, bus.locks, options);
}

function followerOn(
  bus: FakeBus,
  clientId: string,
  courier: PortCourier,
  options?: BroadcastTransportOptions
): BroadcastTransport {
  return new BroadcastTransport(bus.channel(), clientId, courier, bus.locks, options);
}

/**
 * Starts a follower against a leadership whose engine holds the same account —
 * the only pairing a leader adopts a port for. The keyless transport is handed
 * no secret bytes; the buffer only satisfies the `EngineTransport` signature.
 */
function startFollower(relay: LeaderRelay, follower: BroadcastTransport): Promise<void> {
  relay.serves(TEST_ACCOUNT_ID);
  return follower.start(new ArrayBuffer(0), TEST_ACCOUNT_ID);
}

/**
 * Holds a tab's presence lock as a live tab does — from before it greets until
 * the returned `kill` stands in for the tab dying.
 */
function livePresence(bus: FakeBus, clientId: string): () => void {
  let release: (() => void) | null = null;
  void bus.locks.request(
    presenceLockName(clientId),
    { mode: 'exclusive' },
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
      })
  );
  // Killing before the grant would stage no death at all, and the test asserting
  // the reclaim would pass on a presence that was never held.
  return () => {
    if (!release) throw new Error(`presence for ${clientId} was never granted`);
    release();
  };
}

/** Settles a tab's presence request in failure, as a stolen lock does. */
function losePresence(bus: FakeBus, clientId: string): void {
  bus.locks.fail(presenceLockName(clientId), new Error('presence lock stolen'));
}

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
  const relay = relayOn(bus, engine, ports.courier('leader'));
  const follower = followerOn(bus, 'follower-1', ports.courier('follower-1'));
  return { bus, ports, engine, relay, follower };
}

describe('one engine per origin is one account per origin', () => {
  const OTHER_ACCOUNT_ID = 'acct02';

  it('refuses a follower on an account the leader engine does not hold, naming the holder', async () => {
    const { engine, relay, follower } = wire();
    relay.serves(TEST_ACCOUNT_ID);

    const refusal = await follower.start(new ArrayBuffer(0), OTHER_ACCOUNT_ID).then(
      () => null,
      (error: unknown) => error
    );

    expect(refusal).toBeInstanceOf(EngineHeldElsewhereError);
    expect((refusal as EngineHeldElsewhereError).heldBy).toBe(TEST_ACCOUNT_ID);
    // Transport-level: the engine refused nothing, so it lends no code.
    expect((refusal as EngineHeldElsewhereError).code).toBeUndefined();
    // A refused start reached the leader's engine for nothing at all.
    expect(engine.commands).toEqual([]);
    expect(engine.snapshots).toEqual([]);
  });

  it('serves a refused follower nothing afterwards, so no snapshot carries the other vault', async () => {
    const { engine, relay, follower } = wire();
    engine.respondSnapshot = () => Promise.resolve(emptySnapshot(new Uint8Array(16).fill(7)));
    relay.serves(TEST_ACCOUNT_ID);
    await expect(follower.start(new ArrayBuffer(0), OTHER_ACCOUNT_ID)).rejects.toBeInstanceOf(
      EngineHeldElsewhereError
    );

    await expect(follower.snapshot(null)).rejects.toBeInstanceOf(EngineHeldElsewhereError);
    await expect(follower.command({ kind: 'manualRefresh' })).rejects.toBeInstanceOf(
      EngineHeldElsewhereError
    );
    expect(engine.snapshots).toEqual([]);
    expect(engine.commands).toEqual([]);
  });

  it('refuses a follower when the tab hosting the engine has started none', async () => {
    const { follower } = wire(); // the relay never named an account

    const refusal = await follower.start(new ArrayBuffer(0), TEST_ACCOUNT_ID).then(
      () => null,
      (error: unknown) => error
    );

    expect(refusal).toBeInstanceOf(EngineHeldElsewhereError);
    expect((refusal as EngineHeldElsewhereError).heldBy).toBeNull();
  });

  it('serves the follower once the leader engine holds the same account', async () => {
    const { engine, relay, follower } = wire();
    await startFollower(relay, follower);

    await expect(follower.snapshot(null)).resolves.toMatchObject({ staleness: 'fresh' });
    expect(engine.snapshots).toEqual([null]);
  });

  it('re-dials under the account a later start names rather than reusing the adopted port', async () => {
    const { relay, follower } = wire();
    await startFollower(relay, follower);

    // The same tab, now starting for a second account: the port it holds was
    // adopted for the first, and must not carry the second.
    await expect(follower.start(new ArrayBuffer(0), OTHER_ACCOUNT_ID)).rejects.toBeInstanceOf(
      EngineHeldElsewhereError
    );
  });

  it('retires a port adopted before the leader engine named an account', async () => {
    const { engine, relay, follower } = wire();
    // Adopted while neither side had an account, which is the one pairing that
    // matches without naming one.
    await follower.snapshot(null);
    expect(engine.snapshots).toHaveLength(1);

    relay.serves(TEST_ACCOUNT_ID);
    await tick();

    await expect(follower.snapshot(null)).rejects.toBeInstanceOf(EngineHeldElsewhereError);
    expect(engine.snapshots).toHaveLength(1);
  });

  it('releases the handles of a follower the leader engine stops holding the account for', async () => {
    const { engine, relay, follower } = wire();
    await startFollower(relay, follower);
    engine.writeHandle = 7n;
    engine.streamHandle = 9n;
    const write = await follower.beginWrite({ node: new Uint8Array(16).fill(1) }, 4);
    const { handle: stream } = await follower.openContentStream(new Uint8Array(16).fill(2));

    relay.serves(OTHER_ACCOUNT_ID);
    await tick();

    // A retained write keeps its staging reservation for the rest of the
    // session, and a retained stream pins a content version and its key.
    expect(engine.aborts).toEqual([write]);
    expect(engine.closedStreams).toEqual([stream]);
  });

  it('names no account on the origin-wide channel, only on the private port', async () => {
    const { bus, ports, relay, follower } = wire();
    const bystander: unknown[] = [];
    const channel = bus.channel();
    channel.addEventListener('message', (event) => bystander.push(event.data));
    await startFollower(relay, follower);
    await tick();

    // The account rides the port (a hello and, on a refusal, the holder's name);
    // a same-origin context that merely opened the channel learns neither.
    expect(collect(bystander).text).not.toContain(TEST_ACCOUNT_ID);
    expect(collect(ports.messages).text).toContain(TEST_ACCOUNT_ID);
  });
});

describe('a follower no leadership serves', () => {
  const OTHER_ACCOUNT_ID = 'acct03';

  it('fails a read at the brokerage deadline when no tab of the origin leads it', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const follower = followerOn(bus, 'follower-1', ports.courier('follower-1'), {
      portTimeoutMs: 20,
    });

    // No relay ever beacons: an origin every tab has retired from leading. The
    // read must fail rather than park the tab for the rest of its life.
    await expect(follower.snapshot(null)).rejects.toThrow('no tab of this origin leads it');
    follower.close();
  });

  it('reports a refusal naming another account, so its owner can end the session', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    const relay = relayOn(bus, engine, ports.courier('leader'));
    const heldElsewhere: string[] = [];
    const follower = followerOn(bus, 'follower-1', ports.courier('follower-1'), {
      onHeldElsewhere: (heldBy) => heldElsewhere.push(heldBy),
    });
    await startFollower(relay, follower);

    relay.serves(OTHER_ACCOUNT_ID);
    await tick();
    await expect(follower.snapshot(null)).rejects.toBeInstanceOf(EngineHeldElsewhereError);

    // Every re-brokerage reports it, so the owner sees the same verdict once or
    // many times — never a different account.
    expect([...new Set(heldElsewhere)]).toEqual([OTHER_ACCOUNT_ID]);
    follower.close();
    relay.close();
  });

  it('reports nothing when the leadership merely hosts no engine yet', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    const relay = relayOn(bus, engine, ports.courier('leader'));
    const heldElsewhere: string[] = [];
    const follower = followerOn(bus, 'follower-1', ports.courier('follower-1'), {
      onHeldElsewhere: (heldBy) => heldElsewhere.push(heldBy),
    });

    // An engine-less leader steps aside for a tab with a session, so this
    // refusal is a wait, not a verdict on the account.
    await expect(follower.start(new ArrayBuffer(0), TEST_ACCOUNT_ID)).rejects.toBeInstanceOf(
      EngineHeldElsewhereError
    );

    expect(heldElsewhere).toEqual([]);
    follower.close();
    relay.close();
  });
});

describe('broadcast transport ↔ leader relay', () => {
  it('routes a follower command to the leader engine and correlates the response', async () => {
    const { engine, follower } = wire();
    await follower.command({ kind: 'delete', node: new Uint8Array(16) });
    expect(engine.commands.map((c) => c.kind)).toEqual(['delete']);
  });

  it('carries a command outcome back over the private port', async () => {
    const { engine, follower } = wire();
    const identityPublicKey = new Uint8Array(33).fill(6);
    const encPublicKey = new Uint8Array(32).fill(7);
    engine.respond = () =>
      Promise.resolve({ kind: 'contactImported', identityPublicKey, encPublicKey });

    await expect(
      follower.command({ kind: 'importContact', contactCode: new Uint8Array([1, 2]) })
    ).resolves.toEqual({ kind: 'contactImported', identityPublicKey, encPublicKey });
  });

  it('takes no secret: start only brokers the port, wire carries only the rendezvous', async () => {
    const bus = new FakeBus();
    const posted: unknown[] = [];
    const ports = new FakeCourierNetwork();
    const leaderChannel = bus.channel();
    leaderChannel.addEventListener('message', (event) => posted.push(event.data));
    // A relay makes a leader "present" so start resolves.
    const relay = new LeaderRelay(
      leaderChannel,
      new FakeEngineTransport(),
      ports.courier('leader'),
      bus.locks
    );
    const follower = followerOn(bus, 'f', ports.courier('f'));

    // The keyless follower transport receives no secret bytes: the leader's
    // engine already owns key derivation, and `start` only brokers the port.
    await startFollower(relay, follower);
    await tick(); // let the read-port rendezvous land on the wire too

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
    const relay = relayOn(bus, engine, ports.courier('leader'));

    // Capture both leader→follower wires: the channel (events) and the port.
    const leaderPosts: unknown[] = [];
    const spy = bus.channel();
    spy.addEventListener('message', (event) => leaderPosts.push(event.data));

    const follower = followerOn(bus, 'f', ports.courier('f'));
    await startFollower(relay, follower);

    // A command whose engine handling rejects: the relay forwards the failure as
    // a `cb:portResult` error string — a real leak vector for secret bytes
    // bleeding into an error message. A hygienic engine rejects generically.
    engine.respond = () => Promise.reject(new Error('command failed'));
    await follower.command({ kind: 'manualRefresh' }).catch(() => undefined);

    // Plus every EventDescriptor variant, including the byte- and string-bearing
    // ones the relay forwards verbatim.
    engine.respond = () => Promise.resolve({ kind: 'done' });
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

  it('wipes an upload chunk it never gets onto a port', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    relayOn(bus, new FakeEngineTransport(), ports.courier('leader'));
    // No port to move the plaintext out over, so this tab stays its owner.
    const follower = followerOn(bus, 'follower-1', unavailableCourier);
    const plaintext = Uint8Array.of(4, 3, 2, 1);

    await expect(follower.pushChunk(1n, plaintext.buffer as ArrayBuffer)).rejects.toThrow();

    expect([...plaintext]).toEqual([0, 0, 0, 0]);
  });

  it('moves a command bearer onto the port rather than cloning it to the leader', async () => {
    const { ports, engine, relay, follower } = wire();
    await startFollower(relay, follower);
    const accessToken = new TextEncoder().encode('s3cret').buffer as ArrayBuffer;
    const answered: Uint8Array[] = [];
    engine.respond = (command) => {
      answered.push(bearerOf(command));
      return Promise.resolve({ kind: 'done' });
    };

    await follower.command(settingsSaveOf(accessToken));

    // The credential leaves this tab's heap outright and arrives intact two
    // hops later, so no same-origin context between them holds a copy.
    expect(accessToken.byteLength).toBe(0);
    expect(ports.transfers.some((list) => list[0] === accessToken)).toBe(true);
    expect(bearerOf(engine.commands[0])).toEqual(new TextEncoder().encode('s3cret'));
    // The engine acts on the bearer it was delivered, not on a spent descriptor.
    expect(answered).toEqual([new TextEncoder().encode('s3cret')]);
  });

  it('wipes a command bearer it never gets onto a port', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    relayOn(bus, new FakeEngineTransport(), ports.courier('leader'));
    // No port to move the credential out over, so this tab stays its owner.
    const follower = followerOn(bus, 'follower-1', unavailableCourier);
    const bearer = new TextEncoder().encode('s3cret');

    await expect(follower.command(settingsSaveOf(bearer.buffer as ArrayBuffer))).rejects.toThrow();

    expect([...bearer]).toEqual(new Array(bearer.length).fill(0));
  });

  it('keeps upload plaintext and command arguments off the channel', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));

    // A same-origin context that opened the engine channel and does nothing else.
    const observed: unknown[] = [];
    const eavesdropper = bus.channel();
    eavesdropper.addEventListener('message', (event) => observed.push(event.data));

    const follower = followerOn(bus, 'f', ports.courier('f'));
    const plaintext = Uint8Array.from({ length: 64 }, (_, i) => (i * 29 + 13) & 0xff);
    const handle = await follower.beginWrite(
      { parent: new Uint8Array(16), name: 'payslip.pdf' },
      64
    );
    await follower.pushChunk(handle, plaintext.buffer.slice(0));
    await follower.commitWrite(handle);
    await follower.command({ kind: 'rename', node: new Uint8Array(16), newName: 'tax-return.pdf' });
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
    const { engine, follower, relay } = wire();
    const received: EventDescriptor[] = [];
    follower.subscribe((event) => received.push(event));
    // The event stream rides the adopted port, which `start` brokers.
    await startFollower(relay, follower);
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
    const inFlight = follower.command({ kind: 'manualRefresh' });
    await tick();
    follower.close();

    await expect(inFlight).rejects.toThrow('closed');
    await expect(follower.command({ kind: 'manualRefresh' })).rejects.toThrow('closed');
  });

  it('folds follower focus into the union and forces a refresh', async () => {
    const { engine, follower } = wire();
    const before = engine.commands.length;
    follower.reportFocus(new Uint8Array([0xaa, 0xbb]));
    await tick();

    const forced = engine.commands.slice(before).filter((c) => c.kind === 'manualRefresh');
    expect(forced.length).toBe(1);
  });

  it('collapses a burst of union changes onto one trailing pass', async () => {
    const { engine, follower, relay } = wire();
    let settle = (): void => undefined;
    engine.respond = () => new Promise((resolve) => (settle = () => resolve({ kind: 'done' })));
    const forced = (): number => engine.commands.filter((c) => c.kind === 'manualRefresh').length;

    relay.reportLocalFocus('leader', new Uint8Array([1]));
    await tick();
    expect(forced()).toBe(1);

    // Three more union changes while that pass is still running must not stack
    // three more passes behind it.
    follower.reportFocus(new Uint8Array([2]));
    await tick();
    relay.reportLocalFocus('leader', new Uint8Array([3]));
    await tick();
    follower.reportFocus(new Uint8Array([4]));
    await tick();
    expect(forced()).toBe(1);

    engine.respond = () => Promise.resolve({ kind: 'done' });
    settle();
    await tick();
    expect(forced()).toBe(2);
  });

  it('drops the trailing pass a step-down overtook', async () => {
    const { engine, follower, relay } = wire();
    let settle = (): void => undefined;
    engine.respond = () => new Promise((resolve) => (settle = () => resolve({ kind: 'done' })));
    const forced = (): number => engine.commands.filter((c) => c.kind === 'manualRefresh').length;

    relay.reportLocalFocus('leader', new Uint8Array([1]));
    await tick();
    follower.reportFocus(new Uint8Array([2])); // arms a trailing pass behind it
    await tick();
    expect(forced()).toBe(1);

    relay.close();
    engine.respond = () => Promise.resolve({ kind: 'done' });
    settle();
    await tick();

    expect(forced()).toBe(1);
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
          contentCid: new Uint8Array([0xc1, 0xd0]),
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

  it('round-trips a follower bin read through the leader engine', async () => {
    const { engine, follower } = wire();
    const view: BinDescriptor = {
      entries: [
        {
          node: new Uint8Array(16).fill(4),
          kind: 'file',
          originParent: new Uint8Array(16).fill(1),
          originName: 'notes.txt',
          originFolder: { kind: 'root' },
          deletedAt: 1_800_000_000_000n,
          scope: new Uint8Array(16).fill(2),
        },
      ],
      origin: 'stale',
    };
    engine.respondBin = () => Promise.resolve(view);

    // Structured clone across the bus must preserve bytes and bigints intact.
    await expect(follower.bin()).resolves.toEqual(view);
    expect(engine.binReads).toBe(1);
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

    await expect(follower.siweChallenge('link')).resolves.toBe('leaderNonce12345');
    expect(engine.siweChallenges).toBe(1);
    expect(engine.siweChallengeIntents).toEqual(['link']);
  });

  it('serves the three follower device reads off the leader engine', async () => {
    const { engine, follower } = wire();
    const row = {
      id: '7c1e-uuid',
      publicKey: 'ed25519hex',
      label: null,
      createdAt: '2026-08-27T10:00:00.000Z',
      lastSeenAt: '2026-08-27T11:00:00.000Z',
    };
    engine.respondDevices = () => Promise.resolve([row]);
    engine.respondRegistrationChallenge = () => Promise.resolve(Uint8Array.of(9, 9));

    await expect(follower.devices()).resolves.toEqual([row]);
    await expect(follower.pendingApprovals()).resolves.toEqual([]);
    await expect(follower.deviceRegistrationChallenge('ed25519hex')).resolves.toEqual(
      Uint8Array.of(9, 9)
    );

    expect(engine.deviceReads).toBe(1);
    expect(engine.pendingApprovalReads).toBe(1);
    expect(engine.registrationChallenges).toEqual(['ed25519hex']);
  });

  it('serves a follower rendezvous step off the leader engine, step intact', async () => {
    const { engine, follower } = wire();
    const scalar = new Uint8Array(32).fill(5);
    // The step the leader realm holds: its own clone, not the caller's buffer.
    let relayHeld: Uint8Array | null = null;
    engine.respondRendezvous = (step) => {
      relayHeld = step.kind === 'open' ? step.scalar : null;
      return Promise.resolve({
        kind: 'opened',
        ephemeralPublicKey: '02beef',
        requestPayload: Uint8Array.of(1, 2),
        comparisonValue: '482913 205776 640118',
      });
    };

    await expect(
      follower.deviceRendezvous({ kind: 'open', devicePublicKey: 'ed25519hex', scalar })
    ).resolves.toEqual({
      kind: 'opened',
      ephemeralPublicKey: '02beef',
      requestPayload: Uint8Array.of(1, 2),
      comparisonValue: '482913 205776 640118',
    });
    // Snapshotted at the call, so the erase below cannot rewrite the evidence.
    expect(engine.rendezvousSteps).toEqual([
      { kind: 'open', devicePublicKey: 'ed25519hex', scalar: new Uint8Array(32).fill(5) },
    ]);
    // An `open` step's scalar stays the caller's, so nothing detaches the copy
    // the leader realm holds: the relay erases that copy once the step has run.
    expect(relayHeld).toEqual(new Uint8Array(32));
    // The caller's own buffer is untouched — it opens the sealed factor later.
    expect(scalar).toEqual(new Uint8Array(32).fill(5));
  });

  it('moves an opened factor key to the follower rather than leaving the leader a copy', async () => {
    const { ports, engine, follower } = wire();
    const factorKey = new Uint8Array(32).fill(0x7c);
    const backing = factorKey.buffer;
    engine.respondRendezvous = () => Promise.resolve({ kind: 'factor', factorKey });

    const result = await follower.deviceRendezvous({
      kind: 'openFactor',
      sealedFactor: 'c2VhbA==',
      requestId: 'req-1',
      requesterDevicePublicKey: 'reqhex',
      responderDevicePublicKey: 'apprhex',
      responseSignature: 'sighex',
      scalar: new Uint8Array(32).fill(5),
    });

    expect(result.kind).toBe('factor');
    // The key is the account's; a clone would leave the leader realm holding it
    // for the life of the tab (AGENTS.md 7). A transferred buffer is detached,
    // so the leader has nothing left to read.
    expect(ports.transfers.some((list) => list.includes(backing))).toBe(true);
    expect(backing.byteLength).toBe(0);
  });

  it('serves a follower stream window over the private port and rebuilds the window bytes', async () => {
    const { engine, follower } = wire();
    const file = Uint8Array.from({ length: 256 }, (_, i) => (i * 3 + 1) & 0xff);
    engine.respondReadStream = (_handle, offset, length) =>
      Promise.resolve(file.slice(offset, offset + length).buffer);

    const node = new Uint8Array(16).fill(6);
    const { handle } = await follower.openContentStream(node);
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
    const relay = relayOn(bus, engine, ports.courier('leader'));
    const owner = followerOn(bus, 'owner', ports.courier('owner'));
    const other = followerOn(bus, 'other', ports.courier('other'));
    await startFollower(relay, owner);
    await startFollower(relay, other);

    const { handle } = await owner.openContentStream(new Uint8Array(16));
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
    const relayA = relayOn(bus, engineA, ports.courier('leaderA'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    await startFollower(relayA, follower);

    const { handle } = await follower.openContentStream(new Uint8Array(16));
    const inFlight = follower.readStream(handle, 0, 8);
    await tick();
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // The next leader serves the retry, so the swap costs a retry, never a hang.
    const engineB = new FakeEngineTransport();
    engineB.respondReadStream = () => Promise.resolve(new Uint8Array([1, 2]).buffer);
    relayOn(bus, engineB, ports.courier('leaderB')).serves(TEST_ACCOUNT_ID);
    const { handle: reopened } = await follower.openContentStream(new Uint8Array(16));
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
    relayOn(bus, engine, ports.courier('leader'));

    // A same-origin context that opened the engine channel and does nothing else.
    const observed: unknown[] = [];
    const eavesdropper = bus.channel();
    eavesdropper.addEventListener('message', (event) => observed.push(event.data));

    const follower = followerOn(bus, 'f', ports.courier('f'));
    await follower.snapshot(new Uint8Array(16));
    const { handle } = await follower.openContentStream(new Uint8Array(16).fill(6));
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
    const relay = relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'), {
      portTimeoutMs: 40,
    });
    await startFollower(relay, follower);

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

    const command = follower.command({ kind: 'manualRefresh' });
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
    const relay = relayOn(bus, new FakeEngineTransport(), ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'), {
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
    await startFollower(relay, follower);

    await expect(follower.snapshot(new Uint8Array(16))).resolves.toMatchObject({
      folder: new Uint8Array(16).fill(9),
    });
  });

  it('rejects a read whose port the leader detached under a live leadership', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    await follower.snapshot(null); // brokers and adopts the port

    engine.respondSnapshot = () => new Promise(() => undefined); // never answers
    const inFlight = follower.snapshot(null);
    await tick();
    // The tab re-brokers, so the leader retires the port this read is parked on.
    // Without a closing notice the read would wait on a wire that is gone.
    await dialLeader(ports, 'f');
    await expect(inFlight).rejects.toThrow(/retry/);

    // The next read re-brokers against the same live leader.
    engine.respondSnapshot = (folder) => Promise.resolve(emptySnapshot(folder ?? undefined));
    await expect(follower.snapshot(null)).resolves.toMatchObject({ staleness: 'fresh' });
  });

  it('wipes a read window nobody can receive rather than leaving the plaintext behind', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
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
    // The tab's presence ends mid-read, so the leader drops the port the window
    // was going to be transferred down.
    losePresence(bus, 'f');
    await tick();
    release();
    await settled;
    await tick();

    expect([...plaintext]).toEqual([0, 0, 0, 0]);
  });

  it('reclaims a dialed port that never named the follower behind it', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    relayOn(bus, new FakeEngineTransport(), ports.courier('leader'), {
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
    const relay = relayOn(bus, engine, unavailableCourier);
    const follower = followerOn(bus, 'f', ports.courier('f'), {
      portTimeoutMs: 20,
    });

    // No port means no adoption, so the start that brokers it fails closed too.
    await expect(startFollower(relay, follower)).rejects.toThrow(/no port host/);
    await expect(follower.snapshot(new Uint8Array(16))).rejects.toThrow(/no port host/);
    expect(engine.snapshots).toEqual([]);
  });

  it('re-brokers a read port after the follower that held it left', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));
    const first = followerOn(bus, 'f', ports.courier('f'));
    await first.snapshot(null);
    first.close(); // releases its presence, so the leader reclaims that port
    await tick();

    const second = followerOn(bus, 'f', ports.courier('f'));
    await expect(second.snapshot(null)).resolves.toMatchObject({ staleness: 'fresh' });
    expect(engine.snapshots).toHaveLength(2);
  });

  it('rejects an in-flight read retryably when the leader steps down', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engineA = new FakeEngineTransport();
    engineA.respondSnapshot = () => new Promise(() => undefined); // leader A never answers
    const relayA = relayOn(bus, engineA, ports.courier('leaderA'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    await startFollower(relayA, follower);

    const inFlight = follower.snapshot(new Uint8Array(16));
    await tick();
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // A read issued with no leader parks, then resolves against the next leader.
    const queued = follower.snapshot(new Uint8Array(16).fill(4));
    const engineB = new FakeEngineTransport();
    relayOn(bus, engineB, ports.courier('leaderB')).serves(TEST_ACCOUNT_ID);
    await expect(queued).resolves.toMatchObject({ staleness: 'fresh' });
    expect(engineB.snapshots).toHaveLength(1);
  });

  it('rejects in-flight work retryably when the tab forgets the account it greeted with', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    engine.respondSnapshot = () => new Promise(() => undefined); // the leader never answers
    const relay = relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    await startFollower(relay, follower);

    const inFlight = follower.snapshot(new Uint8Array(16));
    await tick();
    // The port is closed at this end, so no notice from the leader can settle
    // what was riding it.
    follower.forgetAccount();

    await expect(inFlight).rejects.toThrow(/retry/);
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

    const relay = relayOn(bus, engine, courier);
    livePresence(bus, 'f');
    await tick();
    deliver!(far);
    // Named for an accountless leadership, so it outlives the naming timeout.
    far.receive({ type: 'cb:portHello', clientId: 'f', accountId: null });
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
    const relayA = relayOn(bus, engineA, ports.courier('leaderA'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    await startFollower(relayA, follower); // leader A present

    const inFlight = follower.command({ kind: 'manualRefresh' });
    await tick();

    // Leader A steps down: the in-flight command rejects retryably, never hangs.
    relayA.close();
    await expect(inFlight).rejects.toThrow(/retry/);

    // A command issued while no leader is present parks on the re-armed gate.
    const queued = follower.command({ kind: 'manualRefresh' });
    let settled = false;
    void queued.then(
      () => (settled = true),
      () => (settled = true)
    );
    await tick();
    expect(settled).toBe(false);

    // A fresh leader is elected → the queued command resolves against it.
    const engineB = new FakeEngineTransport();
    relayOn(bus, engineB, ports.courier('leaderB')).serves(TEST_ACCOUNT_ID);
    await queued;
    expect(engineB.commands.map((c) => c.kind)).toEqual(['manualRefresh']);
  });

  it('holds its presence before it greets, so the leader never watches a free name', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    // Something else holds this tab's presence name, so its grant is delayed —
    // as a contended or merely slow grant would be in a real browser.
    const squatter = livePresence(bus, 'f');
    await tick();
    relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'), { portTimeoutMs: 200 });

    const read = follower.snapshot(null);
    await after(20);
    // Greeting here would have the leader watch a name this tab does not hold,
    // and be granted at once against a live tab.
    expect(engine.snapshots).toEqual([]);

    squatter();
    await expect(read).resolves.toMatchObject({ staleness: 'fresh' });
  });

  it('fans engine events over the private port, putting no descriptor on the channel', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));
    // A same-origin context that drives no engine and only opened the channel.
    const overheard: unknown[] = [];
    bus.channel().addEventListener('message', (event) => overheard.push(event.data));

    const follower = followerOn(bus, 'f', ports.courier('f'));
    const events: EventDescriptor[] = [];
    follower.subscribe((event) => events.push(event));
    // A full write cycle, so the channel sees every rendezvous a real one does.
    const handle = await follower.beginWrite({ node: new Uint8Array(16).fill(1) }, 1);
    await follower.pushChunk(handle, Uint8Array.of(7).buffer);
    await follower.commitWrite(handle);

    // One of every variant, each field distinctive, so the scan below covers the
    // whole union rather than the two variants that happen to carry bytes.
    const node = new Uint8Array(16).fill(0xa7);
    const ipnsName = Uint8Array.of(0xbe, 0xef, 0xca, 0xfe);
    const emitted: EventDescriptor[] = [
      { kind: 'snapshotUpdated' },
      { kind: 'stalenessChanged', staleness: 'reconciling' },
      { kind: 'withheldUpdateEscalation', ipnsName },
      { kind: 'deadLetter', opId: 606060n, reason: 'undecodable' },
      { kind: 'attributableAbuse', description: 'abuse-707070' },
      { kind: 'renewalFailed', routingKey: 'k51-routing-key', detail: 'no peers' },
      {
        kind: 'opProgress',
        opId: 424242n,
        node,
        phase: 'uploadProgress',
        blocksConfirmed: 30003,
        blocksTotal: 90009,
        error: null,
      },
    ];
    for (const event of emitted) engine.emit(event);
    await tick();

    // The follower still sees the whole stream, in emission order.
    expect(events).toEqual(emitted);

    // The bystander saw no event, and not one value any variant carries — bytes,
    // strings, ids and counts alike — so a descriptor field added later cannot
    // ride the channel unnoticed.
    const seen = overheard.map((message) => ({
      type: (message as { type?: string }).type,
      ...collect(message),
    }));
    expect([...new Set(seen.map((message) => message.type))].sort()).toEqual([
      'cb:hello',
      'cb:leader',
      'cb:portHost',
      'cb:portWanted',
    ]);
    const bytes = seen.map((message) => message.bytesHex).join('|');
    const text = seen.map((message) => message.text).join(' ');
    for (const needle of [hex(node), hex(ipnsName)]) expect(bytes).not.toContain(needle);
    for (const needle of [
      'k51-routing-key',
      'abuse-707070',
      'undecodable',
      'reconciling',
      '424242',
      '606060',
      '30003',
      '90009',
    ]) {
      expect(text).not.toContain(needle);
    }
  });

  it('re-brokers when the leader drops its port, so the event stream resumes', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    const events: EventDescriptor[] = [];
    follower.subscribe((event) => events.push(event));
    await follower.snapshot(null);

    // The tab re-brokers, so the leader retires the port it held before. The
    // event stream is one-way, so nothing else would re-dial: this tab would
    // mirror no further event for the rest of that leadership.
    await dialLeader(ports, 'f');
    await after(20);
    engine.emit({ kind: 'snapshotUpdated' });
    await after(20);

    expect(events).toEqual([{ kind: 'snapshotUpdated' }]);
  });

  it('refuses to greet again once its presence lock is lost', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'), { portTimeoutMs: 50 });
    await follower.snapshot(null);
    const greetings = (): number =>
      ports.messages.filter((m) => (m as { type?: string }).type === 'cb:portHello').length;
    expect(greetings()).toBe(1);

    // The tab's presence request settles in failure — a stolen lock, or a
    // document the browser will not grant one to.
    losePresence(bus, 'f');
    await tick();

    // Greeting on a name it no longer holds would invite the leader's watch to
    // reclaim it live, over and over; it fails closed instead.
    await expect(follower.snapshot(null)).rejects.toThrow();
    expect(greetings()).toBe(1);
  });

  it('rejects a forged response bearing a wrong or absent leader token, and takes no event off the channel (P1-4)', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    engine.respond = () => new Promise(() => undefined); // the real leader never answers
    const relay = relayOn(bus, engine, ports.courier('leader'));
    const follower = followerOn(bus, 'f', ports.courier('f'));
    await startFollower(relay, follower);

    const pending = follower.command({ kind: 'manualRefresh' });
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

    // The channel is not an event wire at all: an event posted on it reaches no
    // subscriber, forged token or not.
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
  /** Ends the tab behind that port, releasing the presence lock it holds. */
  kill: () => void;
}> {
  const bus = new FakeBus();
  const ports = new FakeCourierNetwork();
  const engine = new FakeEngineTransport();
  const relay = relayOn(bus, engine, ports.courier('leader'), options);
  const kill = livePresence(bus, 'f1');
  await tick(); // the tab holds its presence before it greets
  return { bus, ports, engine, relay, leaderPort: await dialLeader(ports, 'f1'), kill };
}

/** Dials the relay a fresh named port, returning the relay's end of it. */
async function dialLeader(ports: FakeCourierNetwork, clientId: string): Promise<FakeChannelPort> {
  const dialled = (await ports.courier(clientId).connect('leader')) as FakeChannelPort;
  const leaderPort = dialled.peer!;
  leaderPort.receive({ type: 'cb:portHello', clientId, accountId: null });
  return leaderPort;
}

/** What the relay posted down a port, by wire type. */
function replies(port: FakeChannelPort, type: string): Array<Record<string, unknown>> {
  return (port.posted as Array<Record<string, unknown>>).filter((m) => m.type === type);
}

/** The one credential-bearing command, as a descriptor. */
function settingsSaveOf(accessToken: ArrayBuffer): CommandDescriptor {
  return { kind: 'saveVaultSettings', settings: byoSettings(accessToken) };
}

/** The bearer bytes a relayed settings command arrived with. */
function bearerOf(command: CommandDescriptor | undefined): Uint8Array {
  if (command?.kind !== 'saveVaultSettings' || !command.settings.byo?.accessToken) {
    throw new Error('the relayed command carried no bearer');
  }
  return new Uint8Array(command.settings.byo.accessToken);
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
    const relay = relayOn(bus, engine, ports.courier('leader'));
    return { bus, ports, engine, relay };
  }

  const chunk = (seq: number): ArrayBuffer => Uint8Array.of(seq).buffer;
  const node = (fill: number): Uint8Array => new Uint8Array(16).fill(fill);

  it('applies pipelined chunks for one handle in send order', async () => {
    const { bus, ports, engine } = bench();
    const follower = followerOn(bus, 'f1', ports.courier('f1'));
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
    const follower = followerOn(bus, 'f1', ports.courier('f1'));
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
    const owner = followerOn(bus, 'owner', ports.courier('owner'));
    const other = followerOn(bus, 'other', ports.courier('other'));
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
    const leaving = followerOn(bus, 'leaving', ports.courier('leaving'));
    const staying = followerOn(bus, 'staying', ports.courier('staying'));
    engine.writeHandle = 1n;
    const orphan = await leaving.beginWrite({ node: node(1) }, 4);
    engine.writeHandle = 2n;
    const kept = await staying.beginWrite({ node: node(2) }, 4);

    leaving.close(); // releases its presence
    await tick();

    expect(engine.aborts).toEqual([orphan]);
    await expect(staying.pushChunk(kept, chunk(1))).resolves.toBeUndefined();
    expect(engine.chunks.map((entry) => entry.handle)).toEqual([kept]);
  });

  it('keeps a live follower whole through a farewell forged in its name', async () => {
    const { bus, ports, engine } = bench();
    const follower = followerOn(bus, 'f1', ports.courier('f1'));
    const handle = await follower.beginWrite({ node: node(1) }, 4);

    // The retired farewell shape, and any other message a same-origin context
    // can put on the channel: only the presence lock reports a departure.
    bus.channel().postMessage({ type: 'cb:bye', clientId: 'f1' });
    await after(20);

    expect(engine.aborts).toEqual([]);
    await expect(follower.pushChunk(handle, chunk(1))).resolves.toBeUndefined();
  });

  it('releases rather than strands a handle minted for a client that left mid-mint', async () => {
    const { engine, leaderPort, kill } = await portBench();
    let releaseMint!: (handle: bigint) => void;
    engine.beginWrite = () => new Promise((resolve) => (releaseMint = resolve));

    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    await tick();
    // The tab dies while the mint is still in flight, so the release sweep runs
    // against a table the handle has not landed in yet.
    kill();
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
    let mintStream!: (opened: OpenedStream) => void;
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

    // The same live tab re-brokers, so neither handle can ever reach the entry
    // it was asked for.
    const rebrokered = await dialLeader(ports, 'f1');
    await tick();
    mintWrite(7n);
    mintStream({ handle: 8n, size: 0 });
    await tick();

    // The staging reservation and the pinned content version, with the key
    // resident alongside it, are both released rather than stranded.
    expect(engine.aborts).toEqual([7n]);
    expect(engine.closedStreams).toEqual([8n]);
    expect(replies(leaderPort, 'cb:portResult')).toEqual([]);

    // The tab is still served on the port it now holds.
    engine.openContentStream = () => Promise.resolve({ handle: 9n, size: 0 });
    rebrokered.receive({
      type: 'cb:portStream',
      requestId: 1,
      stream: { kind: 'openContentStream', node: node(3) },
    });
    await tick();
    expect(replies(rebrokered, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 1, ok: true, result: { handle: 9n, size: 0 } })
    );
  });

  it('carries a BYO bearer on to the engine by transfer, keeping no copy in the leader tab', async () => {
    const { engine, leaderPort } = await portBench();
    const bearer = new TextEncoder().encode('s3cret');

    leaderPort.receive({
      type: 'cb:portCommand',
      requestId: 1,
      command: settingsSaveOf(bearer.buffer as ArrayBuffer),
    });
    await tick();

    expect(engine.commandTransfers[0]).toHaveLength(1);
    expect(bearer.byteLength).toBe(0);
    expect(bearerOf(engine.commands[0])).toEqual(new TextEncoder().encode('s3cret'));
  });

  it('wipes a BYO bearer it drops for a malformed command', async () => {
    const { engine, leaderPort } = await portBench();
    const bearer = new TextEncoder().encode('s3cret');

    // No `requestId`, so nothing can be answered — but the bearer already
    // crossed by transfer, leaving the relay its last owner.
    leaderPort.receive({
      type: 'cb:portCommand',
      command: settingsSaveOf(bearer.buffer as ArrayBuffer),
    });
    await tick();

    expect([...bearer]).toEqual([0, 0, 0, 0, 0, 0]);
    expect(engine.commands).toEqual([]);
  });

  it('moves a BYO bearer on even for a command kind this build does not serve', async () => {
    const { engine, leaderPort } = await portBench();
    engine.respond = () => Promise.reject(new EngineRequestError('unknown command kind'));
    const bearer = new TextEncoder().encode('s3cret');

    leaderPort.receive({
      type: 'cb:portCommand',
      requestId: 1,
      command: { kind: 'saveVaultSettingsV2', settings: byoSettings(bearer.buffer as ArrayBuffer) },
    });
    await tick();

    // The credential is found by shape, not by `kind`, so a version-skewed
    // sender's bearer still leaves the leader realm rather than resting in it.
    expect(engine.commandTransfers[0]).toHaveLength(1);
    expect(bearer.byteLength).toBe(0);
    expect(replies(leaderPort, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 1, ok: false })
    );
  });

  it('wipes a BYO bearer it drops for a command whose kind is not a string', async () => {
    const { engine, leaderPort } = await portBench();
    const bearer = new TextEncoder().encode('s3cret');

    leaderPort.receive({
      type: 'cb:portCommand',
      requestId: 1,
      command: { kind: 42, settings: byoSettings(bearer.buffer as ArrayBuffer) },
    });
    await tick();

    expect([...bearer]).toEqual(new Array(bearer.length).fill(0));
    expect(engine.commands).toEqual([]);
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

  /**
   * A port is untrusted input in both directions a follower can be wrong in:
   * hostile, or merely a version-skewed build. A correlated request must always
   * come back settled — a step that throws on the way to its handler would leave
   * the sender waiting on a wire that already answered everything else.
   */
  it.each([
    ['cb:portWrite', { requestId: 1 }],
    ['cb:portWrite', { requestId: 1, write: null }],
    ['cb:portWrite', { requestId: 1, write: { kind: 42 } }],
    ['cb:portRead', { requestId: 1 }],
    ['cb:portRead', { requestId: 1, read: { kind: 'nonsense' } }],
    ['cb:portStream', { requestId: 1 }],
    ['cb:portCommand', { requestId: 1 }],
    // A type this build does not know — the cross-build skew case.
    ['cb:portFuture', { requestId: 1 }],
  ])('answers a malformed %s rather than leaving its sender hanging', async (type, rest) => {
    const { leaderPort } = await portBench();

    leaderPort.receive({ type, ...rest });
    await tick();

    expect(replies(leaderPort, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 1, ok: false })
    );
  });

  /**
   * The owned-handle limb: past the ownership check, so only the step switch is
   * left to reject a kind this build does not serve. Acking it would report a
   * write step that never ran, and a streamed upload would lose those bytes.
   */
  it('refuses a write kind it does not serve on a handle the sender owns', async () => {
    const { engine, leaderPort } = await portBench();
    engine.writeHandle = 6n;
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    await tick();

    const plaintext = Uint8Array.of(2, 7, 1, 8);
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 2,
      write: { kind: 'bogus', handle: 6n, chunk: plaintext.buffer },
    });
    await tick();

    expect(replies(leaderPort, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 2, ok: false })
    );
    expect(engine.chunks).toEqual([]);
    expect([...plaintext]).toEqual([0, 0, 0, 0]);
  });

  it('wipes a chunk carried alongside a write step it does serve', async () => {
    const { engine, leaderPort } = await portBench();
    engine.writeHandle = 7n;
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind: 'beginWrite', target: { node: node(1) }, size: 4 },
    });
    await tick();

    // A well-formed commit that merely carries a buffer too: it still crossed by
    // transfer, so the relay owns it whatever the step it names.
    const plaintext = Uint8Array.of(1, 6, 1, 8);
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 2,
      write: { kind: 'commitWrite', handle: 7n, chunk: plaintext.buffer },
    });
    await tick();

    expect(engine.commits).toEqual([7n]);
    expect([...plaintext]).toEqual([0, 0, 0, 0]);
  });

  it('drops a stream kind it does not serve without reaching the engine', async () => {
    const { engine, leaderPort } = await portBench();
    engine.streamHandle = 5n;
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 1,
      stream: { kind: 'openContentStream', node: node(2) },
    });
    await tick();

    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 2,
      stream: { kind: 'bogus', handle: 5n },
    });
    await tick();

    expect(replies(leaderPort, 'cb:portResult')).toContainEqual(
      expect.objectContaining({ requestId: 2, ok: false })
    );
    // A step off the union would otherwise read the stream at `undefined`.
    expect(engine.reads).toEqual([]);
  });

  it('survives a port payload with no shape at all', async () => {
    const { engine, leaderPort } = await portBench();

    for (const junk of [null, undefined, 'a string', 42]) leaderPort.receive(junk);
    await tick();

    leaderPort.receive({
      type: 'cb:portRead',
      requestId: 1,
      read: { kind: 'siweChallenge', intent: 'login' },
    });
    await tick();
    expect(engine.siweChallenges).toBe(1);
  });

  it('drops a malformed focus report without throwing out of the listener', async () => {
    const { engine, leaderPort } = await portBench();
    const before = engine.commands.length;

    // Uncorrelated, so there is nothing to answer — but a `node` the relay
    // cannot key on must not escape the message handler either.
    leaderPort.receive({ type: 'cb:portFocus', node: 'not-a-node' });
    await tick();

    expect(engine.commands.slice(before)).toEqual([]);
    leaderPort.receive({ type: 'cb:portFocus', node: new Uint8Array([1, 2]) });
    await tick();
    expect(engine.commands.slice(before).map((c) => c.kind)).toEqual(['manualRefresh']);
  });

  // Kind-agnostic: a payload carrying plaintext under any name still crossed.
  it.each(['pushChunk', 'bogus'])('wipes an upload chunk it refuses on a %s step', async (kind) => {
    const { engine, leaderPort } = await portBench();
    const plaintext = Uint8Array.of(9, 8, 7, 6);

    // A step on a handle this port never opened: the chunk was already
    // transferred into the leader, so the relay is its last owner.
    leaderPort.receive({
      type: 'cb:portWrite',
      requestId: 1,
      write: { kind, handle: 4n, chunk: plaintext.buffer },
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
    const follower = followerOn(bus, 'f1', ports.courier('f1'));
    const handle = await follower.beginWrite({ node: node(5) }, 4);

    relay.close();
    await tick();

    expect(engine.aborts).toEqual([handle]);
  });
});

describe('leader relay follower presence', () => {
  const node = (fill: number): Uint8Array => new Uint8Array(16).fill(fill);

  it('reclaims the handles and port of a follower whose tab is gone', async () => {
    const { engine, leaderPort, kill } = await portBench();
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

    // The tab is gone: the browser releases its presence lock.
    kill();
    await tick();

    // Reclaimed on the turn the lock released — no probe interval to wait out.
    // The pinned content version, and the key resident with it, is released, as
    // is the write handle's staging reservation and the port itself.
    expect(engine.closedStreams).toEqual([4n]);
    expect(engine.aborts).toEqual([3n]);
    expect(replies(leaderPort, 'cb:portClosed')).toHaveLength(1);
    expect(leaderPort.closed).toBe(true);
  });

  it('never reclaims a live but frozen follower that answers nothing at all', async () => {
    const { engine, leaderPort } = await portBench();
    engine.streamHandle = 4n;
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 1,
      stream: { kind: 'openContentStream', node: node(2) },
    });
    await tick();

    // A frozen tab runs no handler at all, so it could answer no probe — but it
    // still holds its presence lock, so it is never a candidate.
    await after(30);

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

  it('keeps the handles of a follower that re-brokers while its tab lives', async () => {
    const { engine, ports, leaderPort } = await portBench();
    engine.streamHandle = 4n;
    leaderPort.receive({
      type: 'cb:portStream',
      requestId: 1,
      stream: { kind: 'openContentStream', node: node(2) },
    });
    await tick();

    // The same tab dials a fresh port; its presence never lapsed, so the watch
    // stands and the stream it opened is still its own.
    const rebrokered = await dialLeader(ports, 'f1');
    await tick();
    rebrokered.receive({
      type: 'cb:portStream',
      requestId: 2,
      stream: { kind: 'readStream', handle: 4n, offset: 0, length: 8 },
    });
    await tick();

    expect(engine.closedStreams).toEqual([]);
    expect(engine.reads).toEqual([{ handle: 4n, offset: 0, length: 8 }]);
  });

  it('reclaims a follower that greets while holding no presence at all', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    const engine = new FakeEngineTransport();
    relayOn(bus, engine, ports.courier('leader'));

    // Nothing holds `ghost`'s presence name, so the leader's watch is granted at
    // once: a greeting is only as good as the lock behind it.
    const ghost = await dialLeader(ports, 'ghost');
    await tick();

    expect(replies(ghost, 'cb:portClosed')).toHaveLength(1);
    expect(ghost.closed).toBe(true);
  });

  it('leaves an unnamed port to the naming timeout, watching no presence for it', async () => {
    const bus = new FakeBus();
    const ports = new FakeCourierNetwork();
    relayOn(bus, new FakeEngineTransport(), ports.courier('leader'), { namingTimeoutMs: 10_000 });

    // A port that named no client cannot be watched under a `clientId` it does
    // not have; the naming timeout owns it instead.
    const squatter = (await ports.courier('squatter').connect('leader')) as FakeChannelPort;
    await after(30);
    expect(squatter.peer!.posted).toEqual([]);
    expect(squatter.peer!.closed).toBe(false);
  });

  it('stops watching a follower once the leader steps down', async () => {
    const { engine, relay, kill } = await portBench();
    engine.streamHandle = 4n;
    relay.close();
    await tick();
    const closedOnStepDown = [...engine.closedStreams];

    // The tab dies after the step-down; a retired watch must not fire against a
    // relay that is gone.
    kill();
    await after(30);

    expect(engine.closedStreams).toEqual(closedOnStepDown);
  });
});
