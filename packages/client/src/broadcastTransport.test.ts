import { describe, expect, it } from 'vitest';

import { BroadcastTransport } from './broadcastTransport.js';
import { LeaderRelay } from './leaderRelay.js';
import { FakeBus, FakeEngineTransport } from './testkit.js';
import type { EventDescriptor } from './worker/protocol.js';

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

  it('never transmits the login secret and scrubs the follower copy', async () => {
    const bus = new FakeBus();
    const posted: unknown[] = [];
    const leaderChannel = bus.channel();
    leaderChannel.addEventListener('message', (event) => posted.push(event.data));
    // A relay makes a leader "present" so start resolves.
    new LeaderRelay(leaderChannel, new FakeEngineTransport());
    const follower = new BroadcastTransport(bus.channel(), 'f');

    const secret = new Uint8Array([1, 2, 3, 4, 5]).buffer;
    await follower.start(secret);

    // The secret buffer was zeroed in place and no command carried its bytes.
    expect([...new Uint8Array(secret)]).toEqual([0, 0, 0, 0, 0]);
    const carriedSecret = posted.some((m) => JSON.stringify(m).includes('"1,2,3,4,5"'));
    expect(carriedSecret).toBe(false);
  });

  it('leaks no key-shaped sentinel on any leader→follower message (structural)', async () => {
    const bus = new FakeBus();
    const engine = new FakeEngineTransport();
    new LeaderRelay(bus.channel(), engine);

    // Capture everything the leader broadcasts to followers (events + responses).
    const leaderPosts: unknown[] = [];
    const spy = bus.channel();
    spy.addEventListener('message', (event) => leaderPosts.push(event.data));

    const follower = new BroadcastTransport(bus.channel(), 'f');
    // A key-shaped sentinel: distinctive 32-byte key material that must never
    // appear on the keyless leader→follower wire. Plant it as this follower's
    // secret (the follower scrubs it) so it genuinely exists in the test realm.
    const sentinel = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);
    await follower.start(sentinel.slice().buffer);

    // Drive the full leader→follower surface: a correlated response plus every
    // EventDescriptor variant, including the byte- and string-bearing ones.
    await follower.command({ kind: 'manualRefresh' }, []);
    engine.emit({ kind: 'snapshotUpdated' });
    engine.emit({ kind: 'stalenessChanged', staleness: 'stale' });
    engine.emit({ kind: 'withheldUpdateEscalation', ipnsName: new Uint8Array([1, 2, 3]) });
    engine.emit({ kind: 'deadLetter', opId: 9n });
    engine.emit({ kind: 'attributableAbuse', description: 'abuse' });
    await tick();

    // Serialize every leader post (bytes as csv, bigint as string) and assert the
    // sentinel never rode along — a future variant echoing key bytes would fail.
    const serialize = (value: unknown): string =>
      JSON.stringify(value, (_key, v) =>
        v instanceof Uint8Array ? [...v].join(',') : typeof v === 'bigint' ? v.toString() : v
      );
    const sentinelCsv = [...sentinel].join(',');
    const leaked = leaderPosts.some((message) => serialize(message).includes(sentinelCsv));
    expect(leaked).toBe(false);
    // Sanity: the leader actually broadcast the events + response we drove.
    expect(leaderPosts.length).toBeGreaterThanOrEqual(6);
  });

  it('shares upload content as a Blob and rebuilds identical bytes on the leader', async () => {
    const { engine, follower } = wire();
    const bytes = new Uint8Array([9, 8, 7, 6]);
    await follower.command(
      { kind: 'updateContent', node: new Uint8Array(16), content: bytes.buffer },
      [bytes.buffer]
    );

    const command = engine.commands[0];
    expect(command.kind).toBe('updateContent');
    if (command.kind !== 'updateContent') throw new Error('unreachable');
    expect([...new Uint8Array(command.content)]).toEqual([9, 8, 7, 6]);
  });

  it('fans engine events out to the follower in emission order', async () => {
    const { engine, follower } = wire();
    const received: EventDescriptor[] = [];
    follower.subscribe((event) => received.push(event));
    await tick(); // let the follower register with the leader

    const sent: EventDescriptor[] = [
      { kind: 'snapshotUpdated' },
      { kind: 'deadLetter', opId: 3n },
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
});
