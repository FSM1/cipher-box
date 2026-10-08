import { describe, expect, it, vi } from 'vitest';

import { BroadcastTransport } from './broadcastTransport.js';
import { LeaderRelay } from './leaderRelay.js';
import { FakeBus, FakeCourierNetwork, FakeEngineTransport } from './testkit.js';
import type { DeviceRendezvousStep, ReadDescriptor } from './worker/protocol.js';

vi.mock('./worker/protocol.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./worker/protocol.js')>();
  (actual.RENDEZVOUS_SECRET_FIELDS as string[]).push('laterSecret');
  return actual;
});

/** A leader relay over a fake engine, and one follower that reaches it. */
function relayedFollower(): { engine: FakeEngineTransport; follower: BroadcastTransport } {
  const bus = new FakeBus();
  const ports = new FakeCourierNetwork();
  const engine = new FakeEngineTransport();
  new LeaderRelay(bus.channel(), engine, ports.courier('leader'), bus.locks);
  const follower = new BroadcastTransport(
    bus.channel(),
    'follower-1',
    ports.courier('follower-1'),
    bus.locks
  );
  return { engine, follower };
}

describe('leader relay rendezvous wipe', () => {
  it('erases every listed secret field of the step it served', async () => {
    const { engine, follower } = relayedFollower();
    let relayHeld: unknown = null;
    engine.respondRendezvous = (step) => {
      relayHeld = (step as unknown as Record<string, unknown>).laterSecret;
      return Promise.resolve({
        kind: 'opened',
        ephemeralPublicKey: '02beef',
        requestPayload: Uint8Array.of(1, 2),
        comparisonValue: '482913 205776 640118',
      });
    };
    const step = {
      kind: 'open',
      devicePublicKey: 'ed25519hex',
      scalar: new Uint8Array(32).fill(5),
      laterSecret: new Uint8Array(8).fill(3),
    } as unknown as DeviceRendezvousStep;

    await follower.read({ kind: 'deviceRendezvous', step });

    expect(relayHeld).toEqual(new Uint8Array(8));
  });
});

describe('leader relay reads', () => {
  it('serves a follower any read kind and leaves the refusal of an unknown one to the engine', async () => {
    const { engine, follower } = relayedFollower();
    const served: unknown[] = [];
    vi.spyOn(engine, 'read').mockImplementation((read) => {
      served.push(read.kind);
      return (read.kind as string) === 'laterRead'
        ? (Promise.resolve('later answer') as never)
        : Promise.reject(new Error('the read does not decode'));
    });
    const laterRead = { kind: 'laterRead' } as unknown as ReadDescriptor;
    const unknownRead = { kind: 'noSuchRead' } as unknown as ReadDescriptor;

    await expect(follower.read(laterRead)).resolves.toBe('later answer');
    await expect(follower.read(unknownRead)).rejects.toThrow('the read does not decode');
    expect(served).toEqual(['laterRead', 'noSuchRead']);
  });
});
