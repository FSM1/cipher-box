import { describe, expect, it, vi } from 'vitest';

import { BroadcastTransport } from './broadcastTransport.js';
import { LeaderRelay } from './leaderRelay.js';
import { FakeBus, FakeCourierNetwork, FakeEngineTransport } from './testkit.js';
import type { DeviceRendezvousStep } from './worker/protocol.js';

vi.mock('./worker/protocol.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./worker/protocol.js')>();
  (actual.RENDEZVOUS_SECRET_FIELDS as string[]).push('laterSecret');
  return actual;
});

describe('leader relay rendezvous wipe', () => {
  it('erases every listed secret field of the step it served', async () => {
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
