/**
 * A protocol-speaking engine worker (no WASM) that serves ranged plaintext, for
 * the follower media-routing slice of the browser suite. Only the leader tab
 * spawns it, so bytes carrying `LEADER_SEED` prove a follower's `/stream/` read
 * travelled the broadcast wire to the leader's worker.
 */
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import { StubEngineHost } from '../../src/testkit.js';
import type { EventDescriptor } from '../../src/worker/protocol.js';
import { fixtureBuffer, LEADER_SEED } from './mediaFixture.js';

class MediaHost extends StubEngineHost {
  start(): Promise<void> {
    return Promise.resolve();
  }

  command(): Promise<void> {
    return Promise.resolve();
  }

  abortWrite(): Promise<void> {
    return Promise.resolve();
  }

  downloadRange(_node: Uint8Array, offset: number, length: number): Promise<ArrayBuffer> {
    return Promise.resolve(fixtureBuffer(offset, length, LEADER_SEED));
  }

  nextEvent(): Promise<EventDescriptor | null> {
    return new Promise<EventDescriptor | null>(() => undefined);
  }
}

serveEngine(self as unknown as WorkerScopeLike, new MediaHost());
