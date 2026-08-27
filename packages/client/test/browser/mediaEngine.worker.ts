/**
 * A protocol-speaking engine worker (no WASM) that serves ranged plaintext, for
 * the follower media-routing slice of the browser suite. Only the leader tab
 * spawns it, so bytes carrying `LEADER_SEED` prove a follower's `/stream/` read
 * travelled the broadcast wire to the leader's worker.
 */
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import { StubEngineHost } from '../../src/testkit.js';
import type { CommandOutcomeDescriptor, EventDescriptor } from '../../src/worker/protocol.js';
import type { OpenedStream } from '../../src/worker/protocol.js';
import { fixtureBuffer, LEADER_CONTENT_BYTES, LEADER_SEED } from './mediaFixture.js';

class MediaHost extends StubEngineHost {
  start(): Promise<void> {
    return Promise.resolve();
  }

  command(): Promise<CommandOutcomeDescriptor> {
    return Promise.resolve({ kind: 'done' });
  }

  abortWrite(): Promise<void> {
    return Promise.resolve();
  }

  openContentStream(_node: Uint8Array): Promise<OpenedStream> {
    return Promise.resolve({ handle: 1n, size: LEADER_CONTENT_BYTES });
  }

  readStream(_handle: bigint, offset: number, length: number): Promise<ArrayBuffer> {
    return Promise.resolve(fixtureBuffer(offset, length, LEADER_SEED));
  }

  closeStream(_handle: bigint): Promise<void> {
    return Promise.resolve();
  }

  nextEvent(): Promise<EventDescriptor | null> {
    return new Promise<EventDescriptor | null>(() => undefined);
  }
}

serveEngine(self as unknown as WorkerScopeLike, new MediaHost());
