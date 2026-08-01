/**
 * A protocol-speaking engine worker (no WASM) that serves ranged plaintext, for
 * the follower media-routing slice of the browser suite. Only the leader tab
 * spawns it, so bytes carrying `LEADER_SEED` prove a follower's `/stream/` read
 * travelled the broadcast wire to the leader's worker.
 */
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import type { EngineHostLike } from '../../src/worker/engineHost.js';
import type { EventDescriptor, SnapshotDescriptor } from '../../src/worker/protocol.js';
import { fixtureBuffer, LEADER_SEED } from './mediaFixture.js';

class MediaHost implements EngineHostLike {
  start(): Promise<void> {
    return Promise.resolve();
  }

  command(): Promise<void> {
    return Promise.resolve();
  }

  beginWrite(): Promise<bigint> {
    return Promise.reject(new Error('media host serves no writes'));
  }

  pushChunk(): Promise<void> {
    return Promise.reject(new Error('media host serves no writes'));
  }

  commitWrite(): Promise<bigint> {
    return Promise.reject(new Error('media host serves no writes'));
  }

  abortWrite(): Promise<void> {
    return Promise.resolve();
  }

  snapshot(): Promise<SnapshotDescriptor> {
    return Promise.reject(new Error('media host serves no snapshots'));
  }

  download(): Promise<ArrayBuffer> {
    return Promise.reject(new Error('media host serves whole files only by range'));
  }

  downloadRange(_node: Uint8Array, offset: number, length: number): Promise<ArrayBuffer> {
    return Promise.resolve(fixtureBuffer(offset, length, LEADER_SEED));
  }

  nextEvent(): Promise<EventDescriptor | null> {
    return new Promise<EventDescriptor | null>(() => undefined);
  }
}

serveEngine(self as unknown as WorkerScopeLike, new MediaHost());
