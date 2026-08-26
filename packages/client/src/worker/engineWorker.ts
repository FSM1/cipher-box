/**
 * The production engine worker entry (blueprint/web-client.md "Engine hosting").
 *
 * The leader tab spawns this module worker and posts one `bootstrap` message
 * with the WASM artifact URLs and seam config. The worker dynamically imports
 * the wasm-bindgen artifact, instantiates it, builds the browser seams, and
 * serves the facade protocol. Everything past this point runs off the UI
 * thread; key material lives only here, in WASM linear memory.
 *
 * This is a worker entry (registers a listener on load) — load it via
 * `new Worker(new URL('./engineWorker.js', import.meta.url), { type: 'module' })`,
 * never import it into the UI realm.
 */

import { reclaimOtherAccountStores } from '../accountStores.js';
import { makeBrowserSeams, type BrowserSeams } from './browserSeams.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';
import { serveEngine, type WorkerScopeLike } from './serve.js';
import type { WorkerMessage } from './protocol.js';
import type { EngineHostConfig } from '../spawnEngineWorker.js';
import { measureStorageHeadroomBytes } from './storageHeadroom.js';

/** The one-shot handshake the leader sends after spawning the worker. */
export type EngineWorkerBootstrap = EngineHostConfig & { type: 'bootstrap' };

interface WasmGlue extends EngineWasm {
  default: (options: { module_or_path: string }) => Promise<unknown>;
}

const workerScope = globalThis as unknown as {
  postMessage(message: WorkerMessage): void;
  addEventListener(
    type: 'message',
    listener: (event: MessageEvent<EngineWorkerBootstrap>) => void
  ): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
};

function onBootstrap(event: MessageEvent<EngineWorkerBootstrap>): void {
  if (event.data?.type !== 'bootstrap') return;
  workerScope.removeEventListener('message', onBootstrap as (event: MessageEvent) => void);
  void bootstrap(event.data);
}

/**
 * Opens this account's seams and sweeps the stores of every account the profile
 * no longer holds. The sweep runs alongside the cold start: the origin quota was
 * already measured, so the bytes it frees are the *next* start's headroom.
 */
function openAccount(config: EngineWorkerBootstrap, accountId: string): BrowserSeams {
  // Detached, so its own best-effort contract is the only thing holding a sweep
  // fault off the cold start: make that structural rather than internal.
  void reclaimOtherAccountStores(config, accountId).catch(() => undefined);
  return makeBrowserSeams(config, accountId);
}

async function bootstrap(config: EngineWorkerBootstrap): Promise<void> {
  try {
    // The quota estimate is independent of the WASM fetch and compile, so it
    // rides alongside them rather than extending cold start.
    const headroom = measureStorageHeadroomBytes();
    const wasm = (await import(/* @vite-ignore */ config.wasmModuleUrl)) as WasmGlue;
    await wasm.default({ module_or_path: config.wasmBinaryUrl });
    const host = new EngineHost(wasm, (accountId) => openAccount(config, accountId), {
      apiBaseUrl: config.apiBaseUrl,
      acceleratorBaseUrl: config.acceleratorBaseUrl,
      publicGateways: config.publicGateways,
      profile: config.profile,
      storageHeadroomBytes: await headroom,
    });
    serveEngine(workerScope as unknown as WorkerScopeLike, host);
  } catch (error) {
    workerScope.postMessage({
      type: 'fatal',
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

workerScope.addEventListener('message', onBootstrap);
