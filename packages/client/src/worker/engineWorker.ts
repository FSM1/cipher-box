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

import { makeBrowserSeams, type BrowserSeamsConfig } from './browserSeams.js';
import { EngineHost } from './engineHost.js';
import type { EngineWasm } from './engineWasm.js';
import { serveEngine, type WorkerScopeLike } from './serve.js';
import type { WorkerMessage } from './protocol.js';

/** The one-shot handshake the leader sends after spawning the worker. */
export interface EngineWorkerBootstrap extends BrowserSeamsConfig {
  type: 'bootstrap';
  /** URL of the wasm-bindgen ES glue module (dynamically imported). */
  wasmModuleUrl: string;
  /** URL of the wasm binary handed to the glue's `init`. */
  wasmBinaryUrl: string;
  /** Sync timing profile. */
  profile?: 'ci' | 'production';
}

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

async function bootstrap(config: EngineWorkerBootstrap): Promise<void> {
  try {
    const wasm = (await import(/* @vite-ignore */ config.wasmModuleUrl)) as WasmGlue;
    await wasm.default({ module_or_path: config.wasmBinaryUrl });
    const seams = makeBrowserSeams(config);
    const host = new EngineHost(wasm, seams, config.profile);
    serveEngine(workerScope as unknown as WorkerScopeLike, host);
  } catch (error) {
    workerScope.postMessage({
      type: 'fatal',
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

workerScope.addEventListener('message', onBootstrap);
