/**
 * Engine worker lifecycle, UI-realm half (blueprint/web-client.md "Engine
 * hosting"). Spawn and bootstrap are one indivisible step: the worker ignores
 * every message until it has been bootstrapped, and `LocalTransport` has no
 * timeout, so a spawn that skipped the handshake would park every facade call
 * forever.
 */

import type { EngineWorkerBootstrap } from './worker/engineWorker.js';

/** What a host tab must know to stand the engine worker up. */
export interface EngineHostConfig {
  /** Base URL of the CipherBox API; the mailbox collection hangs off it. */
  apiBaseUrl: string;
  /** `/routing/v1` origins: someguy plus at least one public endpoint. */
  recordEndpoints: string[];
  /** URL of the wasm-bindgen ES glue module the worker imports. */
  wasmModuleUrl: string;
  /** URL of the wasm binary handed to the glue's `init`. */
  wasmBinaryUrl: string;
  /** Sync timing profile. */
  profile?: 'ci' | 'production';
  /** Namespaces the IndexedDB/OPFS store names. */
  dbPrefix?: string;
}

const spawnModuleWorker = () =>
  new Worker(new URL('./worker/engineWorker.js', import.meta.url), { type: 'module' });

export function spawnEngineWorker(
  config: EngineHostConfig,
  createWorker: () => Worker = spawnModuleWorker
): Worker {
  const worker = createWorker();
  const bootstrap: EngineWorkerBootstrap = {
    type: 'bootstrap',
    recordEndpoints: config.recordEndpoints,
    mailboxUrl: `${config.apiBaseUrl.replace(/\/+$/, '')}/mailbox/messages`,
    dbPrefix: config.dbPrefix,
    wasmModuleUrl: config.wasmModuleUrl,
    wasmBinaryUrl: config.wasmBinaryUrl,
    profile: config.profile,
  };
  worker.postMessage(bootstrap);
  return worker;
}
