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
  /** Base URL of the CipherBox API; the `Mailbox` seam appends its own routes. */
  apiBaseUrl: string;
  /** `/routing/v1` origins: someguy plus at least one public endpoint. */
  recordEndpoints: string[];
  /**
   * Base URL of the read accelerator (CONTEXT.md "Read accelerator"). Absent
   * leaves the content gateway dormant: reads fail closed as unavailable rather
   * than falling back to an endpoint nobody configured.
   */
  acceleratorBaseUrl?: string;
  /** Public trustless-gateway fallbacks, tried in order after the accelerator. */
  publicGateways?: string[];
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
  // Spread, not a field-by-field copy: a config field added upstream reaches the
  // worker without a second edit that nothing would typecheck. The annotation
  // keeps the handshake checked against the contract at both ends.
  const bootstrap: EngineWorkerBootstrap = { type: 'bootstrap', ...config };
  worker.postMessage(bootstrap);
  return worker;
}
