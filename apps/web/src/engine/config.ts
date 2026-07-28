/**
 * Build-time configuration for the engine worker's one-shot bootstrap.
 *
 * The worker's seams reach exactly two network surfaces — the `/routing/v1`
 * delegated-routing endpoint set and the API mailbox (blueprint/web-client.md
 * "Browser seams") — plus the `crates/wasm` artifact it instantiates. Nothing
 * here is a trust input: every record the transport returns still passes the
 * engine's adoption gate.
 */

import type { EngineWorkerBootstrap } from '@cipherbox/client/worker';

/** The bootstrap payload minus the message tag the spawner stamps on. */
export type EngineBootstrapConfig = Omit<EngineWorkerBootstrap, 'type'>;

const DEFAULT_API_URL = 'http://localhost:3000';
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';
const DEFAULT_WASM_MODULE_URL = '/wasm/cipherbox_wasm.js';
const DEFAULT_WASM_BINARY_URL = '/wasm/cipherbox_wasm_bg.wasm';

export function engineBootstrapConfig(env: Partial<ImportMetaEnv>): EngineBootstrapConfig {
  const recordEndpoints = (env.VITE_ROUTING_ENDPOINTS ?? DEFAULT_ROUTING_ENDPOINTS)
    .split(',')
    .map((endpoint) => endpoint.trim().replace(/\/+$/, ''))
    .filter((endpoint) => endpoint.length > 0);

  // An empty set would leave the engine with nowhere to resolve or publish
  // records, which the RecordTransport seam refuses to construct anyway.
  if (recordEndpoints.length === 0) {
    throw new Error('VITE_ROUTING_ENDPOINTS resolved to an empty endpoint set');
  }

  const apiUrl = (env.VITE_API_URL ?? DEFAULT_API_URL).replace(/\/+$/, '');

  return {
    recordEndpoints,
    mailboxUrl: `${apiUrl}/mailbox`,
    wasmModuleUrl: env.VITE_WASM_MODULE_URL ?? DEFAULT_WASM_MODULE_URL,
    wasmBinaryUrl: env.VITE_WASM_BINARY_URL ?? DEFAULT_WASM_BINARY_URL,
  };
}
