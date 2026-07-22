/**
 * @cipherbox/client — WASM engine hosting and browser seams for the v2 web
 * client (blueprint/web-client.md).
 *
 * This layer lands every browser seam implementation (IndexedDB, OPFS, and
 * `fetch`), the dedicated engine worker that hosts the WASM engine over those
 * seams, the promise-correlated RPC layer, and the single typed async facade
 * behind a transport seam. This slice ships the local (single-tab) transport;
 * tab leadership and the broadcast transport land next (#640).
 */
export const CLIENT_PACKAGE = '@cipherbox/client';

// The UI-realm consumer contract. The worker realm is wired via `new Worker(URL)`
// and imports its collaborators by relative path, so nothing outside this
// package consumes the worker-realm internals through the barrel.
export { EngineFacade } from './facade.js';
export { LocalTransport } from './transport.js';
export type { EngineTransport, EngineWorkerLike, EngineEventListener } from './transport.js';

// The wire descriptors the UI exchanges with the engine over the transport.
export type {
  CommandDescriptor,
  EventDescriptor,
  Permission,
  NodeKind,
  Staleness,
} from './worker/protocol.js';
