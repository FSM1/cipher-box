/**
 * @cipherbox/client — WASM engine hosting and browser seams for the v2 web
 * client (blueprint/web-client.md).
 *
 * This layer lands every browser seam implementation (IndexedDB, OPFS, and
 * `fetch`), the dedicated engine worker that hosts the WASM engine over those
 * seams, the promise-correlated RPC layer, the single typed async facade behind
 * a transport seam, and tab leadership with the leader/follower broadcast
 * transports and failover (#640).
 */
export const CLIENT_PACKAGE = '@cipherbox/client';

// The UI-realm consumer contract. The worker realm is wired via `new Worker(URL)`
// and imports its collaborators by relative path, so nothing outside this
// package consumes the worker-realm internals through the barrel.
export { EngineFacade } from './facade.js';
export { LocalTransport } from './transport.js';
export type { EngineTransport, EngineWorkerLike, EngineEventListener } from './transport.js';

// Tab leadership, the broadcast transport, and the transport-swapping client:
// one facade per tab, leader or follower, over the origin's single engine.
export { EngineClient } from './engineClient.js';
export type { EngineClientConfig, EngineClientRole, SecretSource } from './engineClient.js';
export { LeaderElection } from './leadership.js';
export type { LockManagerLike, LockGrant, ElectionRole } from './leadership.js';
export { BroadcastTransport } from './broadcastTransport.js';
export { LeaderRelay, FocusRegistry } from './leaderRelay.js';
export { BROADCAST_CHANNEL_NAME, newClientId } from './broadcast.js';
export type { BroadcastChannelLike } from './broadcast.js';

// The wire descriptors the UI exchanges with the engine over the transport.
export type {
  CommandDescriptor,
  EventDescriptor,
  Permission,
  NodeKind,
  Staleness,
} from './worker/protocol.js';
