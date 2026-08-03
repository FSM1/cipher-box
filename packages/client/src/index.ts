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
export { EngineRequestError } from './correlatedTransport.js';
export { LocalTransport } from './transport.js';
export type { EngineTransport, EngineWorkerLike, EngineEventListener } from './transport.js';

// Tab leadership, the broadcast transport, and the transport-swapping client:
// one facade per tab, leader or follower, over the origin's single engine.
export { EngineClient } from './engineClient.js';
export type { EngineClientConfig, EngineClientRole, SecretSource } from './engineClient.js';
export { spawnEngineWorker } from './spawnEngineWorker.js';
export type { EngineHostConfig } from './spawnEngineWorker.js';
export { LeaderElection } from './leadership.js';
export type { LockManagerLike, LockGrant, ElectionRole } from './leadership.js';
export { BroadcastTransport } from './broadcastTransport.js';
export { LeaderRelay } from './leaderRelay.js';
export { BROADCAST_CHANNEL_NAME, newClientId } from './broadcast.js';
export type { BroadcastChannelLike } from './broadcast.js';
export { ServiceWorkerCourier, defaultCourier, unavailableCourier } from './portCourier.js';
export type { CourierContainerLike, CourierOptions } from './portCourier.js';
export type { PortCourier, MessagePortLike } from './portRelay.js';

// The tab side of the Service Worker byte pipe.
export { MediaService } from './media/service.js';
export type { MediaReader } from './media/broker.js';

// The one hex codec in TypeScript, for hosts that receive hex-encoded bytes
// from a third-party SDK or address opaque engine byte strings by string key.
export { fromHex, toHex } from './seams/bytes.js';

// The wire descriptors the UI exchanges with the engine over the transport.
export type {
  CommandDescriptor,
  EventDescriptor,
  Permission,
  NodeKind,
  PendingClass,
  Staleness,
  OpProgressPhase,
  DeadLetterReason,
  DeadLetterDescriptor,
  BlockedOpDescriptor,
  SnapshotDescriptor,
  SnapshotChildDescriptor,
  BreadcrumbDescriptor,
  WriteTarget,
  WriteHandle,
  StreamHandle,
} from './worker/protocol.js';
