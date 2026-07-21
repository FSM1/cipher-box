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

export * from './seams/index.js';

// The typed facade and its transport seam (UI realm).
export { EngineFacade } from './facade.js';
export { LocalTransport } from './transport.js';
export type { EngineTransport, EngineWorkerLike, EngineEventListener } from './transport.js';

// The wire protocol between the UI and the engine worker.
export type {
  CommandDescriptor,
  EventDescriptor,
  Permission,
  NodeKind,
  Staleness,
  WorkerRequest,
  WorkerMessage,
} from './worker/protocol.js';

// The engine worker host and its protocol server (worker realm).
export { EngineHost } from './worker/engineHost.js';
export type { EngineHostLike } from './worker/engineHost.js';
export { serveEngine } from './worker/serve.js';
export type { WorkerScopeLike } from './worker/serve.js';
export { makeBrowserSeams } from './worker/browserSeams.js';
export type { BrowserSeams, BrowserSeamsConfig } from './worker/browserSeams.js';
export { buildCommand, readEvent } from './worker/commandCodec.js';
export type {
  EngineWasm,
  WasmCommand,
  WasmEvent,
  WasmEngineHandle,
  WasmNodeId,
} from './worker/engineWasm.js';
