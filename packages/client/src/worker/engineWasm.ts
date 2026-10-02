/**
 * The wasm-bindgen engine module, as the worker binds it. Every type here is the
 * generated `.d.ts`, the one boundary contract: the engine handle, the node id
 * and the free functions the worker drives.
 */

import type * as Glue from '../../wasm/cipherbox_wasm.js';

/** wasm-bindgen `NodeId` handle. */
export type WasmNodeId = Glue.NodeId;

/** wasm-bindgen `EngineHandle` — the one engine instance. */
export type WasmEngineHandle = Glue.EngineHandle;

/** The bindings of the wasm-bindgen module the worker uses. */
export type EngineWasm = Pick<
  typeof Glue,
  'EngineHandle' | 'NodeId' | 'deviceRendezvous' | 'identityFingerprint'
>;
