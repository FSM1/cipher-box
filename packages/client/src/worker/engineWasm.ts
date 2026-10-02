/**
 * The wasm-bindgen engine module, as the worker binds it. Every type here is the
 * generated `.d.ts`, the one boundary contract: the engine handle, the node id
 * and the free functions the worker drives.
 */

import type * as Glue from '../../wasm/cipherbox_wasm.js';
import type { EngineHandle, NodeId } from '../../wasm/cipherbox_wasm.js';

/** wasm-bindgen `NodeId` handle. */
export type WasmNodeId = NodeId;

/** wasm-bindgen `EngineHandle` — the one engine instance. */
export type WasmEngineHandle = EngineHandle;

/** The bindings of the wasm-bindgen module the worker uses. */
export type EngineWasm = Pick<
  typeof Glue,
  'EngineHandle' | 'NodeId' | 'deviceRendezvous' | 'identityFingerprint'
>;
