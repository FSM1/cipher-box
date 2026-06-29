/**
 * @cipherbox/core - Node Codec Public Surface
 *
 * Re-export barrel for the node/ subdirectory.
 *
 * This file contains ZERO logic (no function bodies, no arrow functions).
 * vitest.config.ts excludes src/**\/index.ts from coverage — all
 * seal logic lives in seal.ts (a named file counted by coverage).
 *
 * Consumer: packages/core/src/index.ts barrel cutover (Plan 05).
 * Do NOT import from this file in Plan 02 — Plan 05 owns that wiring.
 */

export { encodeReadBody, encodeWriteBody, serializeContentForWire } from './encode';
export {
  decodeReadBody,
  decodeWriteBody,
  deserializeContentFromWire,
  validateNode,
} from './decode';
export {
  sealNode,
  unsealNode,
  sealChildReadKey,
  unsealChildReadKey,
  sealContent,
  unsealContent,
} from './seal';
export type {
  Node,
  NodeKind,
  EncryptionMode,
  SealedChildRef,
  WriteChildRef,
  NodeWriteBody,
  NodeContent,
  VersionEntry,
  PublishedNode,
} from './types';
