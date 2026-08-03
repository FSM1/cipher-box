/**
 * Node-id addressing for the UI. Routes and UI-owned state key on the stable
 * node id (blueprint/web-client.md "UI state law"), carried in a URL as
 * lowercase hex through the client package's one hex codec.
 */

import { fromHex, toHex } from '@cipherbox/client';

/** A node id is 16 raw bytes (`crates/core` `NodeId`). */
const NODE_ID_BYTES = 16;

/** What the `/files/:nodeId?` param addresses. */
export type FolderRoute = { kind: 'root' } | { kind: 'node'; id: Uint8Array } | { kind: 'invalid' };

/** Resolves a route param; anything that is not a node id resolves invalid. */
export function folderRoute(param: string | undefined): FolderRoute {
  if (param === undefined) return { kind: 'root' };
  if (param.length !== NODE_ID_BYTES * 2) return { kind: 'invalid' };
  try {
    return { kind: 'node', id: fromHex(param) };
  } catch {
    return { kind: 'invalid' };
  }
}

/** The vault-browser route for a node id; `null` addresses the current root. */
export function folderPath(id: Uint8Array | null): string {
  return id === null ? '/files' : `/files/${toHex(id)}`;
}

/** Node ids compare by value: callers hand in a fresh array per render. */
export function sameNode(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
