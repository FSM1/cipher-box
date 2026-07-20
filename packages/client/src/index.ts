/**
 * @cipherbox/client — WASM engine hosting and browser seams for the v2 web
 * client (blueprint/web-client.md).
 *
 * This slice lands every browser seam implementation (IndexedDB, OPFS, and
 * `fetch`) — the web side of the engine's host seam traits — and the
 * merge-blocking browser suite that runs the engine's Rust conformance kits
 * against them. The engine worker host, tab leadership, the facade transports,
 * and the Service Worker land in later slices.
 */
export const CLIENT_PACKAGE = '@cipherbox/client';

export * from './seams/index.js';
