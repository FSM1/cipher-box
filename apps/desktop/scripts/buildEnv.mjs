/**
 * The environment this build's three products must agree on: the frontend
 * bundle, the CSP, and the compiled shell.
 *
 * The webview posts the identity exchange to the API `src/config.ts` resolves,
 * and the engine logs in against the API it was compiled with
 * (`src-tauri/src/engine/config.rs`). A token minted by one API is worthless at
 * another, so every fallback is applied once, here, and handed to all three —
 * rather than defaulted a second time in Rust, where the two could drift.
 */

import { DEFAULT_API_URL } from './csp.mjs';

/** The public delegated-routing endpoint web falls back to (`apps/web`). */
const DEFAULT_ROUTING_ENDPOINTS = 'https://delegated-ipfs.dev';

/**
 * The build-time variables to hand the Tauri CLI's children, resolved. The
 * engine refuses to start without either of these, so a working-copy build
 * gets the same defaults a working-copy web build does.
 *
 * @param {Record<string, string | undefined>} env
 * @returns {Record<string, string>}
 */
export function engineBuildEnv(env) {
  return {
    VITE_API_URL: env.VITE_API_URL?.trim() || DEFAULT_API_URL,
    VITE_ROUTING_ENDPOINTS: env.VITE_ROUTING_ENDPOINTS?.trim() || DEFAULT_ROUTING_ENDPOINTS,
  };
}
