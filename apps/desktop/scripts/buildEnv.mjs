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

/** The builds the footer has a licence arm for (`src/frontDoor.tsx`). */
const DESKTOP_PLATFORMS = ['windows', 'macos', 'linux'];

/**
 * Which mount backend a bundle built here ships, and so which licence notices
 * its footer owes. Read from the build host, which the release matrix runs one
 * target on.
 *
 * @param {NodeJS.Platform} platform
 * @returns {'windows' | 'macos' | 'linux'}
 */
export function desktopPlatform(platform = process.platform) {
  if (platform === 'win32') return 'windows';
  if (platform === 'darwin') return 'macos';
  return 'linux';
}

/**
 * The same value for a caller that cross builds and names its own target. A
 * token outside the vocabulary is refused rather than defaulted: every spelling
 * this cannot read resolves to one arm, which drops the notices of the others.
 *
 * @param {Record<string, string | undefined>} env
 * @returns {string}
 */
export function desktopPlatformOf(env) {
  const named = env.VITE_DESKTOP_PLATFORM?.trim();
  if (!named) return desktopPlatform();
  if (!DESKTOP_PLATFORMS.includes(named)) {
    throw new Error(`VITE_DESKTOP_PLATFORM must be one of ${DESKTOP_PLATFORMS.join(', ')}`);
  }
  return named;
}

/**
 * The build-time variables to hand the Tauri CLI's children, resolved. The
 * engine refuses to start without the two it reads, so a working-copy build
 * gets the same defaults a working-copy web build does.
 *
 * @param {Record<string, string | undefined>} env
 * @returns {Record<string, string>}
 */
export function engineBuildEnv(env) {
  return {
    VITE_API_URL: env.VITE_API_URL?.trim() || DEFAULT_API_URL,
    VITE_ROUTING_ENDPOINTS: env.VITE_ROUTING_ENDPOINTS?.trim() || DEFAULT_ROUTING_ENDPOINTS,
    VITE_DESKTOP_PLATFORM: desktopPlatformOf(env),
  };
}
