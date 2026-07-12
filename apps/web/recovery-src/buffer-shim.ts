/**
 * Browser `Buffer` polyfill for the recovery bundle.
 *
 * `@cipherbox/crypto`'s ECIES unwrap uses `eciesjs`, which references the Node
 * global `Buffer` internally (e.g. `Buffer.from(...)`). esbuild's
 * `platform: 'browser'` does NOT polyfill Node globals, so in-browser every
 * `unwrapKey` throws `Buffer is not defined`. build.ts `inject`s this module so
 * esbuild rewrites unbound `Buffer` references to this pure-JS implementation,
 * keeping the recovery tool fully self-contained (no CDN, no SDK/API) while
 * letting the gateway-only recovery walk decrypt in the browser.
 */
import { Buffer } from 'buffer';

export { Buffer };
