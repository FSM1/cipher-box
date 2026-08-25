/**
 * The Content-Security-Policy the app origin serves, so no other page can frame
 * a signed-in vault and drive it.
 *
 * `frame-ancestors` is header-only — a `<meta http-equiv>` policy drops the
 * directive — so this is applied at every serving layer instead: Vite's dev and
 * preview servers from here, and the staging vhost from `docker/Caddyfile`,
 * which `csp.test.ts` holds to the same string.
 *
 * `default-src` is deliberately absent: `connect-src` would then have to
 * enumerate the API, routing and gateway origins a build takes from its
 * environment, and a policy authored ahead of those goes stale silently.
 */

const SCRIPT_SRC = [
  "'self'",
  // Chromium blocks every WebAssembly compilation without this, which kills the
  // engine worker and the Core Kit's threshold-signing module.
  "'wasm-unsafe-eval'",
  // Google Identity Services serves the sign-in button's script from its own origin.
  'https://accounts.google.com/gsi/client',
];

function policy(scriptSrc: readonly string[]): string {
  return [
    `script-src ${scriptSrc.join(' ')}`,
    // The Core Kit instantiates its signing module in a worker built from a blob URL.
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

/** What a served bundle carries — preview here, Caddy on staging. */
export const CONTENT_SECURITY_POLICY = policy(SCRIPT_SRC);

/**
 * The dev server's policy: the served one plus the inline-script allowance
 * Vite's React-refresh preamble needs. Every other directive is the served one,
 * so a dev build cannot pass what staging refuses.
 */
export const DEV_CONTENT_SECURITY_POLICY = policy([...SCRIPT_SRC, "'unsafe-inline'"]);
