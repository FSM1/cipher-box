/**
 * The security headers the app origin serves, defined once and applied at every
 * serving layer: Vite's dev and preview servers take them from here, and the
 * staging vhost imports the `docker/csp.caddy` this module generates. No
 * environment is then looser than the one a change is written against.
 *
 * `frame-ancestors` is header-only — a `<meta http-equiv>` policy drops the
 * directive — which is why every layer sets a header rather than the document
 * carrying the policy.
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

/** What every environment serving the built app sets. */
export const SERVED_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy': policy(SCRIPT_SRC),
  'X-Content-Type-Options': 'nosniff',
  // The Web3Auth login popup posts its result back to the opener, which plain
  // `same-origin` severs.
  'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
};

/**
 * The dev server's headers: the served ones, widened only where dev must be.
 * The policy adds the inline script Vite's React-refresh preamble needs and
 * nothing else, so a dev build cannot pass what staging refuses.
 */
export const DEV_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  ...SERVED_SECURITY_HEADERS,
  'Content-Security-Policy': policy([...SCRIPT_SRC, "'unsafe-inline'"]),
  // Lets the dev worker at /src/sw.ts claim the root scope it needs.
  'Service-Worker-Allowed': '/',
};

/**
 * The Caddy `header` block the staging vhost imports, so a policy edit here
 * reaches the deployed origin without a second edit.
 */
export const CADDY_SECURITY_HEADERS = [
  '# Generated from apps/web/src/csp.ts. Run `pnpm --filter @cipherbox/web csp:caddy` to update.',
  'header {',
  ...Object.entries(SERVED_SECURITY_HEADERS).map(
    ([name, value]) => `\t${name} ${JSON.stringify(value)}`
  ),
  '}',
  '',
].join('\n');
