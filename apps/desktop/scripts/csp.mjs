/**
 * The shell's Content-Security-Policy, built from the same environment that
 * decides which API this build talks to.
 *
 * The committed `tauri.conf.json` policy refuses the login the shell exists to
 * run, so the policy is widened here by exactly two things and nothing else:
 * the Web3Auth Core Kit's own hosts, and the configured API origin the identity
 * exchange posts to. Google is deliberately not here — its consent screen is
 * opened natively in a separate window, so the shell's own document never
 * reaches it.
 */

/** Must match `src/config.ts`; `csp.test.ts` holds the two together. */
export const DEFAULT_API_URL = 'http://localhost:3000';

/**
 * The two domains the Core Kit bundle names — its API, session and node hosts
 * under one, its metadata and signer hosts under the other. Wildcarded because
 * it picks a node per request; nothing beyond these two is allowed, and a
 * `wss:` upgrade to the same host is covered by CSP's scheme matching.
 */
const WEB3AUTH_HOSTS = ['https://*.web3auth.io', 'https://*.tor.us'];

/**
 * Tauri's own IPC endpoint, which every `invoke` posts to. Load-bearing for
 * secret hygiene rather than for connectivity: blocked, `invoke` falls back to
 * `postMessage`, which JSON-stringifies the login secret's buffer into a number
 * array no frame can scrub (`src/auth/facade.ts`). The committed
 * `tauri.conf.json` names it too, so a build that bypasses this script keeps
 * the raw-bytes transport.
 */
const TAURI_IPC = ['ipc:', 'http://ipc.localhost'];

/** The origin of `url`, or `null` when it does not parse as one. */
function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/**
 * @param {Record<string, string | undefined>} env
 * @returns {string}
 */
export function contentSecurityPolicy(env) {
  const apiOrigin = originOf(env.VITE_API_URL?.trim() || DEFAULT_API_URL);
  if (apiOrigin === null) throw new Error('VITE_API_URL is not a URL, so no policy can allow it');

  const connect = ["'self'", ...TAURI_IPC, apiOrigin, ...WEB3AUTH_HOSTS];

  return [
    "default-src 'self'",
    // The Core Kit's threshold signing runs in a WebAssembly module, which
    // WebKit and WebView2 both gate behind `wasm-unsafe-eval`.
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self'",
    "img-src 'self' data:",
    // …and it instantiates that module in a worker built from a blob URL.
    "worker-src 'self' blob:",
    `connect-src ${connect.join(' ')}`,
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'self'",
    "form-action 'none'",
  ].join('; ');
}
