#!/usr/bin/env node
/**
 * The read-accelerator front's egress obligations (blueprint/api.md, Egress),
 * asserted against Caddy's ADAPTED config rather than the Caddyfile text — the
 * adapted JSON is what the server executes, so a directive that silently stops
 * taking effect still fails here. Adapting also proves the file parses, which
 * nothing else in CI does: it ships to the VPS by scp.
 *
 * The obligation is "nothing reaches an accelerator ungated", so the accelerator
 * UPSTREAMS are enumerated, never the vhosts — a new vhost proxying to one is
 * caught by default rather than by remembering to edit a list.
 *
 * Adapting runs under the image the stack ships, built here from its own
 * Dockerfile: the front uses a rate limiter stock Caddy does not carry, so an
 * adapt against stock would fail on the directive rather than check it.
 *
 * Usage: `node scripts/check-accelerator-front.mjs [caddyfile-directory]`.
 * Needs Docker; `caddy validate` is not used because it provisions the TLS app
 * and the origin certificates live only on the host.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CADDY_BUILD = resolve(repoRoot, 'docker/caddy');
/** Generates the staging env, so it holds the hop count the API actually runs. */
const DEPLOY_WORKFLOW = '.github/workflows/deploy-staging.yml';
const ACCELERATORS = ['ipfs:8080', 'someguy:8190'];
const VERIFY_PATH = '/auth/gateway/verify';
/** Anything that would tell the verify leg WHAT is being read, not merely who asks. */
const PATH_NAMING_HEADERS = [
  'X-Forwarded-Uri',
  'X-Forwarded-Method',
  'X-Forwarded-Host',
  'Range',
  'Accept',
  'Referer',
  'CF-Ray',
];
/** Cloudflare names the caller in headers of its own; CF-Ray joins its logs to a CID. */
const CALLER_NAMING_HEADERS = [
  'Authorization',
  'X-Forwarded-For',
  'CF-Connecting-IP',
  'CF-Connecting-IPv6',
  'CF-Pseudo-IPv4',
  'CF-EW-Via',
  'CF-Worker',
  'CF-IPCountry',
  'CF-Visitor',
  'CF-Ray',
  'CDN-Loop',
  'True-Client-IP',
  'X-Real-IP',
  'Forwarded',
];
/** The one leg the blueprint leaves open: a signed IPNS record authenticates itself. */
const PUBLISH_LEG = { method: 'PUT', path: '/routing/v1/ipns/*' };
/** Reads present the pseudonym, writes never do — so the gate admits nothing else. */
const READ_METHODS = ['GET', 'HEAD'];
const CLIENT_IP = '{http.vars.client_ip}';
/** The /64 the caller was delegated, not its chosen /128 (docker/Caddyfile). */
const PUBLISH_IPV6_PREFIX = 64;
/**
 * Cloudflare appends to X-Forwarded-For, so every entry left of the caller's own
 * is caller-written; CF-Connecting-IP it writes and overwrites itself.
 */
const CLIENT_IP_HEADER = 'CF-Connecting-IP';
/** A zone this loose bounds nothing; the leg carries no token to fall back on. */
const MAX_PUBLISH_EVENTS = 600;
/** The limiter's own namespace — it logs refusals whether or not `log_key` is on. */
const RATE_LIMIT_LOG = 'http.handlers.rate_limit';
/** The zone's own origin-pull CA. Cloudflare's shared one is presented by every tenant. */
const ORIGIN_PULL_CA = '/etc/caddy/certs/cloudflare-zone-origin-pull-ca.pem';
/** `verify_if_given` admits a caller that presents no certificate at all. */
const CLIENT_AUTH_MODE = 'require_and_verify';
/** cloudflare.com/ips — a hand-mirrored snapshot, so the set is pinned, not counted. */
const CLOUDFLARE_RANGES = [
  '173.245.48.0/20',
  '103.21.244.0/22',
  '103.22.200.0/22',
  '103.31.4.0/22',
  '141.101.64.0/18',
  '108.162.192.0/18',
  '190.93.240.0/20',
  '188.114.96.0/20',
  '197.234.240.0/22',
  '198.41.128.0/17',
  '162.158.0.0/15',
  '104.16.0.0/13',
  '104.24.0.0/14',
  '172.64.0.0/13',
  '131.0.72.0/22',
  '2400:cb00::/32',
  '2606:4700::/32',
  '2803:f800::/32',
  '2405:b500::/32',
  '2405:8100::/32',
  '2a06:98c0::/29',
  '2c0f:f248::/32',
];

const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

/** Every object in the tree, each with the chain of objects above it. */
function* walk(node, ancestors = []) {
  if (node === null || typeof node !== 'object') return;
  yield { node, ancestors };
  const inner = [...ancestors, node];
  for (const value of Object.values(node)) yield* walk(value, inner);
}

const caddyDir = resolve(process.argv[2] ?? 'docker');

/** Docker, or a readable failure — never a truncated one on a verbose build log. */
function docker(args, whatFailed) {
  const run = spawnSync('docker', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (run.status !== 0) {
    console.error(`${whatFailed}:\n${run.stderr ?? run.error}`);
    process.exit(1);
  }
  return run.stdout.trim();
}

// CI builds this image once with a layer cache and passes it in; a bare run
// builds it, so the config is always adapted under the binary that ships.
const image =
  process.env.CADDY_IMAGE ??
  docker(
    ['build', '--quiet', '--tag', 'cipherbox-caddy:lint', CADDY_BUILD],
    `${CADDY_BUILD}/Dockerfile does not build`
  );

const config = JSON.parse(
  docker(
    [
      'run',
      '--rm',
      '-v',
      `${caddyDir}:/etc/caddy:ro`,
      image,
      'caddy',
      'adapt',
      '--config',
      '/etc/caddy/Caddyfile',
    ],
    `${caddyDir}/Caddyfile does not adapt`
  )
);
const nodes = [...walk(config)];

const isVerify = (h) =>
  h?.handler === 'reverse_proxy' && String(h.rewrite?.uri ?? '').startsWith(VERIFY_PATH);
/** Where the verify subrequest sits in a handler list, or -1 when it holds none. */
const verifyAt = (n) => (Array.isArray(n?.handle) ? n.handle.findIndex(isVerify) : -1);
const isGate = (n) => verifyAt(n) >= 0;
/**
 * Caddy runs a handler list in order and `reverse_proxy` terminates, so a verify
 * that sits after the proxy it is meant to gate admits the read before running.
 */
const admits = (gate, chain) => {
  const at = gate.handle.findIndex((h) => chain.includes(h));
  return at > verifyAt(gate);
};
/** Every handler that runs ahead of `chain`, in each list `chain` passes through. */
function* precursors(chain) {
  for (const node of chain) {
    if (!Array.isArray(node.handle)) continue;
    const at = node.handle.findIndex((h) => chain.includes(h));
    if (at > 0) yield* node.handle.slice(0, at);
  }
}
const dials = (h) => (h.upstreams ?? []).map((u) => u.dial);

// Matcher sets in one `match` are OR-ed, as are the values inside a `method` or
// `path` array, so a route narrows a request only when EVERY set narrows it: a
// second set, or a second value, is another way in.
const narrowedBy = (holds) => (route) =>
  Array.isArray(route.match) && route.match.length > 0 && route.match.every(holds);
const readOnly = (m) =>
  (m.method ?? []).length > 0 && m.method.every((v) => READ_METHODS.includes(v));
const publishOnly = (m) =>
  (m.method ?? []).length === 1 &&
  m.method[0] === PUBLISH_LEG.method &&
  (m.path ?? []).length === 1 &&
  m.path[0] === PUBLISH_LEG.path;

const hostOf = (ancestors) =>
  ancestors.flatMap((a) => (a.match ?? []).flatMap((m) => m.host ?? []))[0] ?? 'an unnamed vhost';

const gates = nodes.filter(({ node }) => isGate(node));
check(gates.length > 0, 'no gated route in the adapted config');

const frontVhosts = new Set();
for (const { node, ancestors } of gates) {
  const vhost = hostOf([...ancestors, node]);
  frontVhosts.add(vhost);
  const leg = node.handle.find(isVerify);
  const deleted = leg.headers?.request?.delete ?? [];

  for (const header of PATH_NAMING_HEADERS) {
    check(deleted.includes(header), `${vhost}: verify leg does not delete ${header}`);
  }
  check(
    !deleted.includes('X-Forwarded-For'),
    `${vhost}: verify leg drops X-Forwarded-For, so the surface cannot rate-limit per member`
  );
  check(
    leg.rewrite.uri === `${VERIFY_PATH}?`,
    `${vhost}: verify leg forwards the original query string`
  );

  const responses = leg.handle_response ?? [];
  const admits = responses.filter((r) => (r.match?.status_code ?? []).includes(204));
  const [refuses] = responses.filter((r) => r.match === undefined);
  check(admits.length === 1, `${vhost}: verify leg does not single out 204`);
  check(
    refuses !== undefined &&
      [...walk(refuses)].some(({ node: n }) => n.handler === 'static_response'),
    `${vhost}: verify leg has no catch-all refusal for a non-204`
  );

  check(
    node.handle.some((h) => h.handler === 'reverse_proxy' && h !== leg),
    `${vhost}: the gate admits nothing`
  );

  // Named loggers with `output discard`: neither the pseudonym nor a client IP
  // is written beside a read, and Caddy's error log carries both.
  const logger = [...walk(config)]
    .flatMap(({ node: n }) => Object.entries(n.logs?.logger_names ?? {}))
    .filter(([host]) => host === vhost)
    .flatMap(([, name]) => (Array.isArray(name) ? name : [name]));
  check(logger.length > 0, `${vhost}: access log is not routed to a named logger`);
  for (const name of logger) {
    check(
      config.logging?.logs?.[name]?.writer?.output === 'discard',
      `${vhost}: access logger ${name} is not discarded`
    );
    const errorSinks = Object.values(config.logging?.logs ?? {}).filter((log) =>
      (log.include ?? []).includes(`http.log.error.${name}`)
    );
    check(
      errorSinks.length > 0 && errorSinks.every((log) => log.writer?.output === 'discard'),
      `${vhost}: http.log.error.${name} is not discarded`
    );
  }
}

// The limiter logs a line per refusal under a namespace of its own, outside any
// vhost's access log, so a silent vhost does not cover it.
const rateLimitSinks = Object.values(config.logging?.logs ?? {}).filter((log) =>
  (log.include ?? []).includes(RATE_LIMIT_LOG)
);
check(
  rateLimitSinks.length > 0 && rateLimitSinks.every((log) => log.writer?.output === 'discard'),
  `${RATE_LIMIT_LOG} is not discarded, so a refusal reaches a sink that ships offsite`
);

// Every proxy to an accelerator is gated, bar the one open publish leg — and none
// of them carry anything that re-identifies the reader into an upstream's logs,
// which ship offsite: the pseudonym names the session, the client address the
// account.
for (const { node, ancestors } of nodes) {
  if (node.handler !== 'reverse_proxy') continue;
  const target = dials(node).filter((dial) => ACCELERATORS.includes(dial));
  if (target.length === 0) continue;

  const vhost = hostOf(ancestors);
  const deleted = node.headers?.request?.delete ?? [];
  for (const header of CALLER_NAMING_HEADERS) {
    check(
      deleted.includes(header),
      `${vhost}: proxy to ${target} does not strip ${header} before the upstream`
    );
  }

  const chain = [...ancestors, node];
  if (ancestors.some((a) => isGate(a) && admits(a, chain))) {
    check(
      ancestors.some(narrowedBy(readOnly)),
      `${vhost}: gated proxy to ${target} is not held to ${READ_METHODS.join('/')}`
    );
    continue;
  }

  check(
    ancestors.some(narrowedBy(publishOnly)),
    `${vhost}: proxy to ${target} reaches an accelerator ungated, and is not the ${PUBLISH_LEG.method} ${PUBLISH_LEG.path} publish leg`
  );

  const ahead = [...precursors(chain)];
  const limiters = ahead.filter((h) => h.handler === 'rate_limit');
  const zones = limiters.flatMap((h) => Object.values(h.rate_limits ?? {}));
  check(zones.length > 0, `${vhost}: the open publish leg runs unrated into ${target}`);
  check(
    zones.every((z) => z.key === CLIENT_IP),
    `${vhost}: a publish-leg rate zone does not key on ${CLIENT_IP}, so a caller picks its own bucket`
  );
  check(
    zones.every((z) => z.ipv6_prefix > 0 && z.ipv6_prefix <= PUBLISH_IPV6_PREFIX),
    `${vhost}: a publish-leg rate zone does not mask its key to a /${PUBLISH_IPV6_PREFIX} or shorter, so an IPv6 caller rotates for a fresh bucket`
  );
  check(
    zones.every((z) => z.max_events <= MAX_PUBLISH_EVENTS && z.window > 0),
    `${vhost}: a publish-leg rate zone admits more than ${MAX_PUBLISH_EVENTS} events a window, which bounds nothing`
  );
  check(
    !limiters.some((h) => h.log_key),
    `${vhost}: the publish rate limiter logs its key, putting a member address in a sink that ships offsite`
  );
}

// Trusting the proxy in front and the API's hop count are one setting in two
// files: Caddy discards an untrusted peer's X-Forwarded-For and forwards one
// entry of its own, and preserves a trusted one's beside it. Move either alone
// and every IP-keyed limit keys on the wrong address — an edge POP when the
// count is short, a caller-written entry when it overshoots.
const servers = Object.entries(config.apps?.http?.servers ?? {});
check(servers.length > 0, 'no http server in the adapted config');
const sameSet = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
for (const [name, server] of servers) {
  const trusted = server.trusted_proxies ?? {};
  check(
    trusted.source === 'static' && sameSet(trusted.ranges ?? [], CLOUDFLARE_RANGES),
    `server ${name}: trusted_proxies is not exactly the Cloudflare set — a broader one makes an outsider a trusted proxy`
  );
  check(
    server.trusted_proxies_strict === 1,
    `server ${name}: trusted_proxies_strict is off, so {client_ip} is the caller-written X-Forwarded-For entry`
  );
  check(
    sameSet(server.client_ip_headers ?? [], [CLIENT_IP_HEADER]),
    `server ${name}: {client_ip} does not come from ${CLIENT_IP_HEADER}, so a caller behind the same proxy can prepend its own`
  );
}

// Caddy routes on Host and not on SNI, and it appends a matcher-less policy of
// its own when a config leaves the fallback unwritten — so every policy is
// held, not the fronted vhosts' own (blueprint/deploy.md).
const sniOf = (policy) =>
  (policy.match?.sni ?? []).length > 0
    ? ` for ${policy.match.sni.join(', ')}`
    : ' matching any other SNI';
const policies = servers.flatMap(([name, server]) =>
  (server.tls_connection_policies ?? []).map((policy) => ({ name, policy }))
);
check(policies.length > 0, 'no TLS connection policy in the adapted config');
for (const { name, policy } of policies) {
  const auth = policy.client_authentication;
  check(
    auth?.mode === CLIENT_AUTH_MODE,
    `server ${name}: the policy${sniOf(policy)} does not ${CLIENT_AUTH_MODE} a client certificate, so an unauthenticated caller reaches the origin`
  );
  check(
    auth?.ca?.provider === 'file' && sameSet(auth.ca.pem_files ?? [], [ORIGIN_PULL_CA]),
    `server ${name}: the policy${sniOf(policy)} does not verify against exactly ${ORIGIN_PULL_CA}, so a certificate issued to another Cloudflare tenant passes`
  );
}

// Trusting the proxy in front and the API's hop count are one setting in two
// files: an untrusted peer's X-Forwarded-For is replaced by a single entry of
// Caddy's, a trusted one's is kept with Caddy's beside it.
const trustedInFront = servers.every(([, s]) => (s.trusted_proxies?.ranges ?? []).length > 0);
const arriving = trustedInFront ? 2 : 1;
const declared = readFileSync(resolve(repoRoot, DEPLOY_WORKFLOW), 'utf8').match(
  /^\s*TRUST_PROXY_HOPS=(\d+)\s*$/gm
);
check(
  declared?.length === 1,
  `${DEPLOY_WORKFLOW}: expected exactly one TRUST_PROXY_HOPS, found ${declared?.length ?? 0}`
);
if (declared?.length === 1) {
  const hops = Number(/(\d+)/.exec(declared[0])[1]);
  check(
    hops === arriving,
    `${DEPLOY_WORKFLOW}: TRUST_PROXY_HOPS is ${hops}, but this Caddyfile forwards ${arriving} X-Forwarded-For entries`
  );
}

// A gateway varies on more than the origin, so setting the field drops the
// upstream's own members and lets a cache serve one variant for another.
const appendsVary = new Set();
for (const { node, ancestors } of nodes) {
  if (node.handler !== 'headers') continue;
  const vhost = hostOf(ancestors);
  if (!frontVhosts.has(vhost)) continue;
  check(
    !Object.keys(node.response?.set ?? {}).some((field) => field.toLowerCase() === 'vary'),
    `${vhost}: Vary is set rather than appended, dropping the upstream's own members`
  );
  if ((node.response?.add?.Vary ?? []).includes('Origin')) appendsVary.add(vhost);
}
for (const vhost of frontVhosts) {
  check(
    appendsVary.has(vhost),
    `${vhost}: does not append Vary: Origin beside the per-origin CORS headers`
  );
}

if (failures.length > 0) {
  console.error('Accelerator front obligations violated:');
  for (const failure of failures) console.error(`  - ${failure}`);
  // Not `process.exit`, which can truncate the list above on a piped stderr.
  process.exitCode = 1;
} else {
  console.log(`Accelerator front obligations hold for ${ACCELERATORS.join(', ')}.`);
}
