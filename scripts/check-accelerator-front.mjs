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
const PATH_NAMING_HEADERS = ['X-Forwarded-Uri', 'X-Forwarded-Method', 'X-Forwarded-Host'];
/** The one leg the blueprint leaves open: a signed IPNS record authenticates itself. */
const PUBLISH_LEG = { method: 'PUT', path: '/routing/v1/ipns/*' };
/** Reads present the pseudonym, writes never do — so the gate admits nothing else. */
const READ_METHODS = ['GET', 'HEAD'];
/** Resolves through `trusted_proxies`, so the bucket is a caller, not an edge POP. */
const RATE_LIMIT_KEY = '{http.vars.client_ip}';

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
const built = spawnSync(
  'docker',
  ['build', '--quiet', '--file', `${CADDY_BUILD}/Dockerfile`, CADDY_BUILD],
  { encoding: 'utf8' }
);
if (built.status !== 0) {
  console.error(`${CADDY_BUILD}/Dockerfile does not build:\n${built.stderr ?? built.error}`);
  process.exitCode = 1;
  process.exit();
}

const adapted = spawnSync(
  'docker',
  [
    'run',
    '--rm',
    '-v',
    `${caddyDir}:/etc/caddy:ro`,
    built.stdout.trim(),
    'caddy',
    'adapt',
    '--config',
    '/etc/caddy/Caddyfile',
  ],
  { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
);
if (adapted.status !== 0) {
  console.error(`${caddyDir}/Caddyfile does not adapt:\n${adapted.stderr ?? adapted.error}`);
  process.exitCode = 1;
  process.exit();
}

const config = JSON.parse(adapted.stdout);
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
  for (const header of ['Authorization', 'X-Forwarded-For']) {
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

  // The publish leg presents no token by design, so a bounded rate is the only
  // thing standing between one address and someguy.
  const zones = [...precursors(chain)]
    .filter((h) => h.handler === 'rate_limit')
    .flatMap((h) => Object.values(h.rate_limits ?? {}));
  check(zones.length > 0, `${vhost}: the open publish leg runs unrated into ${target}`);
  check(
    zones.every((z) => z.key === RATE_LIMIT_KEY),
    `${vhost}: a publish-leg rate zone does not key on ${RATE_LIMIT_KEY}, so it buckets every caller behind a proxy together`
  );
}

// Trusting the proxy in front and the API's hop count are one setting in two
// files: Caddy discards an untrusted peer's X-Forwarded-For and forwards one
// entry of its own, and preserves a trusted one's beside it. Move either alone
// and every IP-keyed limit keys on the wrong address — an edge POP when the
// count is short, a caller-written entry when it overshoots.
const servers = Object.entries(config.apps?.http?.servers ?? {});
check(servers.length > 0, 'no http server in the adapted config');
for (const [name, server] of servers) {
  check(
    server.trusted_proxies?.source === 'static' &&
      (server.trusted_proxies?.ranges ?? []).length > 0,
    `server ${name}: no static trusted_proxies, so an IP-keyed limit buckets a whole edge POP`
  );
  // Unset, `{client_ip}` is the leftmost X-Forwarded-For entry — the one the
  // caller writes — and a limit keyed on it hands out buckets on request.
  check(
    server.trusted_proxies_strict === 1,
    `server ${name}: trusted_proxies_strict is off, so {client_ip} is the caller-written X-Forwarded-For entry`
  );
}

const arriving = [
  ...new Set(servers.map(([, s]) => ((s.trusted_proxies?.ranges ?? []).length > 0 ? 2 : 1))),
];
check(arriving.length <= 1, 'servers disagree on whether the proxy in front is trusted');
const declared = /^\s*TRUST_PROXY_HOPS=(\d+)\s*$/m.exec(
  readFileSync(resolve(repoRoot, DEPLOY_WORKFLOW), 'utf8')
);
check(declared !== null, `${DEPLOY_WORKFLOW}: the staging env declares no TRUST_PROXY_HOPS`);
if (declared !== null && arriving.length === 1) {
  check(
    Number(declared[1]) === arriving[0],
    `${DEPLOY_WORKFLOW}: TRUST_PROXY_HOPS is ${declared[1]}, but this Caddyfile forwards ${arriving[0]} X-Forwarded-For entries`
  );
}

// A gateway varies on more than the origin, so setting the field drops the
// upstream's own members and lets a cache serve one variant for another.
for (const { node, ancestors } of nodes) {
  if (node.handler !== 'headers') continue;
  const vhost = hostOf([...ancestors, node]);
  if (!frontVhosts.has(vhost)) continue;
  check(
    !Object.keys(node.response?.set ?? {}).some((field) => field.toLowerCase() === 'vary'),
    `${vhost}: Vary is set rather than appended, dropping the upstream's own members`
  );
}
for (const vhost of frontVhosts) {
  check(
    nodes.some(
      ({ node, ancestors }) =>
        node.handler === 'headers' &&
        hostOf([...ancestors, node]) === vhost &&
        (node.response?.add?.Vary ?? []).includes('Origin')
    ),
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
