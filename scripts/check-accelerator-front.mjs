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
 * Usage: `node scripts/check-accelerator-front.mjs [caddyfile-directory]`.
 * Needs Docker; `caddy validate` is not used because it provisions the TLS app
 * and the origin certificates live only on the host.
 */

import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const CADDY_IMAGE = 'caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648';
const ACCELERATORS = ['ipfs:8080', 'someguy:8190'];
const VERIFY_PATH = '/auth/gateway/verify';
const PATH_NAMING_HEADERS = ['X-Forwarded-Uri', 'X-Forwarded-Method', 'X-Forwarded-Host'];
/** The one leg the blueprint leaves open: a signed IPNS record authenticates itself. */
const PUBLISH_LEG = { method: 'PUT', path: '/routing/v1/ipns/*' };
/** Reads present the pseudonym, writes never do — so the gate admits nothing else. */
const READ_METHODS = ['GET', 'HEAD'];

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
const adapted = spawnSync(
  'docker',
  [
    'run',
    '--rm',
    '-v',
    `${caddyDir}:/etc/caddy:ro`,
    CADDY_IMAGE,
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

for (const { node, ancestors } of gates) {
  const vhost = hostOf([...ancestors, node]);
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
}

if (failures.length > 0) {
  console.error('Accelerator front obligations violated:');
  for (const failure of failures) console.error(`  - ${failure}`);
  // Not `process.exit`, which can truncate the list above on a piped stderr.
  process.exitCode = 1;
} else {
  console.log(`Accelerator front obligations hold for ${ACCELERATORS.join(', ')}.`);
}
