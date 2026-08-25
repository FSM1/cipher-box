#!/usr/bin/env node
/**
 * The read-accelerator front's egress obligations (blueprint/api.md, Egress),
 * asserted against Caddy's ADAPTED config rather than the Caddyfile text — the
 * adapted JSON is what the server executes, so a directive that silently stops
 * taking effect still fails here. Adapting also proves the file parses, which
 * nothing else in CI does: it ships to the VPS by scp.
 *
 * Usage: `node scripts/check-accelerator-front.mjs [caddyfile-directory]`.
 * Needs Docker; `caddy validate` is not used because it provisions the TLS app
 * and the origin certificates live only on the host.
 */

import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const VHOSTS = ['gateway-staging.cipherbox.cc', 'routing-staging.cipherbox.cc'];
const VERIFY_PATH = '/auth/gateway/verify';
const PATH_NAMING_HEADERS = ['X-Forwarded-Uri', 'X-Forwarded-Method', 'X-Forwarded-Host'];

const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

/** Every object in the tree, depth-first. */
function* walk(node) {
  if (node === null || typeof node !== 'object') return;
  yield node;
  for (const value of Object.values(node)) yield* walk(value);
}

const caddyDir = resolve(process.argv[2] ?? 'docker');
const adapted = spawnSync(
  'docker',
  [
    'run',
    '--rm',
    '-v',
    `${caddyDir}:/etc/caddy:ro`,
    'caddy:2-alpine',
    'caddy',
    'adapt',
    '--config',
    '/etc/caddy/Caddyfile',
  ],
  { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
);
if (adapted.status !== 0) {
  console.error(`${caddyDir}/Caddyfile does not adapt:\n${adapted.stderr ?? adapted.error}`);
  process.exit(1);
}

const config = JSON.parse(adapted.stdout);
const servers = Object.values(config.apps?.http?.servers ?? {});

for (const vhost of VHOSTS) {
  // The route subtree Caddy built for this host, wherever it landed.
  const routes = servers
    .flatMap((server) => server.routes ?? [])
    .filter((route) => (route.match ?? []).some((m) => (m.host ?? []).includes(vhost)));
  check(routes.length > 0, `${vhost}: no route in the adapted config`);

  const nodes = [...routes.flatMap((route) => [...walk(route)])];

  // A gate is one handler list holding the verify subrequest; whatever else it
  // proxies is what that verify decision admits.
  const isVerify = (h) => h.handler === 'reverse_proxy' && h.rewrite?.uri?.startsWith(VERIFY_PATH);
  const gates = nodes
    .filter((n) => Array.isArray(n.handle) && n.handle.some(isVerify))
    .map((n) => n.handle);
  check(gates.length === 1, `${vhost}: expected exactly one gated route, found ${gates.length}`);

  for (const gate of gates) {
    const leg = gate.find(isVerify);
    const deleted = leg.headers?.request?.delete ?? [];
    for (const header of PATH_NAMING_HEADERS) {
      check(deleted.includes(header), `${vhost}: verify leg does not delete ${header}`);
    }
    check(
      !leg.headers?.request?.delete?.includes('X-Forwarded-For'),
      `${vhost}: verify leg drops X-Forwarded-For, so the surface cannot rate-limit per member`
    );
    check(
      leg.rewrite.uri === `${VERIFY_PATH}?`,
      `${vhost}: verify leg forwards the original query string`
    );
    // Exactly one 204 pass-through, and a catch-all that denies everything else.
    const responses = leg.handle_response ?? [];
    const pass = responses.filter((r) => (r.match?.status_code ?? []).includes(204));
    const deny = responses.filter((r) => r.match === undefined);
    check(pass.length === 1, `${vhost}: verify leg does not single out 204`);
    check(deny.length === 1, `${vhost}: verify leg has no catch-all deny for a non-204`);
    check(
      deny.every((r) => [...walk(r)].some((n) => n.handler === 'static_response')),
      `${vhost}: verify leg's non-204 branch does not answer with a refusal`
    );

    const admitted = gate.filter((h) => h.handler === 'reverse_proxy' && h !== leg);
    check(admitted.length > 0, `${vhost}: the gate admits nothing`);
    for (const content of admitted) {
      const target = (content.upstreams ?? []).map((u) => u.dial).join(',');
      check(
        (content.headers?.request?.delete ?? []).includes('Authorization'),
        `${vhost}: proxy to ${target} does not strip Authorization before the upstream`
      );
    }
  }

  // A named logger with `output discard`, so neither the pseudonym nor a client
  // IP is written beside a read.
  const logName = servers
    .flatMap((s) => Object.entries(s.logs?.logger_names ?? {}))
    .filter(([host]) => host === vhost)
    .flatMap(([, name]) => (Array.isArray(name) ? name : [name]));
  check(logName.length > 0, `${vhost}: access log is not routed to a named logger`);
  for (const name of logName) {
    const writer = config.logging?.logs?.[name]?.writer?.output;
    check(writer === 'discard', `${vhost}: logger ${name} writes access lines to ${writer}`);
  }
}

// Caddy's error log carries client_ip and the requested uri, so it must be
// discarded too — the access logger alone does not cover it.
const errorSinks = Object.values(config.logging?.logs ?? {}).filter((log) =>
  (log.include ?? []).some((namespace) => namespace.startsWith('http.log.error.'))
);
check(errorSinks.length > 0, 'no logger claims the front’s http.log.error namespace');
check(
  errorSinks.every((log) => log.writer?.output === 'discard'),
  'the front’s error log is not discarded'
);

if (failures.length > 0) {
  console.error('Accelerator front obligations violated:');
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log(`Accelerator front obligations hold for ${VHOSTS.join(', ')}.`);
