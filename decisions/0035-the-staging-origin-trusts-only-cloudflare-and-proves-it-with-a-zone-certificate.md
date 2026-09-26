# ADR 0035 — The staging origin trusts only Cloudflare and proves it with a zone certificate

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1461,
  FSM1/cipher-box#1504, FSM1/cipher-box#1526 and FSM1/cipher-box#1833, and the blueprint
  carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:** [#48](https://github.com/FSM1/cipher-box-next/issues/48) (the deploy
  blueprint thread, the staging stack and the scheduled tier), the scope decision of
  2026-08-25 on FSM1/cipher-box#1387 (the front covers both read legs, and the `/routing/v1`
  PUT publish leg stays open with IP-keyed rate limiting as its abuse control), the
  `blueprint/deploy.md` "The staging stack" and "Scheduled tier" sections, the
  `blueprint/api.md` "Egress" bullets, the `blueprint/testing.md` "CI gates" section (the
  dispatch and scheduled tier), and the `CONTEXT.md` terms "Read accelerator" and
  "Accelerator token"
- **Implemented by:** FSM1/cipher-box#1461 (the hop-count rule, D2, and the Lint gate over the
  adapted config, D6), FSM1/cipher-box#1504 (the Cloudflare ranges and the hop count as one
  unit, D1, the client address source, D3, and the publish-leg rate and its shape, D7 and D8),
  FSM1/cipher-box#1526 (the zone origin-pull certificate, D4, and its reach, D5) and
  FSM1/cipher-box#1833 (the Cloudflare Range Watch, D9). The cutover deploy of
  FSM1/cipher-box#1390 armed D4 on the staging host on 2026-09-13 (run 34776866429).

## Context

The staging stack runs on one VPS behind Cloudflare. Caddy terminates the origin TLS and routes
four vhosts: `api-staging`, `app-staging`, `gateway-staging` and `routing-staging`. The last
two are the read-accelerator front (`blueprint/api.md` "Egress"). Only Caddy publishes a public
HTTP port. The API, Postgres, and the Kubo RPC and gateway ports bind to `127.0.0.1` in
`docker/docker-compose.staging.yml`. The someguy container publishes only its libp2p swarm port.

Every IP-keyed limit in the stack needs the member's own address. The API throttles login,
refresh, session mint and gateway verify per client address. The open publish leg needs a
per-caller rate. FSM1/cipher-box#1461 found that the API resolved no client address at all.
Express `trust proxy` was never set, so `req.ip` was the Caddy container. The whole internet
shared one bucket, and the 10/min auth cap was a global availability limit. That PR added
`TRUST_PROXY_HOPS` as a hop count and set it to 1. With no `trusted_proxies`, Caddy replaced
the `X-Forwarded-For` header that Cloudflare sent with one entry of its own. The API then keyed
on a Cloudflare edge POP. A caller could not write that key, but many members shared it.

FSM1/cipher-box#1504 gave Caddy Cloudflare's published ranges as `trusted_proxies` and moved the
hop count to 2. Its review found three ways in which the first draft bounded nothing. One of
them is D3: `X-Forwarded-For` has a caller-written prefix, because Cloudflare appends to it.

The same review found a larger gap and filed it as FSM1/cipher-box#1507. The ranges belong to
Cloudflare, not to this zone. Any Cloudflare tenant, free tier included, can point a proxied
record at the origin address, override the origin `Host`, and arrive from inside a trusted
range. The attacker needs only the origin IP. Caddy then treats an unauthenticated proxy as
trusted, and every IP-keyed limit rests on that premise. The origin also answered on its own
address, so an edge-only control was walked around.

On 2026-08-26 the owner set the fix on FSM1/cipher-box#1507: a zone-specific origin-pull
certificate, never the shared Cloudflare CA ("the same hole this issue closes"), and three human
steps before the implementing PR merges. The steps were done on 2026-08-31: the certificate was
minted, per-hostname Authenticated Origin Pulls was enabled for the zone, and the CA was placed on
the VPS. FSM1/cipher-box#1526 landed the Caddy half and its Lint assertion the same day. The
running origin predated that PR until the cutover. The deploy of 2026-09-13 armed the gate. A
direct handshake to the origin with no client certificate is now refused after the server
hello, and all four names answer through the front. The zone certificate expires on 2028-12-03.

The range list is a hand-mirrored snapshot. FSM1/cipher-box#1508 asked what happens when
Cloudflare changes it. FSM1/cipher-box#1833 added a nightly diff.

`blueprint/deploy.md` "The staging stack" carries D1 to D8 today, from the paragraph that starts
"Two vhosts" to the paragraph on the open publish leg. The "Scheduled tier" section and the
`blueprint/testing.md` "CI gates" table carry D9.

## Decision

**D1 — Caddy trusts exactly Cloudflare's published ranges, and the API counts two forwarded
entries; the two settings are one unit.** The Caddyfile global `servers` block lists Cloudflare's
published IPv4 and IPv6 ranges as `trusted_proxies static`. From a trusted peer, Caddy keeps the
member address that Cloudflare appended to `X-Forwarded-For` and appends its own entry beside it.
Two entries arrive at the API, and `TRUST_PROXY_HOPS` is 2 in the staging environment that
`.github/workflows/deploy-staging.yml` generates. Trust without the count keys every IP-keyed
limit on a Cloudflare edge. The count without the trust runs off the end of the header onto an
entry that the caller wrote. The **Lint** gate holds the trusted set to exact equality with the
committed Cloudflare list, so a broader set fails. It also derives the expected count from the
adapted config and compares it with the deploy workflow value, so neither setting can move
alone. The rule landed with FSM1/cipher-box#1504; this ADR records it.

**D2 — `TRUST_PROXY_HOPS` equals the number of `X-Forwarded-For` entries that reach the API.**
It never counts the boxes in front of the API. Express counts that many entries back from the
right of the header, so an entry that a caller prepends lands left of the count and is skipped.
An overshooting count lets a caller pick its own bucket, so the value is a count and never
`true`. The default is 0, and a directly exposed deployment configures nothing. The rule landed
with FSM1/cipher-box#1461; this ADR records it.

**D3 — Caddy's `{client_ip}` reads `CF-Connecting-IP` under `trusted_proxies_strict`, never
`X-Forwarded-For`.** Cloudflare appends to `X-Forwarded-For`, so every entry left of the
caller's own entry is caller-written. Strict mode walks past trusted ranges to the first entry
outside them. For a caller whose own address is inside a Cloudflare range (a Worker, WARP, a
Tunnel), that entry is one that the caller wrote. Cloudflare writes and overwrites
`CF-Connecting-IP` itself, so it has no prepend surface. Strict mode still refuses both headers
from an untrusted peer. The rule landed with FSM1/cipher-box#1504; this ADR records it.

**D4 — The origin requires a client certificate that chains to this zone's own origin-pull
CA.** Every TLS connection policy on the origin sets `client_auth { mode require_and_verify }`
with a trust pool of one file, `/etc/caddy/certs/cloudflare-zone-origin-pull-ca.pem`. That file
holds the CA of the zone-specific certificate that per-hostname Authenticated Origin Pulls
presents. The shared Cloudflare origin-pull CA binds nothing, because every tenant presents it.
`require_and_verify` is the one Caddy mode that fails closed: `request` ignores the answer,
`require` does not verify the chain, and `verify_if_given` admits a caller that presents
nothing. The trust pool is one path, and a second CA beside it re-opens the hole. The owner
decided this rule on 2026-08-26 in FSM1/cipher-box#1507, and FSM1/cipher-box#1526 implemented
it.

**D5 — The certificate gate covers every vhost and the matcher-less fallback.** Caddy selects a TLS
connection policy by SNI and routes the request by its `Host` header. A caller that presents an
unauthenticated SNI and then writes a fronted `Host` walks around a partial gate. So every vhost
imports the one `(origin_tls)` snippet, directly or through `(accelerator_front)`. A catch-all
`https://` site imports it too and aborts. Without that site Caddy appends a matcher-less connection
policy of its own with no `client_auth`. The **Lint** gate holds every adapted connection policy,
the fallback included, to the mode and to the one CA path. The rule landed with
FSM1/cipher-box#1526; this ADR records it.

**D6 — The Lint gate asserts the front's obligations against Caddy's adapted config.** Neither
fronted vhost logs, so the obligations cannot be read from the running server. The Caddyfile ships
to the VPS by `scp`, and nothing else compiles it in CI. The **Lint** job builds the Caddy image
from `docker/caddy/Dockerfile`, adapts `docker/Caddyfile` under that image, and runs
`scripts/check-accelerator-front.mjs` over the adapted JSON, which is what the server executes. A
directive that silently stops taking effect fails there, and a file that does not parse fails there.
The checker enumerates the accelerator upstreams, not the vhosts, so a new vhost that proxies to
Kubo or someguy is caught by default. D1, D3, D4, D5, the rate of D7, and D8 are held in this gate.
The rule landed with FSM1/cipher-box#1461; this ADR records it.

**D7 — The open `/routing/v1` PUT publish leg carries a per-caller rate beside its 64 KB body
cap.** The publish leg carries no token, because a signed IPNS record authenticates itself. So a
size cap and a per-caller rate are its whole abuse budget, and both are asserted in the **Lint**
gate. The rate applies ahead of the proxy into someguy. The scope decision of 2026-08-25 on
FSM1/cipher-box#1387 named IP-keyed rate limiting as the abuse control of this leg. The rate,
its tool and its key landed with FSM1/cipher-box#1504; this ADR records them.

**D8 — The publish rate keys on the IPv6 /64, jitters its refusals, runs as a Caddy module in a
built image, and discards its refusal logs.** The zone keys on `{client_ip}` (D3). The limiter
masks the key to the /64 before it buckets (`ipv6_prefix 64`), because a caller that holds the
usual delegated /64 rotates its interface ID for a fresh bucket per request. The mask runs in
the limiter and not in a text pattern, because Caddy renders a compressed IPv6 address whose
network half is not in the string. IPv4 stays per address, because a wider prefix collapses a
NAT. Refusals are jittered, so `Retry-After` does not report when whoever shares an egress
address last published. A Cloudflare rule was the alternative and was not taken (see
Alternatives). Stock Caddy has no rate limiter, so the proxy ships as an image built from
`docker/caddy/Dockerfile`, with both base stages pinned by digest and the module pinned to a
commit. The deploy pushes it beside the API image, and the **Lint** gate builds it again so that
the config is adapted under the binary that runs. The limiter logs each refusal under its own
namespace, `http.handlers.rate_limit`, and that namespace is discarded with the front's other
logs. The rule landed with FSM1/cipher-box#1504; this ADR records it.

**D9 — The nightly Cloudflare Range Watch diffs the trusted set against Cloudflare's published
list.** The committed list lives in `scripts/cloudflare-ranges.mjs`. The **Lint** gate pins the
Caddyfile to it, which catches an edit but not an upstream change. The `Cloudflare Range Watch`
job in `.github/workflows/nightly.yml` runs `scripts/check-cloudflare-ranges.mjs`. The script
fetches `https://api.cloudflare.com/client/v4/ips` and fails on any difference. An unreachable
or malformed source is a failure, never a pass. A failure reaches the one nightly report job,
which opens or comments on one `comp:ci` tracking issue. An upstream change is therefore visible
within a day. The rule landed with FSM1/cipher-box#1833; this ADR records it.

## Trust argument

- **A foreign Cloudflare tenant cannot reach a vhost.** A tenant that points a proxied record at
  the origin arrives from a trusted range, but its edge presents the shared CA or no
  certificate. The handshake fails before any HTTP request exists (D4). A forged `Host` under an
  unknown SNI meets the fallback policy, which demands the same certificate (D5).
- **A direct caller cannot reach a vhost.** A request to the origin address that bypasses
  Cloudflare presents no zone certificate, and the handshake fails (D4). The API, Postgres, and
  the Kubo RPC and gateway ports bind to loopback, so Caddy is the only public HTTP surface.
- **A departed range grants nothing.** The new owner of a range that Cloudflare gives up is a
  trusted proxy in the snapshot, but it cannot complete the D4 handshake. The stale entry keeps
  no trust value. This is why D9 is an availability watch and not a trust control.
- **A caller cannot choose its own bucket.** Behind D4, the header that Caddy reads is written
  by Cloudflare for this zone (D3), and the entry that the API reads is the one Cloudflare
  appended (D2). A prepended entry lands left of the count. A direct peer that sets either
  header is not trusted, and strict mode ignores it.
- **The count and the trust cannot drift apart unseen.** The Lint gate compares them on every PR
  (D1). A short count keys on the edge, and an overshooting count keys on a caller-written
  entry; both fail the gate.
- **The config that the server runs is the config under test.** The gate reads the adapted JSON
  under the shipped image (D6, D8). A directive that the image does not carry fails to adapt.
- **The open leg has a bound that a caller cannot rotate around.** The /64 mask removes the
  interface-ID rotation. The zone admits 60 events a minute, and the Lint gate refuses a zone above
  600 events a window. The refusal log that would hold a member address is discarded (D8).

## Alternatives rejected

**(a) A Transform Rule on the zone that sets a high-entropy header, with an origin firewall on
:443.** FSM1/cipher-box#1507 offered it as the cheaper interim. The owner chose the zone
certificate on 2026-08-26. A shared secret in a header is a bearer credential. A certificate
check at the handshake refuses the caller before any request exists.

**(b) The shared Cloudflare origin-pull CA.** Every Cloudflare customer can present it, so it is
the same hole that D4 closes (FSM1/cipher-box#1507).

**(c) A certificate gate on the two fronted vhosts only.** Caddy routes on `Host` and not on SNI.
A caller with an unauthenticated SNI and a forged `Host` walks around a partial gate
(FSM1/cipher-box#1526).

**(d) Keep `TRUST_PROXY_HOPS` at 1 with no trusted ranges.** This is the state that
FSM1/cipher-box#1461 shipped. It is safe from a caller-written entry, but every member behind
one edge POP shares one bucket (FSM1/cipher-box#1487).

**(e) Read `{client_ip}` from `X-Forwarded-For` under strict mode.** A caller whose own address
is inside a Cloudflare range resolves to an entry that it wrote. FSM1/cipher-box#1504 measured
this against a live Caddy.

**(f) A Cloudflare rate-limiting rule on the publish hostname.** FSM1/cipher-box#1486 offered it,
and FSM1/cipher-box#1461 named it as the interim. The origin answered on its own address, so an
edge-only limit was walked around. A rule in a dashboard also cannot be config-tested like the
other obligations (FSM1/cipher-box#1504).

**(g) Mask the key to the /64 with a text pattern over the address.** Caddy renders
`{client_ip}` in RFC 5952 compressed form, so the network half of a compressed address is not
in the string. The key fell back to the /128 and restored the rotation (FSM1/cipher-box#1504).

**(h) Load `trusted_proxies` from a self-refreshing source instead of a snapshot.**
FSM1/cipher-box#1508 weighed it. It adds a startup network dependency and needs the Lint gate's
`source === 'static'` assertion rewritten. The nightly diff keeps the snapshot and makes a drift
visible.

## Consequences

1. **`blueprint/deploy.md` already carries D1 to D8.** The "The staging stack" section states
   them in the paragraphs that start "Two vhosts" (D1, D2, D6), "`{client_ip}` reads" (D3),
   "The ranges alone are _Cloudflare-wide_" (D4, D5) and "The open `/routing/v1` **PUT**"
   (D7, D8). The paragraph "The range list is a hand-mirrored snapshot" states D9 and the
   departed-range property of the trust argument. No text change is needed.

2. **`blueprint/deploy.md` and `blueprint/testing.md` already carry D9.** The "Scheduled tier"
   bullet "Cloudflare Range Watch" and the dispatch and scheduled row of the testing.md "CI
   gates" table state it. No text change is needed.

3. **`blueprint/api.md` already carries the frame of D7.** The "Egress" bullet "The front covers
   both read legs" states that the PUT publish leg stays open and that the front adds only
   IP-keyed rate limiting. No text change is needed.

4. **`CONTEXT.md` needs no change.** The "Read accelerator" and "Accelerator token" entries name
   the surfaces that the front gates. The origin trust is a deploy rule, and the glossary holds
   no term for it.

5. **`blueprint/deploy.md` section "The staging stack" gains the citation (ADR 0035)** at the
   paragraphs of consequence 1. The "Scheduled tier" bullet "Cloudflare Range Watch" gains the
   citation (ADR 0035 D9).

6. **`blueprint/testing.md` section "CI gates" gains the citation (ADR 0035 D9)** at "the
   Cloudflare Range Watch".

7. **`blueprint/api.md` section "Egress" gains the citation (ADR 0035 D7)** at "beyond IP-keyed
   rate limiting".

8. **The Lint gate does not yet assert the body cap of D7.** `blueprint/deploy.md` states that
   the size cap and the rate "are asserted in that gate". `scripts/check-accelerator-front.mjs`
   at origin/main asserts the rate and has no assertion on the `request_body` handler or its
   `max_size`. This ADR records the blueprint. The checker gains a body-cap assertion on the
   publish leg.

9. **No wire format, no KDF edge, and no op queue record changes.**

## Residuals

**E1 — The Cloudflare side of D4 is dashboard state.** Per-hostname Authenticated Origin Pulls,
the association of the zone certificate with each staging name, and the off state of the global
and zone-level settings live in the Cloudflare dashboard. No gate reads them. The owner checked
them by hand on 2026-09-13. A new hostname without the association fails closed: Cloudflare
presents no zone certificate and the handshake fails. That is an availability fault, not a
trust hole.

**E2 — The Lint gate checks the CA path, not the CA.** The file at
`/etc/caddy/certs/cloudflare-zone-origin-pull-ca.pem` is placed on the VPS by an operator and is
not in the repository. A shared Cloudflare CA placed at that path passes the gate and re-opens
the hole. The CA fingerprint was checked by hand on 2026-09-13. No job watches the expiry of
the zone certificate on 2028-12-03. At expiry the handshake fails closed.

**E3 — No automated check proves the handshake refusal at runtime.** The gate is config-level.
The runtime proof is the probe in FSM1/cipher-box#1526 against a throwaway zone CA and rogue CA,
and the manual direct-handshake check after the cutover deploy of 2026-09-13. A regression that
the adapted config does not show, for example a Caddy build that ignores the policy, reaches
staging unseen.

**E4 — The plain-HTTP listener is outside the certificate gate.** The `:80` site carries no TLS
and so no `client_auth`. The D5 walk reads `tls_connection_policies`, which a plain-HTTP server
does not carry. Today the site only redirects to `https://`, and the upstream walk of D6 still
catches a proxy to Kubo or someguy on it. A proxy to the API on `:80` would pass the gate. The
loopback bindings in `docker/docker-compose.staging.yml` are also not held by any gate.

**E5 — A range that Cloudflare adds degrades limits for up to a day.** Members behind the new
POP arrive from an untrusted peer. Caddy replaces their `X-Forwarded-For`, and they share one
bucket for the publish rate and for the API throttles until the watch fires and a Lint-checked
edit lands. The direction fails safe. It is an availability cost, not a trust hole.

**E6 — The API and the front key the member from different headers.** The API reads the
`X-Forwarded-For` entry that Cloudflare appended (D2). The publish limiter reads
`CF-Connecting-IP` (D3). Both are written by Cloudflare behind D4, and they agree for an
ordinary caller. No gate compares them.

**E7 — The rule covers the staging origin only.** Production is parked
(`blueprint/deploy.md` "Open edges", "Production go-live"). A production origin needs its own
zone certificate and its own Authenticated Origin Pulls association. That is a decision for the
go-live.

**E8 — A shared address shares a bucket.** IPv4 stays per address, so a NAT shares one bucket.
Devices in one delegated IPv6 /64 share one bucket. This is the cost of a key that a caller
cannot rotate.

**E9 — The blueprint and the checker disagree on the body cap of D7.** `blueprint/deploy.md` states
that the size cap and the rate "are asserted in that gate". `scripts/check-accelerator-front.mjs`
asserts the rate only. The cap is the `request_body` handler with `max_size 64KB` in
`docker/Caddyfile`, and no gate holds it. This ADR records the blueprint (consequence 8).

## Gate

The PR gate for D1 and D3 to D8 is the **Lint** job (`.github/workflows/ci-repo.yml`, step
"Check the accelerator front's egress obligations", `pnpm lint:accelerator-front`, which runs
`scripts/check-accelerator-front.mjs`). The quoted names below are its failure messages.

- **D1:** "trusted_proxies is not exactly the Cloudflare set" and "TRUST_PROXY_HOPS is N, but
  this Caddyfile forwards M X-Forwarded-For entries" (**Lint**). In the API area,
  `Integration tests (real Postgres)` runs `apps/api/src/ops/trust-proxy.http.itest.ts`:
  "resolves the member behind Cloudflare and Caddy at two hops" and "collapses a whole
  Cloudflare edge into one bucket at one hop".
- **D2:** `apps/api/src/ops/trust-proxy.http.itest.ts`: "collapses every forwarded client into
  one bucket when unconfigured", "keys each forwarded client separately at one hop" and "lets a
  client pick its own bucket when the hop count overshoots the chain". The Lint gate derives the
  arriving count from the adapted config (2 when every server trusts the ranges, else 1). It
  does not measure the header that Caddy forwards. The one-entry case was measured by hand in
  FSM1/cipher-box#1461 against a live Caddy 2.11.4. That is a finding.
- **D3:** "trusted_proxies_strict is off" and "{client_ip} does not come from CF-Connecting-IP"
  (**Lint**). No CI test resolves `{client_ip}` under a forged header chain. The probe was manual
  in FSM1/cipher-box#1504. That is a finding.
- **D4:** "does not require_and_verify a client certificate" and "does not verify against exactly
  /etc/caddy/certs/cloudflare-zone-origin-pull-ca.pem" (**Lint**). No CI test performs a
  handshake. That is a finding (E3).
- **D5:** the same two messages, reported per policy, the fallback "matching any other SNI"
  included, and "no TLS connection policy in the adapted config" (**Lint**). The plain-HTTP
  server is not walked (E4).
- **D6:** the **Lint** job itself. The checker has no test of its own. Its mutation evidence is
  in the bodies of FSM1/cipher-box#1461, FSM1/cipher-box#1504 and FSM1/cipher-box#1526, and no
  suite re-runs it. That is a finding.
- **D7:** "the open publish leg runs unrated into someguy:8190" (**Lint**). No assertion holds
  the 64 KB body cap. That is a finding (consequence 8).
- **D8:** "does not key on {http.vars.client_ip}", "does not mask its key to a /64 or shorter",
  "admits more than 600 events a window", "logs its key" and "http.handlers.rate_limit is not
  discarded" (**Lint**). The built image is held because the Lint job adapts under
  `docker/caddy/Dockerfile`, and stock Caddy fails to adapt the `rate_limit` directive. No
  assertion holds the refusal jitter. That is a finding.
- **D9:** the `Cloudflare Range Watch` job in `.github/workflows/nightly.yml` is the check. It
  gates no merge by design (`blueprint/testing.md` "CI gates", the dispatch and scheduled tier).
  No test covers `scripts/check-cloudflare-ranges.mjs`. Its unreachable-source path was
  exercised by hand in FSM1/cipher-box#1833.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
