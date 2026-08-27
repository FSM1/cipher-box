# Deployment, infra and release management — v2 blueprint

Resolved by [Blueprint: deployment, infra and release management](https://github.com/FSM1/cipher-box-next/issues/48).
Normative for the v2 build. Upstream inputs: the
[component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D7: v2 rebuilds in the cipher-box repo, v1 frozen on a branch, infra edited
in place), the CI tiers and open edges handed here by
[`blueprint/testing.md`](testing.md) (runner provisioning, staging deploy
gates, release-tag e2e gating, nightly scheduling), the hosted-infra and
gateway shape from [`blueprint/api.md`](api.md), the Tauri updater from
[`blueprint/desktop.md`](desktop.md), the PWA install surface from
[`blueprint/web-client.md`](web-client.md), and the clean-break migration
stance ([FSM1/cipher-box-next#6](https://github.com/FSM1/cipher-box-next/issues/6)).

## Doctrine

v1's release machinery is the acknowledged weak spot this doc exists to
retire: sixteen components versioned independently drove a four-workflow
web — `release-please.yml` + `pr-release-preview.yml` + `release-gate.yml` +
`cargo-lock-release-sync.yml` — whose correctness depended on a bot commit
(`chore(release): set release targets`) surviving on every PR branch, a
`release-as` pin discipline enforced by nobody, and a two-tier Cargo.lock
sync racing the merge queue. All of that complexity served exactly zero
consumers: no package or crate was ever published to a registry. Three laws
replace it:

1. **One version, one train.** The repo releases as a single product,
   `vX.Y.Z`. The only release artifacts are the three deployables — the web
   bundle, the API image, the desktop installers. Internal crates and
   packages are unpublished implementation detail and carry no versions of
   their own.
2. **The release path writes nothing to PR branches.** Version bumps derive
   from conventional commits on `main`, period. Any design that requires a
   bot commit on a contributor branch to release correctly is rejected as a
   defect class, not tuned.
3. **Staging deploys are boring and destructive-restorable.** Staging is the
   only deployed environment (there is no production; it stays funding-gated
   and parked). Everything hosted is an accelerator by design (api.md), and
   the clean break (FSM1/cipher-box-next#6) removes all data-continuity obligations — so a
   deploy may always be "fresh volumes, redeploy, done", and cutover is a
   redeploy, not a migration.

What dies relative to v1 — with what killed it:

| Gone                                                                                                                      | Killed by                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Independent per-component versioning, 16-entry manifest, component tags (`@cipherbox/web-vX`, `cipherbox-fuse-vX`, …)     | law 1 — one product version, tag `vX.Y.Z`                                                                                              |
| `pr-release-preview.yml` + `.github/scripts/pr-release-preview.js` + the load-bearing bot commit + the force-push footgun | law 2                                                                                                                                  |
| `release-as` pins and the self-comparing changelog loop                                                                   | law 1 — nothing to pin; one version moves forward                                                                                      |
| `cargo-lock-release-sync.yml` and the post-merge lock-sync fallback PR                                                    | crates are version-frozen (below); releases never touch Cargo.lock                                                                     |
| `release-gate.yml` + `ci-e2e.yml`'s `retrigger-release-gate` polling                                                      | the main gate (testing.md) — release readiness is "main is green", asserted once at staging-tag time                                   |
| The `--latest=false` un-marking loop in `release-please.yml` and `desktop-staging-release.yml`'s `mark-latest`            | one release stream — the release carrying desktop artifacts is the only release, so `/releases/latest` is correct by construction      |
| `build-tee` image job, `tee-worker` service, Phala compose files and deploy flow, `redis` in every stack                  | FSM1/cipher-box-next#24 — TEE dropped, republisher in-process; nothing queues, throttling and scheduling are in-process                |
| `check-api-client.sh` pre-commit gate, `api-spec` drift CI job                                                            | FSM1/cipher-box-next#28 D5/D6 — no generated clients; the contract suite is the gate, OpenAPI freshness is a hygiene diff (testing.md) |
| `vector-parity` job, `check-vector-parity.sh`, vector generator scripts                                                   | the KAT-manifest regime (core.md)                                                                                                      |
| SC#6/SC#2 grep gates in `cargo-linux`                                                                                     | testing.md law 2 — simulation scenarios, not source greps                                                                              |

## v1 freeze mechanics

The freeze is one commit boundary, executed in this order:

1. **Cut the freeze branch.** Branch `v1` from `main` at the last v1
   release state, tag that commit `v1-freeze` (annotated). The branch is an
   archive and an emergency-redeploy source, not a maintenance line — v1
   maintenance is out of scope for this map.
2. **Close the open release-please PR** (never merge it) and any open v1
   PRs that won't be rebuilt onto v2.
3. **Hand `main` to the v2 workspace.** The first v2 commits on `main`
   delete the four dead release workflows and `pr-release-preview.js`,
   replace `release-please-config.json` + `.release-please-manifest.json`
   with the single-component config below, and begin the layout demolition.
   Workflows, docker files, and scripts are edited in place, in history —
   never forked into `-v2` copies.
4. **Re-point branch protection.** Required checks on `main` track the v2
   PR-gate job names as each suite lands (testing.md law 1: a suite exists
   only if it blocks merges). Job names are the contract; renames update
   the ruleset in the same PR.

Staging redeployability during the build: `deploy-staging.yml` is
tag-triggered, and workflow runs execute the workflow file **at the tag** —
so every existing `staging-*` tag remains a self-contained, reproducible v1
deploy with no dependency on `main` or the freeze branch. An emergency v1
redeploy is "re-run the last staging deploy run" (or re-push its tag).
`tag-staging.yml` stops functioning for v1 by design the moment `main` is
v2 — v1 mints no further releases.

During the build, before the first v2 release exists, staging deploys of
work-in-progress v2 come from a `workflow_dispatch` of the edited
`deploy-staging.yml` against a `main` SHA (no tag required). The tag-gated
flow below takes over at `v2.0.0`.

All v1 tags (component tags, `staging-*`) remain forever — history is
immutable; the `staging-` prefix keeps them disjoint from v2's `v*` tags.

## Release management

### Versioning and release-please

release-please stays — in its boring, single-component mode:

- **One manifest entry**: `.` (root, release-type `node`), component
  `cipher-box`, `include-component-in-tag: false` → tags are plain
  `vX.Y.Z`, starting at `v2.0.0`. One release PR, one CHANGELOG at the
  root, the same changelog-sections config. The GitHub App token mechanism
  (`RELEASE_BOT_APP_ID` / `RELEASE_BOT_PRIVATE_KEY`) ports so release-PR
  pushes still trigger CI.
- **Version surfaces are exactly two files**: the root `package.json` (the
  manifest source) and `apps/desktop/src-tauri/tauri.conf.json` (via
  `extra-files` — the surface the Tauri updater and the About dialog read).
  The API and web read the product version at build time (build arg /
  `define`) from the root — no per-app `version` fields to bump.
- **Crates and packages are version-frozen at `0.0.0`.** They are never
  published, so their manifest versions are meaningless; freezing them
  means a release never edits `Cargo.toml` or `Cargo.lock` — the entire v1
  lock-sync apparatus (both tiers, plus the disabled cargo-workspace-plugin
  workaround) has nothing left to do. `workspace.package` centralizes the
  frozen value.
- **Conventional commits keep feeding the bump**: `pr-title.yml` ports
  as-is (squash merges make the PR title the commit), including the
  no-parens-in-subject rule — release-please still parses subjects, and
  the rule costs nothing.

### Desktop release artifacts

On each `v*` tag, `desktop-release.yml` (v1's `desktop-staging-release.yml`
edited: trigger becomes the product tag, `mark-latest` deleted) builds the
Tauri installers for macOS/Windows/Linux via `tauri-action`, minisign-signed
with the carried `TAURI_SIGNING_PRIVATE_KEY(_PASSWORD)` secrets,
`includeUpdaterJson: true`, and attaches them to the GitHub Release
release-please created for that tag. The updater doctrine is desktop.md's:
Tauri updater over GitHub releases, minisign-verified; with one release
stream, `/releases/latest` resolves correctly with no un-marking
choreography.

## Staging pipeline

### Release-tag gating (the v1 shape, simplified)

`tag-staging.yml` ports with its chain intact — it was the part of v1
release management that worked:

1. `workflow_dispatch` → assert `main` HEAD carries a `v*` tag (one regex,
   replacing v1's three-pattern component zoo). Untagged HEAD fails with
   "wait for release-please".
2. Re-run the e2e gates at that SHA via the reusable workflows — web,
   desktop mounted, and (new) the cross-client suite. This is the
   release-tag e2e gating testing.md handed here: the main gate already ran
   revert-first at merge time; this re-run is the deploy-time assertion
   that HEAD is still green, on the exact bits being shipped.
3. `staging-approval` environment gate (manual approval) → mint
   `staging-YYYYMMDD-release-N` → call `deploy-staging.yml`.

### The staging stack

`docker/docker-compose.staging.yml` edited in place. Same single VPS
(2 vCPU / 8 GB — the CPU budget note survives: Kubo capped, someguy never
starved), same GHCR image flow, same scp-env + `compose pull` + migrations

- `up -d` mechanics in `deploy-vps`:

| Service       | v2 disposition                                                                                                     |
| ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `api`         | ports — new image contents (residual surface + in-process republisher, api.md)                                     |
| `postgres`    | ports                                                                                                              |
| `ipfs` (Kubo) | ports — pin store + trustless gateway upstream                                                                     |
| `someguy`     | ports — the self-hosted `/routing/v1` accelerator (staging/production only; CI uses the promoted mock, testing.md) |
| `caddy`       | ports — static web + reverse proxy + the accelerator front over Kubo and someguy (below); built, not stock         |
| `alloy`       | ports — Grafana Cloud shipping unchanged                                                                           |
| `redis`       | dies — nothing queues; throttling is in-process (verified effective by the contract suite)                         |
| `tee-worker`  | dies (FSM1/cipher-box-next#24) — with it the Phala compose files, the CVM update ritual, and the simulator         |

**Gateway deployment shape** (the api.md handoff): the token-authed
trustless gateway is Caddy in front of Kubo's gateway port —
`forward_auth` to a lightweight API token-verification endpoint, then
proxy to Kubo for block/CAR responses. The API process serves no bytes;
Caddy enforces membership; Kubo serves. Token format and TTL are API
build-time detail. Public trustless gateways remain the no-auth fallback,
so this path can fail without breaking reads.

Two vhosts, `gateway-staging` and `routing-staging`, both under the origin
certificate the other vhosts use — so a new hostname needs its SAN and a DNS
record before it resolves. Which legs are gated, and what the front owes the
pseudonym, is api.md (Egress); because neither vhost logs, those obligations
are asserted against Caddy's adapted config in the **Lint** gate rather than
read out of the Caddyfile. `TRUST_PROXY_HOPS` must equal the number of
`X-Forwarded-For` entries that actually reach the API, not the number of boxes
in front of it. Caddy is given Cloudflare's published ranges as
`trusted_proxies`, so it keeps the member address Cloudflare appended and adds
its own beside it: two entries arrive and the count is 2. The two settings are
one unit — trust without the count keys every IP-keyed limit on Cloudflare's
edge, the count without the trust runs off the end of the header onto an entry
the caller wrote — so the same **Lint** gate holds them to each other.

`{client_ip}` reads **`CF-Connecting-IP`** under `trusted_proxies_strict`, not
`X-Forwarded-For`. Cloudflare _appends_ to the latter, so every entry left of the
caller's own is caller-written, and strict mode walks past trusted ranges to the
first entry outside them — which for a caller whose own address sits inside a
Cloudflare range (a Worker, WARP, a Tunnel) is an entry it wrote. Cloudflare
writes and overwrites `CF-Connecting-IP` itself, so it has no prepend surface;
strict still refuses both headers from an untrusted peer, so a direct-to-origin
request cannot forge either.

The ranges alone are _Cloudflare-wide_, not zone-specific: any Cloudflare tenant
can point a proxied record at the origin address and arrive from inside a
trusted range. So the origin also demands a client certificate —
`client_auth { mode require_and_verify }` against **this zone's own**
origin-pull CA, which per-hostname Authenticated Origin Pulls presents. The
shared Cloudflare origin-pull CA binds nothing, because every tenant presents
it. Caddy routes on the `Host` header rather than on SNI, so the gate covers
every vhost _and_ the matcher-less fallback policy: a partial one is walked
around with a forged `Host`, and Caddy writes that fallback itself when a config
leaves it out. The **Lint** gate holds every adapted connection policy to the
mode and to that one CA path.

One residual assumption stays open: the range list is a hand-mirrored snapshot —
the Lint gate pins the set against edits but cannot see Cloudflare changing it,
where a departed range would make its new owner a trusted proxy.

The open `/routing/v1` **PUT** publish leg (api.md, Egress) carries no token, so
a size cap and a per-caller rate are its whole abuse budget; both are asserted in
that gate. The rate keys on the delegated IPv6 **/64** rather than the address,
since a caller holding one rotates its interface ID freely, and its refusals are
jittered so `Retry-After` does not report when whoever shares an egress address
last published. A Cloudflare rule was the alternative and was not taken: the
origin answers its own address directly, so an edge-only limit is walked around
rather than enforced. The limiter is a module stock Caddy lacks, so the proxy
ships as an image built from `docker/caddy/Dockerfile` — pushed beside the API
image, and built again by the checker so the config is adapted under what runs.
Its refusals log under a namespace of their own, which is discarded with the
front's other logs rather than reaching the default sink.

**Web hosting**: Caddy keeps serving the static bundle from
`/opt/cipherbox/web` — but the artifact deployed is the production build
the e2e suite tested (testing.md: the artifact that ships is the artifact
tested). **PWA install surface** (the web-client.md handoff): v2.0 ships a
valid manifest and the decided SW app-shell precache, but does **not**
advertise installability — no install-prompt UX. Browser-menu install
works for those who seek it; install promotion is a post-v2.0 decision.

**Observability**: alloy → Grafana Cloud and the dashboard-provisioning
job port; the dashboards themselves are rewritten during the build (TEE
panels die, republisher inventory-walk and re-PUT metrics arrive; the
Kubo-version metrics caveat re-checked on the Kubo bump). Faro RUM in the
web build carries over.

**Landing page**: `deploy-landing.yml` and the Render preview path are
outside the v2 blast radius and port untouched, except fixing the known
env-name mismatch (`secrets.DNSLINK_RECORD_ID` vs the
`CLOUDFLARE_DNSLINK_RECORD_ID` variable, and the missing `environment:`
binding).

### Cutover

One scheduled, announced, destructive redeploy: stop the v1 stack, remove
the `postgres` and `ipfs` volumes, deploy the v2 stack fresh. No data
migration, no dual-running (FSM1/cipher-box-next#6 — v1 is staging-only, all-DEVNET). Staging
URL and Web3Auth config decisions carry per FSM1/cipher-box-next#6 (free to keep or change on
merit). One accepted consequence, stated: existing v1 desktop installs
auto-update into v2 via `/releases/latest` and their local vaults become
orphans — consistent with the clean break; the v2 first-run treats them as
new devices.

## CI infrastructure

### Runners

GitHub-hosted only; no self-hosted runners in v2.0.

- **PR gate**: `ubuntu-latest` for everything except the Windows adapter
  check (`windows-latest`). The browser suite (Playwright/chromium) and the
  contract-suite stack (Postgres + Kubo + mock routing store as GH
  services) both fit ubuntu. The PR e2e smoke slice runs on ubuntu only.
- **Main gate**: the mounted-desktop matrix keeps v1's three runner
  provisions — `macos-latest` + FUSE-T, `windows-latest` + pinned WinFsp
  MSI, `ubuntu-latest` + libfuse3/Xvfb. **Cross-client e2e rides the same
  matrix runners**: each OS leg runs the built web artifact headless
  alongside the mounted desktop against one stack — no fourth runner
  class, and cross-client gets per-OS coverage for free.
- **Toolchain single-sourcing** (fixes a v1 defect): a root
  `rust-toolchain.toml` becomes the one Rust pin — every job's
  `rustup default stable` line is deleted so CI builds what the repo pins.
  Node pins once in root `package.json` (`engines` + the existing
  `packageManager`), and workflows read it via `node-version-file` instead
  of sixteen hard-coded `'22'` strings. Dockerfiles align to the same
  major (the tee-worker `node:20` straggler dies with the app).

### Caching and hygiene

The v1 strategy ports: `setup-node` pnpm cache keyed on the lockfile;
`actions/cache` on cargo registry/git/target keyed per-OS on `Cargo.lock`.
The WASM build (`crates/wasm`, wasm-pack/wasm-bindgen) joins the cargo
cache key-space; `cargo-llvm-cov` and other cargo-installed tools move to a
cached install instead of v1's cold `cargo install` per run. Codecov ports
demoted to informational (testing.md): the upload jobs and
`codecov-base.yml` stay, thresholds stop gating. `zizmor.yml` and the
SHA-pinned-actions convention port as-is and apply to every edited
workflow.

### Scheduled tier

One new `nightly.yml` (cron) owns the scheduled slots testing.md defined:

- **Long-horizon liveness**: the compressed-EOL profile run — lease
  renewal at seq+1, the republisher inventory walk, >24 h-no-re-PUT
  alerting — nightly against the CI stack.
- **Full-matrix flake surveillance**: the main-gate e2e matrix re-run on
  `main` HEAD nightly. With `retries: 0` as policy, this distinguishes
  "main broke" (revert) from "environment drifted" (fix the harness)
  before it blocks a release.

Dispatch-only (unscheduled): the load harness against local or staging
(`load-test.yml` re-engaged over `crates/load`; the BYO scenario covers the
API-side advisory-pin path, and external-provider throughput waits on the
engine's provider layer), and the real Web3Auth
Core Kit login job against staging with the test credentials — the honest
inherited limitation testing.md records; never a PR gate.

## Disposition of the v1 inventory

Workflows (all edited in place, per FSM1/cipher-box-next#28 D7):

| v1 workflow                                                                            | Disposition                                                                                                                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ci.yml`                                                                               | **Restructured** — skeleton, dorny path filters, service-container pattern, failure-artifact uploads port; jobs become the testing.md PR gate (lint/typecheck, cargo workspace + KAT/WASM, browser suite, contract suite, Windows adapter, migration drift, e2e smoke). `api-spec`, `vector-parity`, and the grep gates die (table above) |
| `ci-e2e.yml`                                                                           | **Ports** — the main-gate orchestrator (full web + desktop mounted + cross-client); `retrigger-release-gate` dies                                                                                                                                                                                                                         |
| `web-e2e.yml`, `desktop-e2e.yml`                                                       | **Port** — reusable shape and per-OS provisioning intact; suites rewired per testing.md; desktop legs gain the cross-client run                                                                                                                                                                                                           |
| `release-please.yml`                                                                   | **Ports simplified** — single component, app-token mechanism kept; un-latest loop and lock-sync fallback deleted                                                                                                                                                                                                                          |
| `pr-release-preview.yml` (+ script), `release-gate.yml`, `cargo-lock-release-sync.yml` | **Die** (doctrine table)                                                                                                                                                                                                                                                                                                                  |
| `tag-staging.yml`                                                                      | **Ports** — single `v*` assertion, adds cross-client to the gate, same `staging-approval` + tag mint                                                                                                                                                                                                                                      |
| `deploy-staging.yml`                                                                   | **Edited** — `build-tee` and redis plumbing out, gateway `forward_auth` wiring and volume-wipe cutover support in; VPS mechanics unchanged                                                                                                                                                                                                |
| `desktop-staging-release.yml`                                                          | **Becomes `desktop-release.yml`** — triggers on `v*`, attaches to the release-please release, `mark-latest` dies                                                                                                                                                                                                                          |
| `deploy-landing.yml`                                                                   | **Ports** — env-name mismatch fixed                                                                                                                                                                                                                                                                                                       |
| `load-test.yml`                                                                        | **Ported** — dispatch-only, over `crates/load`                                                                                                                                                                                                                                                                                            |
| `pr-title.yml`, `zizmor.yml`, `codecov-base.yml`                                       | **Port as-is**                                                                                                                                                                                                                                                                                                                            |

Docker, scripts, hooks:

| v1 artifact                                                                                                 | Disposition                                                                                                                |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `docker/docker-compose.yml` (local dev)                                                                     | **Edited** — postgres/kubo/someguy/mock-ipns-routing stay; redis and tee-worker leave; the 6380/6379 redis port split dies |
| `docker/docker-compose.staging.yml`, `Caddyfile`, `alloy-config.river`, `ipfs-init/`                        | **Edited** per the stack table                                                                                             |
| `apps/tee-worker/Dockerfile`, `docker-compose{,.phala}.yml`                                                 | **Die**                                                                                                                    |
| `apps/api/Dockerfile`                                                                                       | **Edited** — build graph becomes crates + api                                                                              |
| `tools/mock-ipns-routing/Dockerfile`                                                                        | **Ports** — the promoted CI routing store (testing.md)                                                                     |
| `scripts/check-api-client.sh`, `check-vector-parity.sh`, vector/bench generators, `backfill-pinned-cids.ts` | **Die** (gates replaced; one-shots done)                                                                                   |
| `scripts/baseline-benchmark.sh`                                                                             | **Ports** — ops tooling                                                                                                    |
| `.husky/pre-commit`                                                                                         | **Edited** — lint-staged stays, the api-client staging check dies; the Entire wrapper hooks are untouched                  |

Secrets and environments (repo settings reused as-is per D7; retirements at
cutover):

| Item                                                                                                                                                                                                                                                                                                                                                           | Disposition                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `TAURI_SIGNING_PRIVATE_KEY(_PASSWORD)`, `IDENTITY_JWT_PRIVATE_KEY`, `STAGING_TEST_LOGIN_SECRET`, `STAGING_THROTTLE_BYPASS_SECRET`, `STAGING_SSH_KEY`, `STAGING_DB_PASSWORD`, `STAGING_JWT_SECRET`, `WEB3AUTH_TEST_EMAIL/OTP`, `VITE_WEB3AUTH_CLIENT_ID`, `RELEASE_BOT_*`, `CODECOV_TOKEN`, Grafana/Faro/Cloudflare families, `PINATA_JWT` (BYO load scenarios) | **Keep**                                                                                                                                   |
| `STAGING_TEE_WORKER_SECRET`, `PHALA_CLOUD_API_KEY`, `PHALA_TEE_WORKER_URL`, `STAGING_REDIS_PASSWORD`                                                                                                                                                                                                                                                           | **Retire at cutover** — TEE and redis are gone                                                                                             |
| `SENDGRID_API_KEY`                                                                                                                                                                                                                                                                                                                                             | **Keep** — the API owns passwordless email again and delivers the login code behind the `MAIL_PROVIDER` seam (ADR 0008 D2)                 |
| `SENDGRID_FROM_EMAIL`                                                                                                                                                                                                                                                                                                                                          | **Retire at cutover** — replaced by `MAIL_FROM_ADDRESS`, which the mail provider reads                                                     |
| `staging`, `staging-approval` environments                                                                                                                                                                                                                                                                                                                     | **Keep** — same roles                                                                                                                      |
| `production` environment                                                                                                                                                                                                                                                                                                                                       | **Stays parked** — production remains funding-gated; its topology (same compose stack + CDN'd static web) is designed-for, not provisioned |

## Open edges

- **Cutover trigger** — the criteria for scheduling the destructive
  redeploy (v2 contract suite + smoke green on a VPS dry-run); build-time
  judgment, announced in advance.
- **Gateway token detail** — format, TTL, and the verify endpoint's shape
  behind Caddy `forward_auth`; API build-time work within the shape fixed
  above.
- **Dashboard rewrite** — the v2 Grafana dashboard set (republisher walk,
  mailbox depth, gateway auth hit-rate) lands with the metrics that feed
  it.
- **Nightly cost tuning** — the full-matrix surveillance run is the
  expensive slot; trim to a rotation if runner spend becomes real money.
- **Production go-live** — out of scope until funded: provisioning the
  parked environment, a second VPS or managed Postgres, CDN for the web
  bundle, and DNS cutover would each be decisions then, on this doc's
  seams.
