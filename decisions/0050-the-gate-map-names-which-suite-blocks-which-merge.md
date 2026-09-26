# ADR 0050 — The gate map names which suite blocks which merge

- **Status:** Accepted on 2026-09-26 — retroactive; the tier rules shipped in FSM1/cipher-box#960,
  FSM1/cipher-box#1067, FSM1/cipher-box#1406, FSM1/cipher-box#1776, FSM1/cipher-box#1822,
  FSM1/cipher-box#1831 and FSM1/cipher-box#1833, and the `blueprint/testing.md` "CI gates"
  section carries them. Testing law 1 and `AGENTS.md` item 4 do not carry them yet
  (consequences 3 and 4); the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [ADR 0018](./0018-the-pr-gate-is-grouped-by-area-with-an-adapter-leg-per-desktop-platform.md)
  (the PR gate is grouped by area; D2 the result contexts and the standalone contexts, C3 a
  later suite joins an area), [#47](https://github.com/FSM1/cipher-box-next/issues/47) (the
  testing blueprint thread: law 1 and the three CI tiers),
  [#48](https://github.com/FSM1/cipher-box-next/issues/48) (the deploy blueprint thread: the
  staging pipeline, the scheduled tier, and the dispatch-only load harness), the
  `blueprint/testing.md` "Doctrine" (law 1), "Suite map" (the "Staging e2e" bullet) and "CI
  gates" sections, the `blueprint/deploy.md` "v1 freeze mechanics" (step 4), "Release-tag
  gating", "Caching and hygiene" and "Scheduled tier" sections, and `AGENTS.md` "Code
  Generation Guidelines" item 4. ADR 0049 (proposed; each suite proves what it claims) holds
  the sign-in rules of `Staging E2E`. No `CONTEXT.md` term names a CI tier.
- **Implemented by:** FSM1/cipher-box#960 (the load harness, dispatch-only, D2 and D3),
  FSM1/cipher-box#1067 (`Tracker Refs`, D4), FSM1/cipher-box#1406 (`Perf Benches`,
  dispatch-only, D2 and D3), FSM1/cipher-box#1776 (the cargo cache writer, D5),
  FSM1/cipher-box#1822 (the updater-key check in the main gate, D6), FSM1/cipher-box#1833 (the
  nightly tier, D7) and FSM1/cipher-box#1831 (`Staging E2E` as step 4 of the staging pipeline,
  D8).

## Context

Testing law 1 says: "A suite that does not block a merge does not exist." Its text continues:
"Every v2 suite is wired into a named gate in this doc the day it lands, or it is deleted"
(`blueprint/testing.md` "Doctrine"). The law answers a v1 defect. The `apps/web` unit suite had
no CI runner, `.spec.ts` files sat outside the test include, and web and desktop e2e found
regressions only after they landed. `AGENTS.md` item 4 restates the law for every agent:
"Every suite must block a merge in a named CI gate the day it lands".

The same document has always named suites that block no merge. The first `testing.md`
(commit `fd1d406b5c`, FSM1/cipher-box#616) put "the load harness" and "long-horizon liveness"
in a "Dispatch / scheduled" tier with the trigger "manual or cron". The resolution of #47 says
the same ("dispatch/scheduled (k6 load port, compressed-EOL liveness jobs)"), and the
resolution of #48 adds a nightly cron and says "Load harness and real-Web3Auth login stay
dispatch-only". So law 1 and the tier table disagree from the first day. Four groups of suites
now live on the non-blocking side of that disagreement:

- **`Perf Benches`** (FSM1/cipher-box#1406). Criterion benches over `crates/core` and
  `crates/engine` on the in-memory seam fakes and the virtual clock. The PR states the reason:
  "a shared runner's timings are too noisy to fail a merge on". `perf-bench.yml` has the
  `workflow_dispatch` trigger only.
- **The load harness** (FSM1/cipher-box#960). `crates/load` drives the engine's real API client
  against a local stack or staging. `load-test.yml` has the `workflow_dispatch` trigger only, and
  a staging run passes the approval of the `staging` environment. A load generator is itself a
  hazard, so it must not run on every pull request.
- **The nightly tier** (FSM1/cipher-box#1385, FSM1/cipher-box#1833). It re-runs the main-gate e2e
  matrix on `main` HEAD with no push to compare against. Its purpose is to tell "main broke"
  apart from "the environment drifted". The FSM1/cipher-box#1385 body states: "The full matrix
  runs every night — no cost trim, no weeknights-only, no rotating OS."
- **`Staging E2E`** (FSM1/cipher-box#1821, FSM1/cipher-box#1831). It drives the deployed front
  through a real browser. It cannot run before the deploy it judges. The FSM1/cipher-box#1821
  body states: "A red run blocks nothing on merge, but the workflow result is the release verdict
  for the staging tag." The deploy has no health gate of its own, so this run is also the first
  signal that the containers came up.

Each of these is the right place for its suite. What is wrong is law 1: it forbids them, and an
agent that reads `AGENTS.md` item 4 literally must either delete them or force them into the PR
gate. The audit of 2026-09-26 records the `Perf Benches` row as a lag against #47 law 1.

Three more gate rules shipped without a decision record:

- **`Tracker Refs`** (FSM1/cipher-box#1067). A comment that names a tracker issue makes a claim
  about the tracker, not the code, and nothing catches it when the issue closes. 112 of the 123
  issues that the sweep removed were closed already. The PR added `scripts/check-tracker-refs.mjs`
  as a merge-blocking job so the pattern cannot come back.
- **The cargo cache writer** (FSM1/cipher-box#1776). `ci.yml` runs on `pull_request` only, and
  GitHub scopes a cache entry to the ref that wrote it. An entry that a pull request writes lives
  under `refs/pull/N/merge`, which no other pull request can read. The Windows leg compiled cold
  three times in one run, and the repository cache total stood at 11.3 GB against the 10 GB
  limit, so eviction removed the few `main` entries with the rest.
- **The updater-key drift check** (FSM1/cipher-box#1778, FSM1/cipher-box#1822). The check
  compares the committed updater public key with the release signing secret, and it can do that
  only with the secret. In the PR gate it ran `pnpm install` on the pull request's own tree and
  then `tauri signer sign` with both secrets in the step environment. A same-repository author
  therefore controlled code beside the release signing key, and a fork pull request always failed
  the job.

`blueprint/testing.md` "CI gates" carries all of these rules today, and ADR 0018 settled the
shape of the PR gate. This ADR records the whole gate map and amends law 1 so that the law and
the table agree.

## Decision

**D1 — Law 1 is amended: every suite has a named gate, and a suite that asserts the behavior of a
change blocks a merge.** Every suite is wired into a named tier of `blueprint/testing.md` "CI
gates" the day it lands, or it is deleted. A suite that asserts the behavior of a change blocks a
merge in the PR gate. It reports through an area result context or a standalone context that
branch protection requires (ADR 0018 D2 and C3). `FUSE Op Core` is one such suite (#47 law 1,
ADR 0018 C3), and `Web E2E Smoke Result` is one such standalone context (ADR 0018 D2). Where the
full run of such a suite does not fit the PR gate, the PR gate runs a slice of it and the main
gate runs the full set on every push to `main`, revert-first: "a smoke slice blocks every PR, the
full matrix blocks main" (`blueprint/testing.md` "Doctrine", the v1 table). Where the suite needs
a secret that a pull-request run must not hold, the main gate runs it alone (D6).

One suite is a named exception to D1. The virtual-time liveness suite
(`apps/api/src/republisher/republisher.scheduled.test.ts`) asserts republisher behavior: it drives
the republisher walk over months of virtual time, with no real clock and no network. Its PR slice
is the republisher unit tests (`republisher.task.test.ts` and `republisher.alerter.test.ts`),
which run in the API unit suite. Its full run is in `nightly.yml` only (D7), not in the main gate
(E7). Its companion stack profile (`republisher-stack.scheduled.test.ts`) talks HTTP to the API
that `nightly.yml` boots, and it is a run of the D2 class.

**D2 — Two kinds of suite block no merge, by design, and they live in the dispatch and scheduled
tier.** The first kind is a measurement harness: the load harness (`crates/load`,
`load-test.yml`) and `Perf Benches` (`perf-bench.yml`). Its result is a number, and a number from a
shared runner is too noisy to fail a merge on. The second kind is a run against a deployed or
long-horizon environment: the nightly tier (`nightly.yml`, D7) and `Staging E2E`
(`staging-e2e.yml`, D8). Its subject is an environment or a deploy, not the change in a pull
request. A suite of either kind is still wired into a named tier (D1). It is never a required
status context, and it reports where a person reads it: the nightly tier through one tracking
issue (D7), `Staging E2E` as the release verdict (D8), and the measurement harnesses as the run
artifacts. The load harness has no production target, and its staging target passes the approval
of the `staging` environment.

**D3 — The code of a non-blocking suite still compiles in the PR gate.** A suite that blocks no
merge must not rot unseen. The PR gate compiles, typechecks or unit-tests its code:

- The criterion bench targets compile under `cargo clippy --workspace --exclude cipherbox-desktop
--exclude cipherbox-contract --all-targets -- -D warnings` in the Rust area
  (`.github/workflows/ci-rust.yml`, job `Fmt + clippy (Linux)`).
- The load harness's own unit tests (the run plan, the target guard, the metrics and the
  thresholds) run in the Rust area's workspace tests.
- The `Staging E2E` specs typecheck with the `@cipherbox/web-e2e` package in the Web area
  (`.github/workflows/ci-web.yml`).
- The long-horizon liveness suite (`*.scheduled.test.ts`) typechecks with the API package in the
  API area.
- The baseline runner of the performance tooling typechecks and runs its unit suite in the Repo
  area (job `Perf Tooling`).

**D4 — `Tracker Refs` is a PR-gate check in the Repo area, and it blocks every merge.**
`scripts/check-tracker-refs.mjs` (`pnpm lint:tracker-refs`) scans the tracked source files under
`crates/`, `apps/`, `packages/`, `landing/`, `tools/`, `scripts/` and `.github/`. It fails on a bare
tracker reference of three to five digits, and on a link to an issue or a pull request of
`FSM1/cipher-box`. A repo-qualified reference such as `FSM1/cipher-box-next#32` and a two-digit
`#NN Dn` decision citation pass. The job runs in the Repo area, which has no path filter, and it
reports through `Repo Result`. The rule landed with FSM1/cipher-box#1067; this ADR records it.

**D5 — Only a run on `main` writes the cargo caches that the PR gate reads; a pull-request run
restores and never saves.** Every cargo job of the PR gate restores through `Swatinem/rust-cache`
pinned to one commit, with one `shared-key` per group (`workspace`, `adapters`, `desktop`,
`core-kats`, `client-browser`, `wasm-engine`), and carries
`save-if: ${{ github.ref == 'refs/heads/main' }}`. `cargo-cache-seed.yml` runs on every push to
`main`, on a weekly schedule, and on dispatch from `main`, on all three operating systems. It
compiles what the pull-request jobs compile and writes the same six `shared-key` groups that the
PR gate restores, so it writes the entries that every pull request can read. Every cache key
hashes `Cargo.toml` next to `Cargo.lock`. The rule landed with FSM1/cipher-box#1776, and the
weekly schedule with FSM1/cipher-box#1246; this ADR records it.

**D6 — The updater-key drift check runs in the main gate, because it needs the release signing
secret.** `updater-key.yml` runs the `Updater Key` job on a push to `main` and on
`workflow_dispatch`. The job has the guard `if: github.ref == 'refs/heads/main'`, so a dispatch
cannot aim the signing secret at an unreviewed branch. The PR gate forwards no signing secret to
any area. A key that drifts is found after the merge, not before it; that is the accepted cost.
The owner chose option 1 of FSM1/cipher-box#1778 on 2026-09-14, and FSM1/cipher-box#1822 landed
it.

**D7 — One `nightly.yml` owns every scheduled slot, runs the full matrix every night, and reports
every failure into one tracking issue.** The slots are the long-horizon liveness run (lease
renewal at seq+1, the republisher inventory walk, and the alert on a name with no re-PUT for
more than 24 hours, against a compressed-EOL profile on the CI stack), the
full-matrix flake surveillance, and the Cloudflare Range Watch. The flake surveillance slot calls
`ci-e2e.yml` through `workflow_call` with `force-all: true`, so it runs the main-gate suites and
job names, and the absent change filter cannot skip a suite. It runs the full matrix every
night: no cost trim, no weeknights-only, and no rotating operating system (FSM1/cipher-box#1385).
With `retries: 0` as policy, a red night says "main broke" (revert) or "the environment drifted"
(fix the harness) before it blocks a release. One report job runs when any slot fails and opens,
or comments on, a single `comp:ci` tracking issue. The rule landed with FSM1/cipher-box#1833; this
ADR records it.

**D8 — `Staging E2E` gives the release verdict as step 4 of the staging pipeline, after the
deploy.** `tag-staging.yml` asserts a `v*` tag on `main` HEAD, re-runs the web, desktop and
cross-client e2e at that SHA, waits for the `staging-approval` environment, mints the staging tag,
deploys, and then calls `staging-e2e.yml` against the deployed front. A red run is the verdict on
that deploy, and it is also the first signal that the containers came up, because the deploy has
no health gate of its own. `Staging E2E` blocks no merge (#47, #48). Its sign-in rules are in
ADR 0049 D8. The rule landed with FSM1/cipher-box#1831; this ADR records it.

## Rationale

- **A law that the table contradicts is not a law.** Law 1 and `AGENTS.md` item 4 forbid what the
  tier table requires. D1 and D2 make the one sentence that an agent reads agree with the table
  that CI runs.
- **The v1 defect stays closed.** The v1 defect was a suite with no gate at all. D1 keeps "a named
  gate the day it lands, or it is deleted" for every suite, and keeps the merge block for every
  suite that asserts the behavior of a change.
- **The class is defined by what a suite measures, not by its cost.** A measurement harness gives
  a number, and a shared runner makes that number noisy. A run against a deployed or long-horizon
  environment judges something that a pull request does not contain. Neither can give a
  merge-blocking verdict on a change. A slow suite that asserts behavior is not in the class: it
  gets a PR slice and the main gate (D1). The virtual-time liveness suite is the one named
  exception, and E7 keeps it open.
- **Code that no gate compiles rots.** D3 closes the gap that D2 opens: a bench, a load scenario
  or a staging spec that no longer compiles fails the PR that broke it.
- **A secret stays on reviewed code.** D6 puts the signing key only where the executed tree is
  reviewed code on `main`.
- **A cache that no other run can read is waste.** D5 follows from how GitHub scopes a cache
  entry. Only an entry on `main` helps a later pull request.
- **A scheduled red must reach a person.** D7 sends every scheduled failure to one issue, so a
  red night is not a square nobody reads, and a week of red nights is not seven issues.

## Alternatives rejected

**(a) Put `Perf Benches` in the PR gate.** A shared runner's timings are too noisy to fail a merge
on (FSM1/cipher-box#1406). A gate that fails on noise teaches people to re-run it until it passes.

**(b) Put the load harness in the PR gate.** A load generator is a hazard, and staging is one
2-vCPU VPS. FSM1/cipher-box#960 bounds every run and keeps the workflow dispatch-only.

**(c) Make `Staging E2E` a merge gate.** It judges a deploy, and the deploy happens after the
merge and the tag. A pull request has no deployed front to drive.

**(d) Trim the nightly matrix to a rotation.** The gate text of FSM1/cipher-box#652 allowed a
rotation "if runner spend becomes real money". FSM1/cipher-box#1385 replaced it with the full
matrix every night. A rotation leaves an operating system unobserved on most nights, and the
slot exists to separate "main broke" from "environment drifted" on every platform.

**(e) Keep the updater-key check in the PR gate behind a protected environment.** Option 2 of
FSM1/cipher-box#1778. Every pull-request run would stall for an approval. Option 3, a public-key
comparison with no secret, cannot prove that the public key matches the signing key without a
signature that the release workflow commits, and a secret rotation would then be found only at
the next release.

**(f) Delete the non-blocking suites to satisfy law 1 as written.** Each of them finds a defect
class that no merge-blocking suite finds: shared-runner performance, API throughput, environment
drift, and a broken deployed front. The v2.0.2 deploy shipped two front defects that only a real
browser against the real staging front shows (FSM1/cipher-box#1821).

## Consequences

1. **`blueprint/testing.md` "CI gates" already carries D2 and D4 to D7.** The PR-gate row names
   `Tracker Refs` in the Repo area (D4). The main-gate row names `Updater Key` and states why it
   stays out of the pull-request path (D6). The dispatch and scheduled row names the load harness,
   the nightly tier and `Perf Benches` (D2, D7). The "Suite map" bullet "Staging e2e" says "It
   gates no merge: its verdict is on a deploy" (D8). The paragraph under the table states the cache
   writer rule (D5) with one error, which changes when this ADR is accepted: the sentence "A push
   to main is the only writer of those caches" becomes "A run on `main` is the only writer of
   those caches", because `cargo-cache-seed.yml` also writes on a weekly schedule and on dispatch
   from `main`. No other text change is needed there. No blueprint text carries D3 today;
   consequence 3 adds it to law 1.

2. **`blueprint/deploy.md` already carries D2, D7 and D8.** "Release-tag gating" step 4 states
   the release verdict (D8). "Scheduled tier" states the three slots, `force-all` and the one
   `comp:ci` issue (D7), and the dispatch-only load harness, "never a PR gate" (D2). No text change
   is needed there.

3. **`blueprint/testing.md` "Doctrine" law 1 changes when this ADR is accepted.** The law then
   reads: "A suite that asserts the behavior of a change and does not block a merge does not
   exist." The paragraph gains, after the v1 evidence: "Such a suite blocks a merge in the PR
   gate; where its full run does not fit, the PR gate runs a slice and the main gate runs the full
   set revert-first. A measurement harness (the load harness, `Perf Benches`) and a run against a
   deployed or long-horizon environment (the nightly tier, `Staging E2E`) block no merge and live
   in the dispatch and scheduled tier; their code still compiles in the PR gate. The virtual-time
   liveness suite is a named exception: its PR slice is the republisher unit suite, and its full
   run is nightly (ADR 0050)." The last sentence, "wired into a named gate in this doc the day it
   lands, or it is deleted", stays.

4. **`AGENTS.md` "Code Generation Guidelines" item 4 changes in the same PR.** It mirrors law 1
   and needs the same amendment: "A suite that asserts the behavior of a change and does not
   block a merge does not exist (`blueprint/testing.md` law 1): every suite is wired into a named
   CI gate the day it lands, and a measurement harness or a run against a deployed or long-horizon
   environment lives in the dispatch and scheduled tier with its code compiled in the PR gate;
   assert behavior, never source text."

5. **`blueprint/deploy.md` "v1 freeze mechanics" step 4 changes in the same PR.** It restates law
   1 in the old form ("a suite exists only if it blocks merges") and says "Job names are the
   contract; renames update the ruleset in the same PR". ADR 0018 D2 already replaced the job-name
   list with result contexts. The step reads under this ADR: required checks on `main` are the area
   result contexts and the standalone contexts (ADR 0018), and a suite of the non-blocking class
   is not a required check (ADR 0050). The code comment at `.github/workflows/ci-e2e.yml:8`, "Job
   names are the contract (blueprint/deploy.md freeze step 4).", cites the sentence that this
   change removes, so it changes in the same PR.

6. **This ADR amends #47 law 1.** #47 law 1 now reads as D1 and D2. The #47 CI tiers stand, and
   the dispatch and scheduled tier of #47 and #48 is the home of the D2 class. This closes the
   audit's `Perf Benches` lag against #47 law 1.

7. **This ADR amends ADR 0018.** ADR 0018 C3 ("A suite that lands later joins an area ... Law 1
   is met by the area's result job") now reads: a suite that lands later and asserts the behavior
   of a change joins an area and reports through its result context; a suite of the D2 class
   joins no area and is not a required context. ADR 0018 C1 said "The main-gate and dispatch rows
   do not change"; that held for ADR 0018 alone, and D6 to D8 record the later changes to those
   rows. ADR 0018 D2 and D3 do not change.

8. **Three sections gain the citation.** `blueprint/testing.md` section "CI gates" gains the
   citation (ADR 0050). `blueprint/deploy.md` sections "Release-tag gating" and "Scheduled tier"
   gain the citation (ADR 0050).

## Residuals

**E1 — No check proves law 1.** Nothing asserts that every suite is wired into a named tier, or
that every merge-blocking suite reports through a required context. A new suite outside every
workflow is found only by review. The same holds for D3: a later `--exclude` on the Rust
workspace jobs, or a change to the `@cipherbox/web-e2e` include list, can take a non-blocking
suite's code out of the PR gate with no failure.

**E2 — D6 finds a drifted key after the merge.** The main gate treats a failure revert-first, but
a drifted public key can reach `main` before the check reports. A release that is cut in that
window ships an app that can never update again. `Updater Key` is not a required context, and
the check has no pull-request slice.

**E3 — Other workflows write cargo caches under keys that the PR gate does not read.**
`perf-bench.yml`, `load-test.yml`, `desktop-e2e.yml` and `desktop-release.yml` save
`actions/cache` entries under their own keys on the ref they run on. No PR-gate job restores those
keys. A dispatch of `cargo-cache-seed.yml` from a branch other than `main` writes the six
`shared-key` groups under that branch, and a pull request does not read it. So no run off `main`
writes an entry that the PR gate reads, but no check holds this (Gate, D5).

**E4 — `blueprint/deploy.md` "Caching and hygiene" is stale.** It still describes
"`actions/cache` on cargo registry/git/target keyed per-OS on `Cargo.lock`". The PR gate uses
`Swatinem/rust-cache` with keys that hash `Cargo.toml` too (D5, ADR 0018 D4). This ADR records
`blueprint/testing.md`.

**E5 — The staging sign-in is partial.** ADR 0049 D8 and E7 state which sign-in methods
`Staging E2E` covers and which stay uncovered.

**E6 — A measurement harness has no regression band.** The load thresholds detect a whole-run
collapse only, and `Perf Benches` compares against a baseline only when a person asks it to. A
slow regression is visible only to a person who reads the artifacts.

**E7 — The virtual-time liveness suite may belong in the main gate.** The suite asserts
republisher behavior on virtual time, with no environment under it, so by D1 it belongs in the
main gate if its runtime allows. It runs nightly only today. The owner decides whether it moves.

## Gate

- **D1:** branch protection on `main` requires `Repo Result`, `API Result`, `Rust Result`,
  `Web Result`, `Desktop Result`, `Contract Suite Result`, `Web E2E Smoke Result`,
  `Detect Changes`, `lint-pr-title` and `zizmor static audit` (read on 2026-09-26). `FUSE Op Core`
  runs in the Rust area (`ci-rust.yml`, `cargo test -p cipherbox-fuse`). The main gate is
  `ci-e2e.yml` on a push to `main`. The named exception's PR slice is `republisher.task.test.ts`
  and `republisher.alerter.test.ts` in the API unit suite (`apps/api/vitest.config.ts` excludes
  `*.scheduled.test.ts`). No test asserts that every suite has a tier (E1). That is a finding.
- **D2:** `perf-bench.yml` and `load-test.yml` have the `workflow_dispatch` trigger only;
  `staging-e2e.yml` has `workflow_dispatch` and `workflow_call`; `nightly.yml` has `schedule` and
  `workflow_dispatch`. The required-context list above names none of them. No test asserts it.
- **D3:** `ci-rust.yml` job `Fmt + clippy (Linux)` (`--all-targets`, which builds the bench
  targets), job `Workspace tests (Linux)` (`cargo test --workspace`, which includes
  `cipherbox-load`), `ci-web.yml` (`pnpm --filter @cipherbox/web --filter @cipherbox/web-e2e run
typecheck`), the API typecheck (`apps/api/tsconfig.json` includes `src`), and `ci-repo.yml` job
  `Perf Tooling`. No test asserts that these stay in place (E1). That is a finding.
- **D4:** `ci-repo.yml` job `Tracker Refs` runs `node scripts/check-tracker-refs.mjs` on every
  pull request and reports through `Repo Result`. The script has no test of its own; its pattern
  and exemptions were proved by hand in FSM1/cipher-box#1067. That is a finding.
- **D5:** every `Swatinem/rust-cache` step in `ci-rust.yml`, `ci-web.yml`, `ci-desktop.yml`,
  `ci.yml` and `web-e2e.yml` carries the `save-if` on `refs/heads/main`, and `cargo-cache-seed.yml`
  runs on every push to `main` and on `cron: '0 5 * * 1'`. No test asserts it. That is a finding.
- **D6:** `updater-key.yml` job `Updater Key` (push to `main`, dispatch guarded to `main`). The
  job is the check itself. `ci-repo.yml` has no updater-key job, and `ci.yml` forwards no
  `TAURI_SIGNING_*` secret. No test asserts the absence.
- **D7:** `nightly.yml` jobs `API Long-Horizon Liveness` (`vitest.scheduled.config.ts`),
  `Full-Matrix Flake Surveillance` (`ci-e2e.yml` with `force-all: true`), `Cloudflare Range
Watch`, and `Report A Nightly Failure` (the one `comp:ci` issue). No test covers the report job.
- **D8:** `tag-staging.yml` job `Staging E2E` needs `deploy` and calls `staging-e2e.yml`. The
  `front-contract.spec.ts` interceptor cases prove that the suite fails red on the two front
  defects of the v2.0.2 deploy (FSM1/cipher-box#1831). They prove the check, not the placement
  after the deploy; no test holds the placement.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
