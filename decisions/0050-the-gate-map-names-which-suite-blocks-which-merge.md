# ADR 0050 — The gate map names which suite blocks which merge

- **Status:** Accepted on 2026-09-26 — retroactive; the tier rules shipped in FSM1/cipher-box#960,
  FSM1/cipher-box#1067, FSM1/cipher-box#1406, FSM1/cipher-box#1776, FSM1/cipher-box#1822,
  FSM1/cipher-box#1831 and FSM1/cipher-box#1833, and the `blueprint/testing.md` "CI gates"
  section carries them. Testing law 1 and `AGENTS.md` item 4 carry D1 since FSM1/cipher-box#2028;
  trimmed on 2026-09-26 to the items that pass the three ADR hurdles — the removed items live in the blueprint
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

Testing law 1 said: "A suite that does not block a merge does not exist." The same document has
always named a "Dispatch / scheduled" tier with the trigger "manual or cron", so law 1 and the
tier table disagreed from the first day. Four suites live on the non-blocking side: `Perf
Benches`, the load harness, the nightly tier and `Staging E2E`. An agent that read `AGENTS.md`
item 4 literally had to delete them or force them into the PR gate. The updater-key drift check
compares the committed updater public key with the release signing secret, so it can run only
with that secret. In the PR gate it ran `pnpm install` on the pull request's own tree with the
signing secrets in the step environment, so a same-repository author controlled code beside the
release signing key.

## Decision

**D1 — Law 1 is amended: every suite has a named gate, and a suite that asserts the behavior of a
change blocks a merge.** Every suite is wired into a named tier of `blueprint/testing.md` "CI
gates" the day it lands, or it is deleted. A suite that asserts the behavior of a change blocks a
merge in the PR gate. It reports through an area result context or a standalone context that
branch protection requires (ADR 0018 D2 and C3). Where the
full run of such a suite does not fit the PR gate, the PR gate runs a slice of it and the main
gate runs the full set on every push to `main`, revert-first: "a smoke slice blocks every PR, the
full matrix blocks main" (`blueprint/testing.md` "Doctrine", the v1 table). Where the suite needs
a secret that a pull-request run must not hold, the main gate runs it alone (D6).

One suite is a named exception to D1. The virtual-time liveness suite
(`apps/api/src/republisher/republisher.scheduled.test.ts`) asserts republisher behavior over
months of virtual time. Its PR slice is the republisher unit tests in the API unit suite, and its
full run is nightly only (E7).

**D2 — Two kinds of suite block no merge, by design, and they live in the dispatch and scheduled
tier.** The first kind is a measurement harness: the load harness (`crates/load`,
`load-test.yml`) and `Perf Benches` (`perf-bench.yml`). Its result is a number, and a number from a
shared runner is too noisy to fail a merge on. The second kind is a run against a deployed or
long-horizon environment: the nightly tier (`nightly.yml`) and `Staging E2E`
(`staging-e2e.yml`). Its subject is an environment or a deploy, not the change in a pull
request. A suite of either kind is still wired into a named tier (D1), and its code still
compiles in the PR gate. It is never a required status context. The load harness has no
production target, and its staging target passes the approval of the `staging` environment.

**D6 — The updater-key drift check runs in the main gate, because it needs the release signing
secret.** `updater-key.yml` runs the `Updater Key` job on a push to `main` and on
`workflow_dispatch`. The job has the guard `if: github.ref == 'refs/heads/main'`, so a dispatch
cannot aim the signing secret at an unreviewed branch. The PR gate forwards no signing secret to
any area. A key that drifts is found after the merge, not before it; that is the accepted cost.
The owner chose option 1 of FSM1/cipher-box#1778 on 2026-09-14, and FSM1/cipher-box#1822 landed
it.

Items D3, D4, D5, D7 and D8 moved to `blueprint/testing.md` "Doctrine" and "CI gates", and `blueprint/deploy.md` "Release-tag gating" and "Scheduled tier", on 2026-09-26.

## Rationale

- **D1:** a law that the table contradicts is not a law; the amendment keeps "a named gate the
  day it lands, or it is deleted" for every suite, so the v1 defect stays closed.
- **D2:** the class is defined by what a suite measures, not by its cost; a slow suite that
  asserts behavior gets a PR slice and the main gate instead.
- **D6:** the signing secret runs only where the executed tree is reviewed code on `main`.

## Alternatives rejected

**(a) Put `Perf Benches` in the PR gate.** A gate that fails on shared-runner noise teaches people
to re-run it until it passes.

**(b) Put the load harness or `Staging E2E` in the PR gate.** A load generator is a hazard, and
staging is one 2-vCPU VPS. `Staging E2E` judges a deploy, which happens after the merge and the
tag.

**(e) Keep the updater-key check in the PR gate.** Behind a protected environment (option 2 of
FSM1/cipher-box#1778), every pull-request run stalls for an approval. A public-key comparison with
no secret (option 3) cannot prove that the public key matches the signing key.

**(f) Delete the non-blocking suites to satisfy law 1 as written.** Each of them finds a defect
class that no merge-blocking suite finds: shared-runner performance, API throughput, environment
drift, and a broken deployed front.

## Consequences

1. `blueprint/testing.md` "CI gates" carries D2 and D6.
2. `blueprint/deploy.md` "v1 freeze mechanics" step 4 states that a suite of the D2 class is not a required check.
3. `blueprint/testing.md` "Doctrine" law 1 reads as D1 and D2.
4. `AGENTS.md` "Code Generation Guidelines" item 4 mirrors the amended law 1.
5. ADR 0018 C3 and #47 law 1 are amended: a suite of the D2 class joins no area and is not a required context.

## Residuals

**E2 — D6 finds a drifted key after the merge.** A release that is cut before the check reports
ships an app that can never update again. `Updater Key` is not a required context.

**E7 — The virtual-time liveness suite may belong in the main gate.** The suite asserts
republisher behavior on virtual time, with no environment under it, so by D1 it belongs in the
main gate if its runtime allows. It runs nightly only today. The owner decides whether it moves.
