# ADR 0018 — The PR gate is grouped by area, with an adapter leg per desktop platform

- **Status:** Accepted — `blueprint/testing.md` reworded in FSM1/cipher-box#1776 (merged); trimmed on 2026-09-26 to the items that pass the three ADR hurdles — the removed items live in the blueprint
- **Date:** 2026-09-06
- **Relates to:**
  [FSM1/cipher-box#1775](https://github.com/FSM1/cipher-box/issues/1775) (the CI run time and
  the flat job list this ADR settles),
  `blueprint/testing.md` "CI tiers" (the PR-gate row this ADR rewords) and law 1 (every suite
  blocks a merge in a named gate),
  `blueprint/desktop.md` "CredentialStore" (the OS keychain seam the adapter leg proves).
- **Implemented by:** FSM1/cipher-box#1776, which restructures `ci.yml`, sets the test-profile
  build rule, and rewords the PR-gate row of `blueprint/testing.md` after acceptance.

## Context

`ci.yml` ran 24 merge-blocking jobs, and each job name was a required status check in branch
protection. A rename of one job was therefore a change to branch protection, and every open PR
lost its reported check at the switch. A macOS leg ran the keyring conformance suite against the
real Apple Keychain, but the PR-gate row of the blueprint did not name it. Law 1 says every suite
blocks a merge in a named gate, so a reader could remove the leg and break law 1 with no diff to
the blueprint. The Windows leg ran the whole workspace test set, which duplicated the engine
simulation that the Linux legs already ran. The blueprint already had a stable-context shape in
`Contract Suite Result` and `Web E2E Smoke Result`, where the jobs behind the context can change
freely.

## Decision

1. **The PR gate is grouped by area.** `ci.yml` is one caller that holds the path filters and
   calls one reusable workflow per area: Repo, API, Rust, Web, Desktop. A job's name states what
   it checks and in which language. Each TypeScript package is typechecked, tested, and built once,
   inside its area.
2. **Each area ends in one stable result context.** The result job needs every job of its area,
   runs always, fails when any needed job failed or was cancelled, and passes when every needed
   job succeeded or was skipped by the path filter. Branch protection requires the result contexts
   and the standalone contexts that stay outside an area. It requires no job inside an area.
3. **The PR gate has an adapter leg per shipped desktop platform.** The macOS and Windows legs
   each run a workspace check with all targets, the tests of the OS adapter crates, and the
   keyring conformance suite against the real OS backend. Neither leg runs the engine simulation:
   the engine is platform-neutral and the Linux Rust area owns it. Linux adapter coverage stays
   on the main-gate mounted matrix, where a mount exists.

Item D4 moved to `blueprint/testing.md` "CI gates" on 2026-09-26.

## Alternatives rejected

- **Name the macOS leg in the row and change nothing else.** Closes the law-1 gap and leaves the
  duplicate API unit run and the 24-name protection list.
- **Drop the macOS leg.** The Keychain conformance run is the only proof of the credential seam
  against the backend it ships on. `blueprint/desktop.md` makes that seam the shell's one
  credential duty, so its proof belongs in the merge gate.
- **Run the engine simulation on every platform.** The engine has no `cfg(target_os)` surface. The
  cost is 15 minutes per leg for no platform-specific finding.
- **Keep the flat job list and rename the jobs.** Every later rename is a branch-protection
  switch that strands the open PRs. The result contexts end that.

## Consequences

**C1 —** `blueprint/testing.md` "CI gates", the PR-gate row, carries D1 to D3.

**C3 — A suite that lands later joins an area** and reports through that area's result context. Law
1 is met by the area's result job, so no suite needs its own protection entry.
Amended by ADR 0050 D1 and D2 on 2026-09-26: a suite that lands later and asserts the behavior of
a change joins an area and reports through its result context. A suite of the ADR 0050 D2 class
joins no area and is not a required context.

## Residuals

- **E1 — The Linux adapter backend has no PR-gate proof.** The Linux keyring backend needs a
  secret service that the runner does not offer, and a mount needs the main-gate matrix. Both
  stay post-merge.

## Gate

Branch protection on `main` requires the area result contexts; `Rust Result` carries the macOS and Windows adapter legs.
