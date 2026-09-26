# ADR 0018 — The PR gate is grouped by area, with an adapter leg per desktop platform

- **Status:** Accepted — `blueprint/testing.md` reworded in FSM1/cipher-box#1776 (merged)
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

### What the PR gate runs today, and what the blueprint says it runs

The blueprint's PR-gate row names its contents as a list: lint and typecheck, the tracker scan,
the cargo workspace tests, the FUSE operation core, the WASM KAT run, the browser suite, the TS
unit suites, the contract suite, "Windows cargo check + adapter tests", the migration drift
check, and the e2e smoke slice. The row names no macOS leg.

`ci.yml` runs 24 merge-blocking jobs. Three of them differ from the row:

- **A macOS leg exists and blocks merges.** It runs a workspace check, the workspace tests, and
  the keyring conformance suite against the real Apple Keychain. Law 1 says every suite blocks a
  merge in a named gate. The Keychain run has no named home in the table, so a reader of the
  blueprint can remove the leg and break law 1 without a diff to the blueprint.
- **The Windows leg runs the whole workspace test set.** The row asks for a check plus the
  adapter tests. The extra tests are the engine simulation, which the Linux legs already run.
- **Three jobs named `Typecheck`, `Test`, and `Build` run `pnpm -r` over every TypeScript
  package.** The names say neither the language nor the packages. `Test` runs the API unit suite
  a second time next to the `API Unit` job.

### Where the run time goes

A PR run takes about 30 minutes. Compile time is equal on every leg; the critical path is test
execution in three engine test binaries, and the cause is two-fold. The workspace has no cargo
profile, so every dependency compiles at opt-level 0 in the test profile. The slow tests are the
bound tests: one signature, key derivation, or seal per item up to a ceiling. The Azure runners are
slow per thread, and the unoptimized crypto amplifies that by about ten.

| Engine test binary            | Linux runner | macOS runner |
| ----------------------------- | ------------ | ------------ |
| engine unit tests, 1702 tests | 6 min 10 s   | 52 s         |
| `write_plane`, 219 tests      | 5 min 32 s   | 30 s         |
| `owner_actions`, 77 tests     | 2 min 12 s   | 11 s         |

The same tests in a Linux container on an M-series Mac run at macOS speed, so the operating
system is not the cause. With dependencies at opt-level 3 the full-contact-book test drops from
7 s to 0.9 s on the Mac.

### What a check name is for

A required status check is a name in branch protection. Today the 24 job names are the required
checks, so a rename of one job is a change to branch protection, and every open PR loses its
reported check at the switch. The blueprint already has the other shape in two places: `Contract
Suite Result` and `Web E2E Smoke Result` are stable contexts that one reusable workflow reports
through, so the jobs behind them can change freely.

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
4. **Dependencies compile optimized in the test profile.** The workspace `Cargo.toml` sets
   `[profile.dev.package."*"] opt-level = 3`. Workspace crates stay at opt-level 0. Every cargo
   cache key hashes `Cargo.toml` next to `Cargo.lock`.

## Alternatives rejected

- **Name the macOS leg in the row and change nothing else.** Closes the law-1 gap and leaves the
  30-minute run, the duplicate API unit run, and the 24-name protection list.
- **Drop the macOS leg.** The Keychain conformance run is the only proof of the credential seam
  against the backend it ships on. `blueprint/desktop.md` makes that seam the shell's one
  credential duty, so its proof belongs in the merge gate.
- **Run the engine simulation on every platform.** The engine has no `cfg(target_os)` surface. The
  cost is 15 minutes per leg for no platform-specific finding.
- **Keep the flat job list and rename the jobs.** Every later rename is a branch-protection
  switch that strands the open PRs. The result contexts end that.
- **Optimize the whole test profile.** `opt-level` on the workspace crates removes debug
  information from the code under test; the bound tests are slow in the dependencies, not in the
  workspace crates.

## Consequences

1. **`blueprint/testing.md` changes when this ADR is accepted.** The PR-gate row lists the five
   areas and the standalone contexts, names the adapter leg per desktop platform, and states that
   branch protection requires the result contexts. A new paragraph under the tier table states the
   test-profile build rule. The main-gate and dispatch rows do not change.
   Amended by ADR 0050 D6 to D8 on 2026-09-26: the main-gate and dispatch rows stayed the same under
   this ADR alone, and ADR 0050 D6 to D8 record the later changes to those rows.
2. **Branch protection switches once**, at the merge of FSM1/cipher-box#1776, from the 24 job names
   to the result contexts. Every open PR re-runs CI after the switch.
3. **A suite that lands later joins an area** and reports through that area's result context. Law
   1 is met by the area's result job, so no suite needs its own protection entry.
   Amended by ADR 0050 D1 and D2 on 2026-09-26: a suite that lands later and asserts the behavior of
   a change joins an area and reports through its result context. A suite of the ADR 0050 D2 class
   joins no area and is not a required context.
4. **The expected PR run is near 10 minutes**, with the critical path at the repo lint plus the
   engine simulation tests.

## Residuals

- **E1 — The Linux adapter backend has no PR-gate proof.** The Linux keyring backend needs a
  secret service that the runner does not offer, and a mount needs the main-gate matrix. Both
  stay post-merge.
- **E2 — Optimized dependencies change nothing under test but change the timing of the tests.** A
  test that passed only because a dependency was slow would now fail. None is known; the change
  runs the whole gate as its own proof.

## Gate

- `blueprint/testing.md` PR-gate row names the five areas, the adapter leg per desktop platform,
  and the result-context rule; a paragraph states the test-profile build rule.
- Branch protection on `main` requires the area result contexts and no job inside an area.
- `ci.yml` calls one reusable workflow per area; the macOS and Windows legs run no engine test.
- The workspace `Cargo.toml` carries the profile rule, and every cargo cache key hashes it.
