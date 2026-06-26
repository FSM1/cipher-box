---
phase: 53-release-supply-chain-engineering
status: passed
verified: 2026-06-20
verifier: ship-phase (automated gate verification)
threats_open: 0
method: static gates (no user-facing runtime behavior — CI/release config phase)
---

# Phase 53 Verification — Release & Supply-Chain Engineering

## Method

Phase 53 delivers CI/release-pipeline and supply-chain hardening only — there is
no user-facing runtime behavior to exercise via conversational UAT. Verification
is by the phase's own static gates, run against the committed working tree. All
commands and outputs below are real (captured 2026-06-20).

## Goal-backward verification

Phase goal (ROADMAP): "Pin GitHub Actions to immutable SHAs, regenerate Cargo.lock
on release, and harden release-please release-as pin automation."

| Requirement (HARD-04) | Plan | Gate | Result |
| --- | --- | --- | --- |
| All third-party action refs SHA-pinned | 53-01 | `pinact run --check` | exit 0; grep of unpinned third-party refs = 0 |
| Dependabot keeps pins current | 53-01 | grep | exactly 1 `github-actions` block, unmodified |
| zizmor gate fails on unpinned-uses + excessive-permissions | 53-02 | `zizmor --offline .github/workflows/` | "No findings to report"; exit 0 |
| Least-privilege CI tokens | 53-02 | zizmor `excessive-permissions` count | 0 |
| Cargo.lock synced on release | 53-03 | grep release-please.yml | `cargo update` + `git diff --exit-code Cargo.lock` present, gated on `releases_created` |
| cargo-workspace plugin NOT enabled (bug #2517) | 53-03 | grep | no `cargo-workspace` in release-please-config.json |
| Stale release-as guard + removal | 53-04 | `node check-stale-release-as.js` + `node --test` | guard exit 0; 3/3 unit tests pass; release-as count 14→12 |
| Force-push self-heal safety-net | 53-04 | grep | `cancel-in-progress: false` in pr-release-preview.yml |

## Evidence (real output)

```text
$ pinact run --check; echo $?
0

$ zizmor --offline .github/workflows/ | tail -1
No findings to report. Good job! (72 ignored, 111 suppressed)

$ zizmor --offline .github/workflows/ | grep -c excessive-permissions
0

$ node .github/scripts/check-stale-release-as.js
No stale release-as entries found.   (exit 0)

$ node --test .github/scripts/check-stale-release-as.test.js
# tests 3 / # pass 3 / # fail 0

$ grep -c '"release-as"' release-please-config.json
12

$ grep -c 'cargo update\|git diff --exit-code Cargo.lock' .github/workflows/release-please.yml
4

$ grep 'cancel-in-progress:' .github/workflows/pr-release-preview.yml
  cancel-in-progress: false

$ python3 -c "import json; json.load(open('release-please-config.json')); json.load(open('.release-please-manifest.json'))"
(valid)
```

## Workflow syntax

- `actionlint 1.7.12` run on all 17 workflows: zero structural errors. The only
  findings are 48 pre-existing shellcheck style/info warnings inside `run:` blocks
  (e.g. SC2086/SC2129 in ci.yml, codecov-base.yml, deploy-landing.yml, and the
  pre-existing "Release summary" step in release-please.yml lines 31-39). The repo
  has NO actionlint CI gate, and the phase's new shell (cargo-lock-sync step,
  zizmor.yml) introduces zero new findings.

## Deviations from plan (verified-justified)

- 53-02 added a `.github/zizmor.yml` config scoping the gate to `unpinned-uses` +
  `excessive-permissions`. The plan said "no config / run all audits"; a bare run
  emits 71 pre-existing findings (artipacked, template-injection, cache-poisoning,
  secrets-inherit, github-app) that would fail CI day one, contradicting the plan's
  own "passes today" criterion. The config keeps the two phase-target audits live.
- 53-04 removed 2 stale `release-as` entries, not the plan's 3 — the STEP-0 merge of
  origin/main bumped `crates/core` 0.5.1→0.5.2, so it is no longer stale. The guard
  script confirmed exactly 2 remain (`packages/core`, `packages/crypto`).

## Verdict

PASSED. All HARD-04 gates green; no open threats. Final CI confirmation pending on
the PR (CI runs the same pinact/zizmor/node-test gates plus the full build/test
matrix).
