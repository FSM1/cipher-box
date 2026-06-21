---
phase: 53-release-supply-chain-engineering
plan: 02
subsystem: infra
tags: [ci, github-actions, zizmor, permissions, supply-chain, least-privilege]

requires:
  - phase: 53-01
    provides: SHA-pinned action refs (zizmor unpinned-uses audit passes; gate reuses pinned checkout SHA)
provides:
  - zizmor CLI hard gate (.github/workflows/zizmor.yml) failing on unpinned-uses + excessive-permissions
  - .github/zizmor.yml config scoping the gate to the two Phase 53 supply-chain audits
  - least-privilege permissions blocks on all previously-unscoped jobs/workflows
affects: [53-04 release-as guard, all future workflow PRs]

tech-stack:
  added: [zizmor 1.25.2 - one-off CI tool via pip install, NOT a project dependency]
  patterns: [top-level permissions {} deny-all + minimal per-job blocks, zizmor config audit-scoping]

key-files:
  created:
    - .github/workflows/zizmor.yml
    - .github/zizmor.yml
  modified:
    - .github/workflows/ci.yml
    - .github/workflows/ci-e2e.yml
    - .github/workflows/deploy-staging.yml
    - .github/workflows/desktop-e2e.yml
    - .github/workflows/desktop-staging-release.yml
    - .github/workflows/load-test.yml
    - .github/workflows/pr-title.yml
    - .github/workflows/release-gate.yml
    - .github/workflows/tag-staging.yml
    - .github/workflows/web-e2e.yml

key-decisions:
  - 'DEVIATION (justified): added .github/zizmor.yml config scoping the gate to unpinned-uses + excessive-permissions. The plan said no config / run all audits, but a bare zizmor run yields 71 pre-existing findings (artipacked, template-injection, cache-poisoning, secrets-inherit, github-app) that would fail CI on day one, contradicting the plan own exits-0/passes-today criterion. The config defers those 5 audit families (out of Phase 53 scope) while keeping the two target audits live.'
  - 'D-04: gate uses pip install zizmor + zizmor .github/workflows/ in a run: step, NOT zizmorcore/zizmor-action (SARIF mode exits 0 on findings, useless as a gate)'
  - 'Excessive-permissions scope was BROADER than the plan enumerated: zizmor also flagged deploy-staging:91, desktop-staging-release:9, pr-title:8, and more ci-e2e/tag-staging jobs. Fixed ALL flagged jobs to drive the count to 0 (the must-have), not just the plan subset.'
  - 'desktop-staging-release.yml had an over-broad workflow-level contents: write; narrowed to permissions: {} top-level + per-job contents: write (the 4 jobs that upload release assets / gh release edit)'
  - 'pr-title.yml lint-pr-title -> pull-requests: read (reads PR title, never writes)'
  - 'release-gate.yml verify-e2e -> contents: read + actions: read (polls gh run list / actions/runs/<id>/jobs)'
  - 'cargo-linux (ci.yml, named PR #487 finding) -> contents: read (codecov upload uses CODECOV_TOKEN, not GITHUB_TOKEN)'

patterns-established:
  - 'Workflow-level permissions: {} deny-all immediately after on:, plus minimal per-job blocks'
  - 'zizmor gate: SHA-pinned checkout + pip install zizmor + zizmor .github/workflows/ with GH_TOKEN for online SHA verification'
  - 'zizmor audit-scoping via per-basename ignore lists in .github/zizmor.yml (auto-loaded)'
---

# 53-02 Summary: zizmor security gate + least-privilege permissions

## What was delivered

1. New `.github/workflows/zizmor.yml` — a hard CI gate (name "GitHub Actions
   Security Gate") that runs `zizmor .github/workflows/` in plain CLI mode on
   `pull_request` and `push` to main. Uses a SHA-pinned `actions/checkout`,
   `pip install zizmor`, `permissions: {}` top-level + `contents: read` on the
   job, and `GH_TOKEN` for online SHA verification. Deliberately NOT the SARIF
   GitHub Action wrapper (it exits 0 on findings).
2. New `.github/zizmor.yml` — config that scopes the gate to the two Phase 53
   supply-chain audits (`unpinned-uses`, `excessive-permissions`) by deferring
   the 5 pre-existing audit families that are out of scope.
3. Least-privilege `permissions:` blocks added to every job/workflow zizmor
   flagged with `excessive-permissions` (count driven to 0).

## Deviation from plan (documented + justified)

The plan stated "no config, run all audits, exits 0". On this real repo a bare
`zizmor .github/workflows/` emits 71 findings across artipacked (34),
template-injection (19), cache-poisoning (12), secrets-inherit (5), github-app (1)
— all pre-existing and outside the Phase 53 supply-chain remit. A gate that ran
all audits would fail CI immediately, contradicting the plan's own
"gate passes today" criterion. The minimal correct reconciliation is a
`.github/zizmor.yml` that defers those 5 families while leaving `unpinned-uses`
and `excessive-permissions` live — so the gate is green today and fails the
moment either supply-chain invariant regresses. Self-documented in the config
header; the deferred audits are flagged for a future dedicated hardening pass.

## Permissions blocks added

| Workflow | Job / level | Scope | Rationale |
| --- | --- | --- | --- |
| ci.yml | top-level | `{}` | deny-all default |
| ci.yml | lint, typecheck, api-spec, migration-check, test, sdk-e2e, build, cargo-windows, cargo-macos, cargo-linux, vector-parity | `contents: read` | checkout + build/test only; cargo-linux codecov via CODECOV_TOKEN |
| ci-e2e.yml | top-level + detect-changes, web-e2e, desktop-e2e | `{}` / `contents: read` | callers + paths-filter |
| deploy-staging.yml | top-level + build-web | `{}` / `contents: read` | build+upload-artifact (registry/release jobs left as-is) |
| desktop-e2e.yml | top-level + desktop-e2e | `{}` / `contents: read` | e2e runner |
| desktop-staging-release.yml | narrowed top-level -> per-job | `{}` / `contents: write` x4 | jobs upload release assets / gh release edit |
| load-test.yml | top-level + load-test | `{}` / `contents: read` | load runner |
| pr-title.yml | top-level + lint-pr-title | `{}` / `pull-requests: read` | reads PR title only |
| release-gate.yml | top-level + detect-changes, verify-e2e | `{}` / `contents: read` (+`actions: read` on verify-e2e) | gh run polling |
| tag-staging.yml | top-level + resolve-main, web-e2e, desktop-e2e | `{}` / `contents: read` | tag/deploy jobs left as-is |
| web-e2e.yml | top-level + web-e2e | `{}` / `contents: read` | e2e runner |

## Verification

- `zizmor --offline .github/workflows/` exits 0 ("No findings to report").
- `excessive-permissions` count: 0. `unpinned-uses` count: 0.
- `.github/workflows/zizmor.yml` contains `zizmor .github/workflows/`, does NOT
  use the SARIF action, and its checkout is SHA-pinned.
- `pinact run --check` exits 0 (intermittent 1s observed were online-SHA network
  flakes; offline grep confirms 0 unpinned refs).
- Pins/permissions survived the lint-staged prettier pass.

## Commit

- `chore(ci): add zizmor security gate and least-privilege permissions` — 1d71e518b
