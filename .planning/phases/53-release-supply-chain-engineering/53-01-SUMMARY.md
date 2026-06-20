---
phase: 53-release-supply-chain-engineering
plan: 01
subsystem: infra
tags: [ci, github-actions, supply-chain, pinact, dependabot, sha-pinning]

requires:
  - phase: none
    provides: foundational supply-chain hardening for the phase
provides:
  - All 111 third-party GitHub Action uses refs SHA-pinned to immutable 40-char commit SHAs with trailing version comments
  - Dependabot github-actions block verified to keep pins current (no change)
affects: [53-02 zizmor gate, 53-03 release-please, 53-04 release-as guard]

tech-stack:
  added: [pinact 4.1.0 - one-off dev/CI tool, NOT a project dependency]
  patterns: [SHA-pin + version-comment for all third-party action refs]

key-files:
  created: []
  modified:
    - .github/workflows/ci.yml
    - .github/workflows/ci-e2e.yml
    - .github/workflows/codecov-base.yml
    - .github/workflows/deploy-landing.yml
    - .github/workflows/deploy-staging.yml
    - .github/workflows/desktop-e2e.yml
    - .github/workflows/desktop-staging-release.yml
    - .github/workflows/load-test.yml
    - .github/workflows/pr-release-preview.yml
    - .github/workflows/release-gate.yml
    - .github/workflows/release-please.yml
    - .github/workflows/tag-staging.yml
    - .github/workflows/web-e2e.yml

key-decisions:
  - 'D-01/D-02: single bulk pinact run, no hand-editing; pr-title.yml has no uses refs so it was untouched (13 of 14 files modified)'
  - 'D-03: Dependabot github-actions block already existed (chore(ci) prefix, weekly) - verified-only, no edit committed'
  - 'Re-ran pinact once: first pass hit intermittent api.github.com timeouts that left 33 actions/checkout@v6 refs as tags; idempotent re-run resolved all to df4cb1c... # v6.0.3'

patterns-established:
  - 'SHA-pin pattern: uses: owner/action@<40-hex> # vX.Y.Z for every third-party ref'
  - 'Internal reusable-workflow refs (./.github/workflows/*.yml) left as plain paths - pinact excludes them by design'
---

# 53-01 Summary: SHA-pin all third-party action refs via pinact

## What was delivered

Converted all 111 third-party `uses:` refs across 13 of 14 workflow files from
mutable tags (`@v6`, `@v0`, etc.) to immutable 40-char commit SHAs with trailing
`# vX.Y.Z` version comments, via a single bulk `pinact run` (pinact 4.1.0). This
eliminates the tag-hijacking supply-chain attack surface (T-53-01).

`pr-title.yml` was correctly left untouched (it has zero `uses:` refs). The 5
internal `./.github/workflows/*.yml` reusable-workflow refs remain plain paths
(pinact excludes them by design).

## Tool

- pinact 4.1.0 (Homebrew). Run as `GITHUB_TOKEN=<gh-token> pinact run` from repo root.
- NOT added to any project manifest (npm/cargo/pip) - one-off dev/CI tool only (T-53-SC accepted).

## Counts

- 111 third-party refs pinned (matches 53-RESEARCH per-file expectation).
- 13 files changed, 111 insertions / 111 deletions.
- 5 internal reusable-workflow refs unchanged.

## D-03 (Dependabot) — satisfied, no change

`.github/dependabot.yml` already contained exactly one `package-ecosystem: 'github-actions'`
block (directory `/`, weekly schedule, `prefix: 'chore(ci)'`). Verified present and
unmodified — Dependabot will bump both the SHA and the version comment on new releases.
No duplicate block added (Pitfall 3 avoided).

## Verification

- `pinact run --check` exits 0 (no remaining tag-pinned third-party refs).
- Guard grep for any third-party ref not matching `@<40-hex> # v`: 0 lines.
- High-risk publishers confirmed pinned: tauri-apps/tauri-action, appleboy/ssh-action,
  appleboy/scp-action, ikalnytskyi/action-setup-postgres.
- `.github/dependabot.yml` and `pr-title.yml` unmodified.
- Pins survived the lint-staged prettier pass (re-checked post-commit: 0 unpinned).

## Commit

- `chore(ci): SHA-pin all third-party GitHub Action refs via pinact` — f4abddcd9
