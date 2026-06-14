---
created: 2026-06-14T14:40:38.000Z
title: Pin GitHub Actions to immutable SHAs (CI supply-chain hardening)
area: ci
files:
  - .github/workflows/ci.yml
  - .github/workflows/ci-e2e.yml
  - .github/workflows/codecov-base.yml
  - .github/workflows/deploy-landing.yml
  - .github/workflows/deploy-staging.yml
  - .github/workflows/desktop-e2e.yml
  - .github/workflows/desktop-staging-release.yml
  - .github/workflows/load-test.yml
  - .github/workflows/pr-release-preview.yml
  - .github/workflows/pr-title.yml
  - .github/workflows/release-gate.yml
  - .github/workflows/release-please.yml
  - .github/workflows/tag-staging.yml
  - .github/workflows/web-e2e.yml
---

## Problem

Every third-party GitHub Action across the 14 workflow files is referenced by a
**mutable version tag** — 111 `uses:` refs, **zero** pinned to a commit SHA. A tag
like `@v6` can be force-moved by the action's maintainer (or an attacker who
compromises their account) to point at malicious code, which would then run in CI with
access to repo secrets. GitHub's own hardening guidance and the `zizmor` SAST linter
both flag this (`unpinned-uses`, "required by blanket policy").

Surfaced by CodeRabbit + zizmor on PR #487 (the three `codecov/codecov-action@v7`
refs at `ci.yml` lines 335/660/671). Deliberately **not** fixed in that PR: pinning
only codecov would have made it the lone SHA-pinned action among 111 and broken the
repo-wide convention. This todo tracks doing it consistently across the whole suite.

Distinct third-party actions in use (count) — these are what need pinning:

```
33  actions/checkout@v6              5  actions/upload-artifact@v7
20  actions/setup-node@v6           4  codecov/codecov-action@v7
18  pnpm/action-setup@v6            3  appleboy/ssh-action@v1.2.5
 9  actions/cache@v5                3  appleboy/scp-action@v1.0.0
 6  tauri-apps/tauri-action@v0      2  dorny/paths-filter@v4
 2  docker/login-action@v4          2  docker/build-push-action@v7
 1  ikalnytskyi/action-setup-postgres@v8   1  googleapis/release-please-action@v5
 1  actions/download-artifact@v8    1  actions/create-github-app-token@v3
```

The higher-risk ones are the non-GitHub-owned, lower-profile publishers
(`appleboy/*`, `dorny/*`, `ikalnytskyi/*`, `tauri-apps/*`) — prioritize those if doing
it incrementally. The three `./.github/workflows/*.yml` reusable-workflow refs are
internal and do NOT need SHA pinning.

## Solution

Pin every third-party action to a full 40-char commit SHA with a trailing version
comment, e.g.:

```yaml
- uses: actions/checkout@<40-char-sha> # v6.0.0
```

**Critical companion step — otherwise this regresses into staleness:** enable
Dependabot for the `github-actions` ecosystem (`.github/dependabot.yml`) so it bumps
the pinned SHAs (and updates the version comments) on new releases. Without it, pinning
freezes CI on whatever SHA was current and silently stops receiving security patches —
the exact maintenance-drift trade-off called out when this was deferred on PR #487.

Recommended approach:

1. Use a tool to do the bulk conversion rather than hand-editing 111 refs —
   [`pinact`](https://github.com/suzuki-shunsuke/pinact) or
   [`ratchet`](https://github.com/sethvargo/ratchet) both resolve tags→SHAs and add
   version comments idempotently.
2. Add/extend `.github/dependabot.yml` with a `package-ecosystem: "github-actions"`
   entry so pins stay current.
3. (Optional, prevents regressions) Add a `zizmor` CI gate so any newly introduced
   unpinned ref fails the build. This also covers the related zizmor finding from the
   same scan: the `cargo-linux` job in `ci.yml` (and any others) lacking a job-level
   `permissions:` block (`excessive-permissions`) — add least-privilege `permissions:`
   while in here.

Scope note: pure CI hardening, no app-code or runtime impact. Verify by re-running the
full workflow suite on a PR after conversion (the SHAs must resolve to the same action
versions currently in use, so behavior should be unchanged).
