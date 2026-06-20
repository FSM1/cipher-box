---
phase: 53-release-supply-chain-engineering
plan: 03
subsystem: infra
tags: [ci, release-please, cargo, cargo-lock, supply-chain, rust, monorepo]

requires:
  - phase: 53-01
    provides: SHA-pinned action refs (the new checkout ref reuses the pinned actions/checkout SHA)
provides:
  - Post-release Cargo.lock sync step in release-please.yml for bumped first-party crates
  - Stale-lock guard (git diff --exit-code Cargo.lock) so main is never stale-on-first-cargo
affects: [53-04 release-as pin guard]

tech-stack:
  added: []
  patterns: [cargo update --precise per released first-party crate, gated on releases_created]

key-files:
  created: []
  modified:
    - .github/workflows/release-please.yml

key-decisions:
  - 'D-05: FALLBACK path chosen. Native cargo-workspace plugin REJECTED due to open bug googleapis/release-please#2517 (skips Cargo.lock + .release-please-manifest.json updates in monorepo/manifest mode)'
  - 'Crate-path to package-name map: crates/api-client->cipherbox-api-client, crates/core->cipherbox-core, crates/crypto->cipherbox-crypto, crates/fuse->cipherbox-fuse, crates/sdk->cipherbox-sdk, apps/desktop->cipherbox-desktop'
  - 'apps/desktop is release-type node but bumps src-tauri/Cargo.toml (cipherbox-desktop) via extra-files, so it is included in the sync map'
  - 'Parse release-please manifest-mode outputs via the "<path>--version" keys (strip --version suffix to get the path)'
  - 'New checkout ref reuses the 53-01 pinned actions/checkout@df4cb1c... # v6.0.3 so pinact run --check stays green'

patterns-established:
  - 'Conditional post-release step: if steps.release.outputs.releases_created == ''true'' with RELEASES_OUTPUT toJSON + app-token'
  - 'cargo update -p <pkg> --precise <ver> updates only that crate''s [[package]] version line, no transitive re-resolution'
---

# 53-03 Summary: Cargo.lock sync on release

## What was delivered

Appended two post-release steps to `.github/workflows/release-please.yml`, both
gated on `steps.release.outputs.releases_created == 'true'`:

1. A SHA-pinned `actions/checkout` (token = app-token, `fetch-depth: 0`) so the
   workflow can update and push the lock.
2. A "Update Cargo.lock for released crates" step (id `cargo-lock-sync`) that:
   - Parses the release-please manifest-mode outputs (`<path>--version` keys).
   - Maps each released first-party crate path to its cargo package name.
   - Runs `cargo update -p <pkg> --precise <ver>` for each bumped first-party crate.
   - Runs `git diff --exit-code Cargo.lock` as the stale guard — empty diff is a
     no-op success; non-empty diff is committed (`chore(ci): sync Cargo.lock for
     released crates`) and pushed, with a post-commit `git diff --exit-code`
     re-check so main is never stale-on-first-cargo (T-53-03).

## D-05 path: FALLBACK (cargo-workspace plugin rejected)

The native release-please `cargo-workspace` plugin (the D-05 "preferred" path) was
NOT enabled: open bug googleapis/release-please#2517 (March 2025) causes it to skip
Cargo.lock AND `.release-please-manifest.json` updates in this repo's manifest/monorepo
mode — enabling it would regress the working release pipeline. `release-please-config.json`
is unchanged (no `cargo-workspace` plugin key).

## Crate-name to path mapping used

| release-please path | cargo package | release-type |
| --- | --- | --- |
| crates/api-client | cipherbox-api-client | rust |
| crates/core | cipherbox-core | rust |
| crates/crypto | cipherbox-crypto | rust |
| crates/fuse | cipherbox-fuse | rust |
| crates/sdk | cipherbox-sdk | rust |
| apps/desktop | cipherbox-desktop | node (Cargo.toml bumped via extra-files) |

## New step id

`cargo-lock-sync` in `release-please.yml`.

## Verification

- `release-please.yml` contains `cargo update`, `git diff --exit-code Cargo.lock`,
  both inside a `releases_created == 'true'`-gated step.
- `release-please-config.json` contains no `cargo-workspace`.
- `pinact run --check` exits 0 (new checkout ref SHA-pinned).
- zizmor findings on this file are limited to a pre-existing `github-app` (line 18,
  not introduced here) and an `artipacked` on the new push-capable checkout
  (`persist-credentials` intentionally retained because the step pushes) — neither
  is in the plan's target audit set (`unpinned-uses` + `excessive-permissions`).
  These are scoped out by the 53-02 zizmor gate config.

## Commit

- `chore(ci): sync Cargo.lock for released crates on release` — e9b18a9d1
