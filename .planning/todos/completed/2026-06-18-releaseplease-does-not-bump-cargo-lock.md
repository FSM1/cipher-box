---
created: 2026-06-18
title: release-please bumps crate Cargo.toml versions but not Cargo.lock
area: ci
files:
  - release-please-config.json
  - .release-please-manifest.json
  - Cargo.lock
  - .github/workflows/release-please.yml
---

## Problem

release-please bumps the Rust crates' versions in their `Cargo.toml`
(`crates/core` → 0.5.1, `crates/fuse` → 0.6.1, plus `apps/desktop/src-tauri`
via `extra-files`) but does **not** regenerate the workspace `Cargo.lock`. The
lockfile still carries the previous `[[package]] version` for each bumped crate,
so after every release `main` is left with a **stale Cargo.lock**.

Observed 2026-06-18: after the release PR (#510) merged, `Cargo.lock` still had
`cipherbox-core 0.5.0` / `cipherbox-fuse 0.6.0` while the `Cargo.toml`s read
`0.5.1` / `0.6.1`. The drift surfaces as a spurious `Cargo.lock` diff the moment
anyone runs any `cargo` command (build, test, or even rust-analyzer), which then
has to be committed out-of-band — exactly what happened here.

### Why it matters

- Every release leaves `main` dirty-on-first-cargo-invocation; the lockfile sync
  becomes a manual chore detached from the release.
- A stale lockfile can cause confusing CI churn and makes `--locked`/`--frozen`
  builds fail until someone regenerates it.
- It silently erodes the guarantee that `main` is in a clean, buildable,
  reproducible state immediately post-release.

## Solution

TBD — make the release process keep `Cargo.lock` in sync with the version bumps.
Options to evaluate:

- **Post-bump `cargo update -p <crate> --precise <new-version>` (or
  `cargo generate-lockfile`)** inside the release-please workflow, committed onto
  the release PR before merge. release-please supports extra steps / generic
  updaters; a workspace `cargo update --workspace` limited to the bumped crates
  is the minimal correct touch.
- **release-please `Cargo.lock` updater** — release-please has cargo-aware
  components; confirm whether enabling a `Cargo.lock`/workspace updater in
  `release-please-config.json` makes it rewrite the lock's `[[package]] version`
  entries for first-party crates automatically.
- **CI guard** — a cheap `cargo metadata`/`cargo update --locked --dry-run` (or
  `git diff --exit-code Cargo.lock` after `cargo generate-lockfile`) check that
  fails the release PR if the lockfile is out of sync, so it can never merge
  stale.

Prefer whichever keeps the lock update **on the release PR itself** so `main` is
never stale post-merge.

## Notes

- First-party crates only need their `[[package]] version` lines updated; no
  dependency resolution changes (the diff is literally two version strings).
- Verified the bump is correct/safe before committing the out-of-band sync on
  2026-06-18 (lock now matches the released 0.5.1 / 0.6.1).
