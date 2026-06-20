---
created: 2026-06-20T05:00
title: Reconsider Cargo.lock release sync — cargo update --precise per-crate vs --workspace
area: ci-release
phase: future-hardening
files:
  - .github/workflows/release-please.yml
---

## Summary

The Phase 53 Cargo.lock release-sync step (`release-please.yml`, `cargo-lock-sync`)
loops over each released first-party crate and runs
`cargo update -p <pkg> --precise <ver>`. This is deliberate (D-05: first-party
only, no transitive re-resolution) and works because each crate's checked-out
`Cargo.toml` already declares the bumped version, so `--precise` is effectively a
no-op match that just refreshes the lock's `[[package]]` line.

## Consideration (deferred — design change, not a bug)

If a crate's `Cargo.toml` version and the release-please output `<ver>` ever
disagree (e.g. a partial/timing-skewed release), `cargo update --precise <ver>`
errors out and fails the release job. A single `cargo update --workspace` (or
`cargo generate-lockfile`) would re-sync all workspace members directly from their
manifests in one shot, and the existing `git diff --exit-code Cargo.lock` guard
would still validate the result.

## Why deferred

Switching to `--workspace` changes the documented design intent (it re-resolves
the whole tree rather than touching only released first-party crates). That is a
behavioral change to release automation, not a safe in-place simplification — it
should be evaluated against a real release-please cycle, not slipped into a ship
pass. Captured for a future release-automation hardening pass. The current
per-crate approach passes all Phase 53 gates and is correct for the current
manifest/Cargo.toml state.

## Source

Raised during Phase 53 ship-phase simplify review (CodeRabbit/simplify pass).
