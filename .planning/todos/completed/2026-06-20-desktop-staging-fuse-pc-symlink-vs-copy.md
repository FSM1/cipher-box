---
created: 2026-06-20T05:30
title: desktop-staging-release fuse.pc uses symlink, diverges from ci.yml copy+version-rewrite
area: desktop-ci
phase: pre-existing
files:
  - .github/workflows/desktop-staging-release.yml
  - .github/workflows/ci.yml
---

## Summary

`desktop-staging-release.yml` installs the FUSE-T pkg-config file via
`sudo ln -sf "$FUSE_T_PC" /usr/local/lib/pkgconfig/fuse.pc` (a symlink), whereas
the macOS Cargo job in `ci.yml` uses `sudo cp "$FUSE_T_PC" .../fuse.pc` and then
rewrites `Version:` in place (to `2.9.9`). The staging workflow's symlink path
skips that version rewrite and the existence check ci.yml guards with.

## Why deferred (NOT a Phase 53 change)

This is PRE-EXISTING — Phase 53 only SHA-pinned `uses:` refs and added
`permissions:` blocks in `desktop-staging-release.yml`; it did not touch the
`ln -sf` / `fuse.pc` install line. Out of scope for the release-supply-chain
phase (this is desktop FUSE build-env, not supply-chain hardening). Raised by
greptile (P2) on PR #531; capturing for a future desktop-CI consistency pass.

## Fix direction (future)

Align the staging workflow with ci.yml: `cp` the pc file + rewrite `Version:` +
add the existence guard, so the two macOS FUSE build paths are identical and a
version-string mismatch can't fail the Cargo build only on staging.

## Source

greptile review thread on PR #531 (path desktop-staging-release.yml:29).
