---
phase: 25-desktop-enhancements
plan: 03
subsystem: ci
tags: [ci, github-actions, tauri, desktop-build, code-signing, updater]

# Dependency graph
requires:
  - phase: 25-desktop-enhancements
    plan: 02
    provides: tauri-plugin-updater config with createUpdaterArtifacts and updater endpoint
enables:
  - system: updater
    provides: Signed desktop bundles + latest.json manifest for auto-update
---

## What was built

Created `.github/workflows/build-desktop.yml` — a cross-platform CI workflow that builds signed desktop bundles when Release Please publishes a GitHub Release.

## Key decisions

1. **Trigger:** `release: types: [published]` — fires on Release Please publish, attaches artifacts to the same release via `releaseId`
2. **Build matrix:** 4 targets — macOS ARM64, macOS Intel, Ubuntu 22.04, Windows. Windows uses `--no-default-features --features winfsp`
3. **Ed25519 signing:** Generated keypair via `tauri signer generate`, private key + password stored as GitHub secrets, public key embedded in `tauri.conf.json`
4. **FUSE-T for macOS:** Added FUSE-T install step (brew install macfuse alternative) with `PKG_CONFIG_PATH` for the fuse feature to compile
5. **WinFsp for Windows:** Downloads and installs WinFsp MSI silently for the winfsp crate build

## Self-Check: PASSED

- [x] `.github/workflows/build-desktop.yml` exists with correct trigger
- [x] Build matrix covers macOS (aarch64 + x86_64), Linux, Windows
- [x] `tauri-apps/tauri-action@v1` with `releaseId` and `updaterJsonPreferNsis`
- [x] `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` from GitHub Secrets
- [x] Real Ed25519 public key in `tauri.conf.json` (not placeholder)
- [x] GitHub secrets configured in FSM1/cipher-box repo

## Deviations

1. **Added FUSE-T install for macOS** — without it, macOS builds fail (fuse feature needs libfuse headers via pkg-config)
2. **Ed25519 key setup done inline** — non-blocking checkpoint resolved by orchestrator generating keys and setting secrets directly

## key-files

### created
- `.github/workflows/build-desktop.yml`

### modified
- `apps/desktop/src-tauri/tauri.conf.json` (replaced placeholder pubkey with real Ed25519 public key)
