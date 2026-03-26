---
phase: 25-desktop-enhancements
plan: 02
subsystem: desktop
tags: [tauri, updater, auto-update, ed25519, github-releases, tray-menu]

# Dependency graph
requires:
  - phase: 09-desktop-client
    provides: Desktop app with tray icon, FUSE mount, and plugin chain
provides:
  - Tauri updater plugin integration with launch check and manual tray trigger
  - Updater configuration with GitHub Releases endpoint and Ed25519 pubkey placeholder
  - System notification on update availability
affects: [25-desktop-enhancements, ci-release]

# Tech tracking
tech-stack:
  added: [tauri-plugin-updater]
  patterns: [async-launch-check-with-delay, manual-tray-update-check, updater-notification-flow]

key-files:
  created:
    - apps/desktop/src-tauri/src/updater.rs
  modified:
    - apps/desktop/src-tauri/Cargo.toml
    - apps/desktop/src-tauri/tauri.conf.json
    - apps/desktop/src-tauri/capabilities/default.json
    - apps/desktop/src-tauri/src/main.rs
    - apps/desktop/src-tauri/src/tray/mod.rs

key-decisions:
  - 'GitHub endpoint uses FSM1/cipher-box repo path from git remote'
  - 'Ed25519 pubkey left as placeholder (REPLACE_WITH_ED25519_PUBLIC_KEY) for user to fill after key generation'
  - 'Check for Updates menu item placed between logout and quit with separator grouping'

patterns-established:
  - 'Updater module pattern: check_on_launch with 5s delay, manual_check from tray, shared do_update_check async function'

requirements-completed: [DESKTOP-01]

# Metrics
duration: 4min
completed: 2026-03-25
---

# Phase 25 Plan 02: Tauri Updater Integration Summary

**Tauri v2 updater plugin with 5s-delayed launch check, manual tray trigger, and GitHub Releases endpoint for Ed25519-signed updates**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-25T22:46:05Z
- **Completed:** 2026-03-25T22:51:03Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Integrated tauri-plugin-updater into the desktop app with proper plugin registration and capability permissions
- Created updater.rs module with automatic launch check (5s delay), manual check from tray menu, and system notifications for update status
- Added "Check for Updates..." tray menu item with event handler wired to the updater module

## Task Commits

Each task was committed atomically:

1. **Task 1: Add tauri-plugin-updater dependency and configure tauri.conf.json + capabilities** - `0d9040345` (chore)
2. **Task 2: Create updater.rs module, register plugin in main.rs, and add tray menu item** - `29cf3d836` (feat)
3. **Cargo.lock update** - `cb107b0a7` (chore)

## Files Created/Modified

- `apps/desktop/src-tauri/src/updater.rs` - New module: check_on_launch, manual_check, do_update_check with notification integration
- `apps/desktop/src-tauri/Cargo.toml` - Added tauri-plugin-updater = "2" dependency
- `apps/desktop/src-tauri/tauri.conf.json` - Added createUpdaterArtifacts, updater plugin config with pubkey placeholder and GitHub endpoint
- `apps/desktop/src-tauri/capabilities/default.json` - Added updater:default permission
- `apps/desktop/src-tauri/src/main.rs` - Added mod updater, plugin registration, check_on_launch call in setup
- `apps/desktop/src-tauri/src/tray/mod.rs` - Added "Check for Updates..." menu item and check_updates event handler

## Decisions Made

- Used `FSM1/cipher-box` as the GitHub owner/repo for the updater endpoint (derived from git remote)
- Left Ed25519 public key as `REPLACE_WITH_ED25519_PUBLIC_KEY` placeholder -- user must generate keypair and fill in
- Placed "Check for Updates..." between logout and quit with a separator for clean visual grouping
- do_update_check returns Result<bool> to differentiate "no update" from "error" for manual check UX (shows "latest version" vs "check failed")

## Deviations from Plan

None - plan executed exactly as written.

## User Setup Required

**External services require manual configuration.** Per the plan's user_setup section:

- Generate Ed25519 keypair: `npx @tauri-apps/cli signer generate -w ~/.tauri/cipherbox.key`
- Replace `REPLACE_WITH_ED25519_PUBLIC_KEY` in `tauri.conf.json` with the generated public key
- Add `TAURI_SIGNING_PRIVATE_KEY` secret to GitHub repository
- Add `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` secret to GitHub repository

## Issues Encountered

None

## Next Phase Readiness

- Updater integration is complete and compiles cleanly
- CI workflow for building signed desktop bundles (plan 03) will complete the end-to-end update pipeline
- Ed25519 keypair generation and GitHub secret configuration must be done before first signed release

## Self-Check: PASSED

All created files verified on disk. All commit hashes verified in git log.

---

_Phase: 25-desktop-enhancements_
_Completed: 2026-03-25_
