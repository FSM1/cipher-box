---
phase: 41-package-and-app-versioning-and-release-cycles
plan: 05
subsystem: infra
tags: [release-please, github-actions, tauri, desktop, ci-cd, updater]

# Dependency graph
requires:
  - phase: 41-01
    provides: 15-package release-please-config.json with per-component entries
  - phase: 41-03
    provides: post-merge release-as injection script
provides:
  - Batched release configuration (separate-pull-requests false)
  - Desktop-release workflow triggered by cipherbox-desktop-v* tags
  - Updater JSON published to desktop-specific GitHub Release
  - Latest-flag management ensuring /releases/latest/ resolves to desktop release
affects: [desktop-updates, release-workflow, staging-deploy]

# Tech tracking
tech-stack:
  added: []
  patterns: [latest-flag-management, component-specific-release-tags, cross-platform-desktop-build]

key-files:
  created:
    - .github/workflows/desktop-release.yml
  modified:
    - release-please-config.json
    - .github/workflows/release-please.yml

key-decisions:
  - 'Latest-flag management: un-mark batched RP release, mark desktop release as latest, so /releases/latest/ always points to desktop updater JSON'
  - 'No tauri.conf.json endpoint change needed: /releases/latest/download/latest.json resolves correctly with latest-flag strategy'
  - 'Desktop-release mirrors deploy-staging build matrix (macOS, Windows with WinFsp, Linux ubuntu-22.04) with production environment'

patterns-established:
  - 'Latest-flag management: batched RP releases get --latest=false, desktop-release.yml mark-latest job ensures updater resolution'
  - 'Component-specific workflows: tag-triggered workflows (cipherbox-desktop-v*) for component-specific build and release pipelines'

requirements-completed: [D-31, D-32, D-33]

# Metrics
duration: 3min
completed: 2026-03-31
---

# Phase 41 Plan 05: Batched Releases and Desktop Release Pipeline Summary

**Batched RP releases with desktop-specific tag workflow and latest-flag management for Tauri updater resolution**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-31T21:32:15Z
- **Completed:** 2026-03-31T21:35:19Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Configured Release Please for batched releases with explicit separate-pull-requests: false (D-31)
- Created desktop-release.yml workflow that builds macOS/Windows/Linux on cipherbox-desktop-v* tags with updater JSON (D-33)
- Implemented latest-flag management: RP workflow un-marks batched release, desktop workflow marks its release as latest, ensuring Tauri updater resolves correctly (D-33)
- Added release summary step to RP workflow for visibility into created releases

## Task Commits

Each task was committed atomically:

1. **Task 1: Configure RP for per-component changelogs and batched releases** - `a0d27f4e6` (chore)
2. **Task 2: Add release summary to RP workflow, create desktop-release workflow, update updater endpoint** - `6c35829fe` (ci)

## Files Created/Modified

- `release-please-config.json` - Added separate-pull-requests: false for explicit batched release behavior
- `.github/workflows/release-please.yml` - Added outputs, release summary, and batched release latest-flag removal
- `.github/workflows/desktop-release.yml` - New workflow: 3-platform desktop build pipeline triggered by desktop tags, publishes updater JSON, marks release as latest

## Decisions Made

- **Latest-flag management strategy:** Rather than changing the Tauri updater endpoint URL (which cannot dynamically resolve the "latest desktop" tag), we manage GitHub's "latest" release flag. The RP workflow un-marks the batched root release (`--latest=false`), and the desktop-release workflow marks the desktop release as latest after all platform builds complete. This ensures `/releases/latest/download/latest.json` always resolves to the desktop-specific release containing the updater JSON.
- **No tauri.conf.json change needed:** The existing endpoint `https://github.com/FSM1/cipher-box/releases/latest/download/latest.json` works correctly with the latest-flag management strategy. No URL change required.
- **Desktop-release mirrors deploy-staging build matrix:** Used identical build steps from deploy-staging.yml (FUSE-T on macOS, WinFsp on Windows with registry setup, ubuntu-22.04 with system deps on Linux) but with `production` environment instead of `staging`.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. The `production` GitHub environment must have `PRODUCTION_API_URL`, `TAURI_SIGNING_PRIVATE_KEY`, and other production vars/secrets configured, which is a pre-existing requirement.

## Next Phase Readiness

- All 5 plans in Phase 41 complete
- Release Please configured for per-package versioning with batched releases
- PR preview, post-merge injection, staging deploy, and desktop release workflows all in place
- Ready for production release cycle testing

## Self-Check: PASSED

All created files verified to exist. All commit hashes verified in git log.

---

_Phase: 41-package-and-app-versioning-and-release-cycles_
_Completed: 2026-03-31_
