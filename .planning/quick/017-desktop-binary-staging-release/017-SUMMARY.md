---
phase: quick
plan: 017
subsystem: infra
tags: [github-actions, tauri, macos, dmg, staging, ci-cd]

requires:
  - phase: 9.1
    provides: deploy-staging.yml workflow
provides:
  - macOS desktop .dmg build in staging deploy pipeline
  - GitHub pre-release upload for staging tags
affects: [desktop releases, staging testing]

tech-stack:
  added: [tauri-apps/tauri-action@v0]
  patterns: [parallel CI job for desktop build, decoupled from server deploy]

key-files:
  created: []
  modified: [.github/workflows/deploy-staging.yml]

key-decisions:
  - 'build-desktop runs in parallel, not in deploy-vps.needs -- failure cannot block server deploy'
  - 'No code signing -- staging tech demo uses right-click > Open for Gatekeeper bypass'
  - 'macFUSE installed via brew for vendored fuser pkg-config compilation'
  - 'VITE_* env vars baked into binary at build time via tauri-action env'

patterns-established:
  - 'Desktop binary builds are independent from server deploys'

duration: 3min
completed: 2026-02-19
---

# Quick Task 017: Desktop Binary Staging Release Summary

Parallel macOS .dmg build job in deploy-staging.yml using tauri-apps/tauri-action with staging env vars baked in.

## Performance

- **Duration:** 3 min
- **Started:** 2026-02-19T05:00:55Z
- **Completed:** 2026-02-19T05:03:55Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Added `build-desktop` job to deploy-staging.yml that builds macOS .dmg on `macos-latest` runner
- Job runs in parallel with existing build-api, build-tee, build-web jobs
- Desktop build failure cannot block server deployment (not in deploy-vps.needs)
- Staging VITE\_\* env vars (API URL, Web3Auth client ID, Google client ID, environment) baked into binary
- .dmg uploaded as GitHub pre-release artifact for the staging tag

## Task Commits

Each task was committed atomically:

1. **Task 1: Add build-desktop job to deploy-staging.yml** - `8351fd2c4` (feat)

## Files Created/Modified

- `.github/workflows/deploy-staging.yml` - Added build-desktop job with macFUSE install, pnpm/Node setup, crypto build, and tauri-action release

## Decisions Made

- **No code signing:** Staging is a tech demo; releaseBody instructs users to right-click > Open
- **macFUSE via brew:** The vendored fuser crate needs `fuse.pc` pkg-config file at compile time
- **Parallel, not blocking:** Desktop binary is for testers, not a deploy dependency
- **tauri-action@v0:** Handles Rust toolchain setup, Tauri build, and GitHub Release upload in one step

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- First commit attempt failed with lint-staged git index error (transient); retry succeeded.

## User Setup Required

None - no external service configuration required. Existing `staging` GitHub environment vars (`VITE_WEB3AUTH_CLIENT_ID`, `STAGING_API_URL`, `GOOGLE_CLIENT_ID`) are already configured.

## Next Phase Readiness

- Push a `v*-staging*` tag to test the full pipeline
- The .dmg will appear on the GitHub Releases page as a pre-release
- Future: add Windows/Linux builds when those platforms are supported

---

_Quick: 017-desktop-binary-staging-release_
_Completed: 2026-02-19_
