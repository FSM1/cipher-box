---
phase: 23-rust-sdk-extraction
plan: 07
subsystem: infra
tags: [ci, github-actions, release-please, cargo-workspace, test-vectors, parity-gate]

# Dependency graph
requires:
  - phase: 23-rust-sdk-extraction (plans 01-06)
    provides: Cargo workspace with 5 crates and shared test vectors
provides:
  - CI workspace-level cargo builds on all three platforms
  - Cross-language vector parity gate in CI
  - Release Please configuration for all 5 Rust crates
  - Parity check script for vector file validation
affects: [future-rust-crate-releases, desktop-ci, cross-language-testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    [workspace-level-cargo-commands, cross-language-parity-gate, multi-platform-workspace-ci]

key-files:
  created:
    - scripts/check-vector-parity.sh
  modified:
    - .github/workflows/ci.yml
    - .github/workflows/desktop-e2e.yml
    - release-please-config.json
    - .release-please-manifest.json

key-decisions:
  - 'Used needs.changes.outputs.src instead of nonexistent packages output for parity gate condition'
  - 'Included all 9 existing vector files in parity script (not just the 5 in the plan) for completeness'
  - 'Updated desktop-e2e.yml binary paths to target/debug/ to match workspace build output'
  - 'Removed stale apps/desktop/src-tauri/Cargo.lock from path filters since workspace uses root lockfile'

patterns-established:
  - 'Workspace CI pattern: cargo check/test --workspace --no-default-features --features <platform>'
  - 'Parity gate pattern: run both language test suites then validate shared vectors via meta-check script'

requirements-completed: [RSDK-09, RSDK-10]

# Metrics
duration: 7min
completed: 2026-03-24
---

# Phase 23 Plan 07: CI & Release Please Summary

**Workspace-level cargo CI builds on all platforms, cross-language vector parity gate, and Release Please config for 5 Rust crates**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-24T11:09:39Z
- **Completed:** 2026-03-24T11:17:12Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Migrated all three platform CI jobs (Windows, macOS, Linux) from manifest-path desktop builds to workspace-level cargo commands
- Added cross-language vector parity gate as a new CI job that validates Rust and TypeScript produce identical results for shared test vectors
- Configured Release Please for all 5 Rust crates with independent versioning, include-component-in-tag, and 0.1.0 initial versions
- Updated cache keys and paths to reference root Cargo.lock and workspace target directory
- Updated desktop-e2e.yml to use `cargo build -p cipherbox-desktop` instead of manifest-path

## Task Commits

Each task was committed atomically:

1. **Task 1: Update CI workflows for workspace builds and parity gate** - `7979f3f1f` (ci)
2. **Task 2: Configure Release Please for Rust crates** - `db745845c` (chore)

## Files Created/Modified

- `scripts/check-vector-parity.sh` - Meta-check script validating all 9 vector files exist, are valid JSON, and Rust tests reference them
- `.github/workflows/ci.yml` - Workspace cargo commands on all platforms, updated cache/filters, added vector-parity job
- `.github/workflows/desktop-e2e.yml` - Workspace build command, updated cache/paths, binary path to workspace target
- `release-please-config.json` - 5 Rust crate entries with release-type: rust, extra-files for version propagation
- `.release-please-manifest.json` - Initial 0.1.0 versions for all 5 crates

## Decisions Made

- Used `needs.changes.outputs.src` instead of nonexistent `packages` output in the vector-parity job condition (the plan referenced `packages` but the changes job only exposes `src` and `desktop`)
- Included all 9 existing vector files in the parity script rather than only the 5 listed in the plan -- the additional 4 files (ecies.json, folder-metadata.json, ipns-record.json, bin-metadata.json) were created by earlier plans and should be validated
- Updated desktop-e2e.yml binary paths from `apps/desktop/src-tauri/target/debug/` to `target/debug/` to match workspace build output location
- Removed `apps/desktop/src-tauri/Cargo.lock` from path filters in both CI and desktop-e2e workflows since the workspace now uses the root Cargo.lock

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed nonexistent `packages` output reference in parity gate**

- **Found during:** Task 1 (vector-parity job creation)
- **Issue:** Plan specified `needs.changes.outputs.packages == 'true'` but the changes job only exposes `src` and `desktop` outputs
- **Fix:** Changed to `needs.changes.outputs.src == 'true'` which covers packages/\*\* changes
- **Files modified:** .github/workflows/ci.yml
- **Verification:** YAML validates correctly
- **Committed in:** 7979f3f1f

**2. [Rule 2 - Missing Critical] Added all 9 vector files to parity script**

- **Found during:** Task 1 (parity script creation)
- **Issue:** Plan only listed 5 vector files but 9 exist on disk (ecies.json, folder-metadata.json, ipns-record.json, bin-metadata.json were missing from the plan)
- **Fix:** Added all 9 vector files to the EXPECTED_VECTORS array
- **Files modified:** scripts/check-vector-parity.sh
- **Verification:** Script runs successfully and validates all 9 files
- **Committed in:** 7979f3f1f

**3. [Rule 3 - Blocking] Updated desktop-e2e.yml binary paths for workspace builds**

- **Found during:** Task 1 (desktop-e2e.yml update)
- **Issue:** Changing from manifest-path build to workspace `cargo build -p cipherbox-desktop` moves output from `apps/desktop/src-tauri/target/debug/` to `target/debug/`; 4 references to the old path would break E2E tests
- **Fix:** Updated all 4 binary path references in desktop-e2e.yml to use `target/debug/`
- **Files modified:** .github/workflows/desktop-e2e.yml
- **Verification:** All path references consistent
- **Committed in:** 7979f3f1f

---

**Total deviations:** 3 auto-fixed (1 bug, 1 missing critical, 1 blocking)
**Impact on plan:** All auto-fixes necessary for correctness. No scope creep.

## Issues Encountered

None - plan executed smoothly after auto-fixes were applied.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 23 is now complete (all 7 plans executed)
- CI fully supports workspace-level Rust builds and cross-language parity verification
- Release Please is configured for independent Rust crate versioning
- Desktop E2E tests use workspace build paths

## Self-Check: PASSED

All files verified present. All commits verified in git log.

---

_Phase: 23-rust-sdk-extraction_
_Completed: 2026-03-24_
