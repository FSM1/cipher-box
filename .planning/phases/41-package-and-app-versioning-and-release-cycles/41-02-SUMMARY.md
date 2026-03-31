---
phase: 41-package-and-app-versioning-and-release-cycles
plan: 02
subsystem: ci
tags: [github-actions, conventional-commits, release-labels, dependency-cascade, pr-automation]

requires:
  - phase: 41-01
    provides: 'Pre-created release labels and updated RP config with per-app/package entries'
provides:
  - 'PR-time commit analysis with file-to-package mapping via release-please-config.json'
  - 'Auto-applied release:{component}:{type} labels on PRs'
  - 'Dependency cascade detection with JS and Rust dependency graphs'
  - 'CI check blocking merge on non-conventional commits touching versioned packages'
  - 'Release preview PR comment with bump table and cascade details'
affects: [41-03-post-merge-release-as-injection, 41-04-release-please-restructure]

tech-stack:
  added: ['@actions/core', '@actions/github']
  patterns:
    [
      'PR comment marker pattern for idempotent updates',
      'Longest-prefix file-to-package mapping',
      'Hardcoded dependency graph for CI stability',
    ]

key-files:
  created:
    - '.github/scripts/pr-release-preview.js'
    - '.github/workflows/pr-release-preview.yml'
  modified: []

key-decisions:
  - 'Hardcoded JS_DEPS and RUST_DEPS dependency graphs rather than dynamic pnpm/cargo resolution for CI stability and speed'
  - 'Manual label overrides preserved via component-level conflict detection (D-18)'
  - 'API lock group collapses api + api-client TS + api-client Rust into single label prefix'
  - 'Monotonic versioning for web/desktop upgrades patch to minor at label computation time'

patterns-established:
  - 'PR comment marker pattern: <!-- release-preview --> for idempotent comment updates'
  - 'File-to-package mapping via release-please-config.json as single source of truth (D-37)'
  - 'Cascade detection with reverse dependency lookup and iterative propagation'

requirements-completed:
  [D-01, D-15, D-16, D-17, D-18, D-19, D-21, D-22, D-23, D-24, D-37, D-38, D-39, D-40]

duration: 3min
completed: 2026-03-31
---

# Phase 41 Plan 02: PR Release Preview Summary

**PR-time GitHub Action analyzing conventional commits, mapping files to packages, detecting dependency cascades, and auto-applying release labels with CI enforcement**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-31T21:11:57Z
- **Completed:** 2026-03-31T21:15:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created comprehensive PR release analysis script (746 lines) that parses conventional commits, maps changed files to packages via release-please-config.json, detects dependency cascades, and auto-applies release labels
- Created PR release preview workflow triggering on all PR events (open, synchronize, reopened, labeled, unlabeled) with release-please PR exclusion
- Implemented all versioning decisions: API lock group (D-05), monotonic web/desktop versioning (D-08/D-13), cascade detection (D-21-24), auto-exemptions (D-39), and release:none escape hatch

## Task Commits

Each task was committed atomically:

1. **Task 1: Create PR release preview analysis script** - `d2d412d78` (feat)
2. **Task 2: Create PR release preview workflow** - `f6458472d` (ci)

## Files Created/Modified

- `.github/scripts/pr-release-preview.js` - Full PR commit analysis pipeline: conventional commit parsing, file-to-package mapping, API lock group enforcement, cascade detection, label application, PR comment generation, CI check enforcement
- `.github/workflows/pr-release-preview.yml` - Workflow trigger on PR events with correct permissions and release-please PR exclusion

## Decisions Made

- Hardcoded dependency graphs (JS_DEPS, RUST_DEPS) in the script rather than resolving dynamically via pnpm/cargo at CI time -- adds stability and avoids CI failures from dependency resolution issues; requires manual update when dependency graph changes
- Used iterative cascade propagation (while loop) to handle transitive cascades correctly (e.g., crypto -> core -> sdk-core -> sdk)
- Applied monotonic versioning upgrade (patch -> minor) both after direct bump computation AND after cascade detection to ensure consistency
- Re-applied API lock group after cascading to ensure all lock group members stay synchronized

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Known Stubs

None - all functionality is fully implemented.

## Next Phase Readiness

- Release labels and PR analysis are ready for Plan 03 (post-merge release-as injection) to consume
- The script's label output (`release:{component}:{type}`) is the input for Plan 03's version computation
- Dependency graphs in the script match the interfaces defined in Plan 02 context

---

_Phase: 41-package-and-app-versioning-and-release-cycles_
_Completed: 2026-03-31_
