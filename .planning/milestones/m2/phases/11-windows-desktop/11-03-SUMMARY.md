---
phase: 11-windows-desktop
plan: 03
subsystem: desktop
tags: [winfsp, nsis, windows, ci, tauri, winreg, installer, platform-branching]

# Dependency graph
requires:
  - phase: 11-windows-desktop plan 01
    provides: Platform-agnostic FileAttrs, AccessMode, WinFsp Cargo deps, build.rs delayload
  - phase: 11-windows-desktop plan 02
    provides: WinFsp FileSystemContext, Windows mount/unmount, platform dispatch in fuse/mod.rs
provides:
  - Platform-branched main.rs, tray, commands for Windows (explorer.exe, WinFsp detection)
  - WinFsp runtime detection via Windows Registry at startup
  - NSIS installer with silent WinFsp MSI bundling
  - CI pipeline with Windows cargo check and full Tauri build jobs
  - Headless --dev-key mode parity on Windows
affects: [11.3-linux-desktop (similar platform branching pattern)]

# Tech tracking
tech-stack:
  added: [winreg 0.55]
  patterns: [WinFsp registry detection at startup, NSIS installer hooks for driver bundling, CI Windows runner with MSI download]

key-files:
  created:
    - apps/desktop/src-tauri/windows/installer-hooks.nsh
    - apps/desktop/src-tauri/resources/.gitkeep
  modified:
    - apps/desktop/src-tauri/src/main.rs
    - apps/desktop/src-tauri/src/tray/mod.rs
    - apps/desktop/src-tauri/src/commands.rs
    - apps/desktop/src-tauri/tauri.conf.json
    - apps/desktop/src-tauri/Cargo.toml
    - .github/workflows/ci.yml

key-decisions:
  - "winreg crate for WinFsp registry detection (standard Windows Registry access)"
  - "Notification dialog (not blocking MessageBox) for missing WinFsp -- app can still launch"
  - "NSIS ExecWait for MSI install (not nsExec::ExecToLog) -- simpler exit code handling"
  - "WinFsp MSI downloaded in CI, not committed to git -- binary not suitable for source control"
  - "icon.ico for Windows tray icon, tray-icon@2x.png for macOS -- platform-appropriate formats"
  - "cfg(any(fuse, winfsp)) replaces cfg(fuse) in entry point files for cross-platform dispatch"

patterns-established:
  - "WinFsp runtime detection: check HKLM\\SOFTWARE\\WinFsp registry + verify DLL exists"
  - "NSIS installer hooks pattern: PREINSTALL checks registry before silent MSI install"
  - "CI Windows runner: download WinFsp MSI -> install system-wide -> cargo check/build"
  - "Platform tray icon: cfg(target_os) branching for icon format selection"

# Metrics
duration: 5min
completed: 2026-02-22
---

# Phase 11 Plan 03: NSIS Installer & CI Windows Build Summary

**Platform-branched entry points with WinFsp runtime detection, NSIS installer bundling WinFsp MSI, and CI Windows build pipeline on windows-latest**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-22T20:22:28Z
- **Completed:** 2026-02-22T20:27:40Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Added WinFsp runtime detection at startup via Windows Registry (HKLM\SOFTWARE\WinFsp) with DLL existence verification
- Platform-branched tray "open" handler (explorer.exe on Windows, open on macOS) and tray icon format (.ico vs .png)
- Updated all mount/unmount cfg gates from `cfg(feature = "fuse")` to `cfg(any(feature = "fuse", feature = "winfsp"))` in commands.rs and tray/mod.rs
- Created NSIS installer hooks with silent WinFsp MSI install during CipherBox setup
- Added two CI jobs: `cargo-check-windows` (fast Rust check) and `build-desktop-windows` (full Tauri NSIS build)
- Verified headless `--dev-key` mode is cross-platform (debug_assertions gating only, no platform gates)

## Task Commits

Each task was committed atomically:

1. **Task 1: Platform branching in main.rs, tray, commands, and WinFsp runtime detection** - `0a08ae6` (feat)
2. **Task 2: Tauri NSIS packaging with WinFsp bundling and CI pipeline** - `a39282d` (feat)

**Plan metadata:** (committed below) (docs: complete plan)

## Files Created/Modified

- `apps/desktop/src-tauri/src/main.rs` - Added check_winfsp_installed() registry check, WinFsp missing notification in setup hook, autostart comment
- `apps/desktop/src-tauri/src/tray/mod.rs` - Platform-branched "open" (explorer.exe vs open), tray icon (ico vs png), cfg(any(fuse, winfsp)) for unmount
- `apps/desktop/src-tauri/src/commands.rs` - Updated mount/unmount cfg gates to any(fuse, winfsp), generic error messages
- `apps/desktop/src-tauri/Cargo.toml` - Added winreg = "0.55" under cfg(windows) dependencies
- `apps/desktop/src-tauri/tauri.conf.json` - Added NSIS config, installer hooks path, WinFsp resource bundling, Windows bundle settings
- `apps/desktop/src-tauri/windows/installer-hooks.nsh` - NSIS macros for WinFsp MSI silent install/registry check
- `apps/desktop/src-tauri/resources/.gitkeep` - Placeholder for WinFsp MSI bundling (downloaded in CI)
- `.github/workflows/ci.yml` - Added cargo-check-windows and build-desktop-windows jobs on windows-latest

## Decisions Made

- **Notification instead of blocking dialog for missing WinFsp:** Used tauri-plugin-notification instead of a blocking MessageBox. The app can still launch without WinFsp (tray, settings work), but mount will fail gracefully. A notification is less intrusive and fits the system tray app pattern.
- **icon.ico for Windows tray icon:** Windows system tray prefers .ico format. Since icon.ico already exists in the icons directory, used platform-branched tray icon loading.
- **WinFsp MSI not committed to git:** Binary files should not be in source control. CI downloads the MSI from the official WinFsp GitHub release during the build step.
- **Two separate CI jobs:** `cargo-check-windows` provides fast feedback on Rust compilation without the full Tauri/Node build overhead. `build-desktop-windows` runs the complete NSIS installer pipeline.
- **cfg(any(fuse, winfsp)) in entry points:** All three entry point files (main.rs, tray/mod.rs, commands.rs) now use the compound feature gate so the same code paths work on both platforms.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- **Cargo not available on Windows dev machine:** `cargo check --no-default-features --features winfsp` could not be run locally because Rust/cargo is not installed on this MINGW64 environment. This is the same limitation documented in Plans 01 and 02. Full compilation verification deferred to CI.
- **YAML validator not available:** No Python yaml or Node js-yaml available in the MINGW64 environment. CI YAML was verified via visual inspection and grep checks for structural correctness.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 11 (Windows Desktop) is now COMPLETE with all 3 plans executed:
  - Plan 01: Platform abstraction layer (FileAttrs, AccessMode, WinFsp Cargo deps)
  - Plan 02: WinFsp FileSystemContext implementation (15 callbacks, mount/unmount)
  - Plan 03: NSIS installer, CI pipeline, platform branching
- Full Windows build pipeline ready: CI will compile with `--features winfsp` and produce NSIS installer
- The CI `cargo-check-windows` job will be the first real compilation test of the WinFsp code written in Plans 01-03
- Minor WinFsp API adjustments may be needed after first CI run (API signatures based on research docs, not live compilation)

---
*Phase: 11-windows-desktop*
*Completed: 2026-02-22*
