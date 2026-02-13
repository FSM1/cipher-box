---
phase: 09-desktop-client
plan: 01
subsystem: desktop
tags: [tauri, rust, fuse, keyring, macos, desktop-app]

# Dependency graph
requires:
  - phase: 08-tee-integration
    provides: 'TEE key management and republishing infrastructure'
provides:
  - 'Compilable Tauri v2 desktop app scaffold in pnpm workspace'
  - 'Rust Cargo.toml with all dependencies for crypto, FUSE, auth, networking'
  - 'Tauri config: headless (no window), deep-link scheme, ActivationPolicy::Accessory'
  - 'Plugin registrations: deep-link, autostart, shell, notification'
affects: [09-02-crypto-module, 09-03-fuse-filesystem, 09-04-auth-keychain]

# Tech tracking
tech-stack:
  added:
    [
      tauri v2,
      tauri-plugin-deep-link,
      tauri-plugin-autostart,
      tauri-plugin-shell,
      tauri-plugin-notification,
      fuser,
      keyring,
      reqwest,
      aes-gcm,
      ecies,
      ed25519-dalek,
      tokio,
      prost,
      ciborium,
      multihash,
      zeroize,
    ]
  patterns:
    [
      Tauri v2 headless app (no default window),
      ActivationPolicy::Accessory for menu bar only,
      optional FUSE dependency via cargo feature,
    ]

key-files:
  created:
    - apps/desktop/package.json
    - apps/desktop/tsconfig.json
    - apps/desktop/index.html
    - apps/desktop/src/main.ts
    - apps/desktop/src-tauri/Cargo.toml
    - apps/desktop/src-tauri/tauri.conf.json
    - apps/desktop/src-tauri/capabilities/default.json
    - apps/desktop/src-tauri/build.rs
    - apps/desktop/src-tauri/src/main.rs
    - apps/desktop/src-tauri/.gitignore
  modified:
    - pnpm-lock.yaml

key-decisions:
  - 'fuser made optional via cargo feature flag -- requires FUSE-T installed on macOS to compile'
  - 'multihash 0.19 used without identity feature (feature does not exist in this version)'
  - 'bundle.identifier removed from tauri.conf.json (Tauri v2 uses top-level identifier)'
  - 'Placeholder icons generated for cargo check to pass (Tauri requires icons at compile time)'
  - 'Rust toolchain installed (1.93.0) as prerequisite for Tauri compilation'

patterns-established:
  - 'Optional FUSE: fuser behind cargo feature flag for environments without FUSE-T'
  - 'Tauri headless: empty windows array + ActivationPolicy::Accessory for menu bar utility'

# Metrics
duration: 6min
completed: 2026-02-08
---

# Phase 9 Plan 1: Scaffold Tauri v2 Desktop App Summary

> Tauri v2 desktop app shell with all Rust dependencies, headless config (no window), and plugin registrations for deep-link, autostart, shell, and notification

## Performance

- **Duration:** 6 min
- **Started:** 2026-02-07T23:16:00Z
- **Completed:** 2026-02-07T23:22:06Z
- **Tasks:** 1
- **Files modified:** 17

## Accomplishments

- Scaffolded `apps/desktop` as a proper pnpm workspace member (`@cipherbox/desktop`)
- Created Cargo.toml with all Rust dependencies needed for future plans (crypto, FUSE, auth, networking, IPNS)
- Configured Tauri v2 for headless operation: no default window, deep-link scheme "cipherbox", menu bar only via ActivationPolicy::Accessory
- Registered all required plugins: deep-link, autostart (LaunchAgent), shell, notification
- `cargo check` passes cleanly with all dependencies resolved

## Task Commits

Each task was committed atomically:

1. **Task 1: Scaffold Tauri v2 app in monorepo** - `83a8fe9` (feat)

## Files Created/Modified

- `apps/desktop/package.json` - Desktop app package with Tauri CLI and JS API deps
- `apps/desktop/tsconfig.json` - TypeScript config extending monorepo base
- `apps/desktop/index.html` - Minimal HTML shell for Tauri webview
- `apps/desktop/src/main.ts` - Webview entry point (expanded in plan 09-04)
- `apps/desktop/src-tauri/Cargo.toml` - Rust dependencies with optional fuser
- `apps/desktop/src-tauri/tauri.conf.json` - Tauri config: headless, deep-link, CSP disabled
- `apps/desktop/src-tauri/capabilities/default.json` - Permission grants for plugins
- `apps/desktop/src-tauri/build.rs` - Standard Tauri build script
- `apps/desktop/src-tauri/src/main.rs` - App entry: plugin registration, ActivationPolicy::Accessory
- `apps/desktop/src-tauri/.gitignore` - Ignore target/ and gen/ directories
- `apps/desktop/src-tauri/icons/` - Placeholder icons for compilation
- `pnpm-lock.yaml` - Updated with desktop app dependencies

## Decisions Made

1. **fuser made optional via cargo feature flag** - fuser 0.16 requires FUSE-T (or macFUSE) installed to compile on macOS. Since this scaffold plan should compile without FUSE-T, fuser is behind `[features] fuse = ["dep:fuser"]`. Plan 09-03 will enable it when FUSE-T is installed.

2. **multihash 0.19 without identity feature** - The plan specified `features = ["identity"]` but multihash 0.19 does not have this feature. The identity hash code (0x00) is a constant in the crate, not a feature gate. Used `multihash = "0.19"` without features.

3. **bundle.identifier removed from tauri.conf.json** - Tauri v2 uses a top-level `identifier` field, not `bundle.identifier`. The build script errored on the unknown field.

4. **Placeholder icons required for cargo check** - Tauri's `generate_context!()` macro validates icon paths at compile time. Created minimal PNG/ICO/ICNS placeholder files.

5. **Rust toolchain installed (1.93.0)** - Rust was not previously installed on this machine. Installed via rustup as a prerequisite.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] multihash "identity" feature does not exist in v0.19**

- **Found during:** Task 1 (Cargo.toml creation)
- **Issue:** Plan specified `multihash = { version = "0.19", features = ["identity"] }` but this feature does not exist in multihash 0.19.x
- **Fix:** Changed to `multihash = "0.19"` without features. Identity hash code is available as a constant.
- **Files modified:** apps/desktop/src-tauri/Cargo.toml
- **Verification:** `cargo check` passes
- **Committed in:** 83a8fe9

**2. [Rule 3 - Blocking] fuser cannot compile on macOS without FUSE-T installed**

- **Found during:** Task 1 (cargo check)
- **Issue:** `fuser` 0.16 build script panics: "Building without libfuse is only supported on Linux"
- **Fix:** Made fuser optional via cargo feature: `fuser = { ..., optional = true }` with `[features] fuse = ["dep:fuser"]`
- **Files modified:** apps/desktop/src-tauri/Cargo.toml
- **Verification:** `cargo check` passes without FUSE-T
- **Committed in:** 83a8fe9

**3. [Rule 1 - Bug] bundle.identifier is not a valid Tauri v2 field**

- **Found during:** Task 1 (cargo check)
- **Issue:** Tauri v2 moved `identifier` to top-level config; `bundle.identifier` causes build error
- **Fix:** Removed `identifier` from `bundle` section (top-level `identifier` already set)
- **Files modified:** apps/desktop/src-tauri/tauri.conf.json
- **Verification:** `cargo check` passes, JSON valid
- **Committed in:** 83a8fe9

**4. [Rule 3 - Blocking] Tauri generate_context!() requires icon files at compile time**

- **Found during:** Task 1 (cargo check)
- **Issue:** Macro panicked: "failed to open icon icons/32x32.png: No such file or directory"
- **Fix:** Generated minimal placeholder PNGs (32x32, 128x128, 256x256), ICO, and ICNS via Python and macOS sips
- **Files modified:** apps/desktop/src-tauri/icons/
- **Verification:** `cargo check` passes
- **Committed in:** 83a8fe9

**5. [Rule 3 - Blocking] Rust toolchain not installed**

- **Found during:** Task 1 (before cargo check)
- **Issue:** `rustc` and `cargo` not found on system
- **Fix:** Installed Rust 1.93.0 via rustup (`curl https://sh.rustup.rs | sh -s -- -y`)
- **Verification:** `rustc --version` returns 1.93.0
- **Committed in:** N/A (system prerequisite)

---

**Total deviations:** 5 auto-fixed (2 bugs, 3 blocking)
**Impact on plan:** All fixes necessary for compilation. No scope creep. The fuser optional feature is the most significant deviation -- it enables the scaffold to compile without FUSE-T installed, which is the correct approach since FUSE setup belongs in plan 09-03.

## Issues Encountered

None beyond the auto-fixed deviations above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Tauri app scaffold is complete and compiles cleanly
- All Rust dependencies for crypto, networking, and IPNS are resolved
- Ready for plan 09-02 (Rust crypto module with cross-language test vectors)
- FUSE-T must be installed before plan 09-03 (FUSE filesystem) to enable the `fuse` cargo feature
- Icons should be replaced with proper CipherBox branding before distribution

---

_Phase: 09-desktop-client_
_Completed: 2026-02-08_
