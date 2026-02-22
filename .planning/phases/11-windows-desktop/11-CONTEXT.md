# Phase 11: Windows Desktop - Context

**Gathered:** 2026-02-22
**Status:** Ready for planning

<domain>
## Phase Boundary

CipherBox desktop app runs on Windows with native filesystem integration via WinFsp, full feature parity with macOS (system tray, credential storage, background sync, auto-start, headless mode). Linux desktop is deferred to Phase 11.3.

</domain>

<decisions>
## Implementation Decisions

### Scope split
- Phase 11 is now **Windows-only** (renamed from "Cross-Platform Desktop")
- Phase 11.3 added to roadmap for Linux Desktop (separate phase)
- Roadmap phase name updated to "Windows Desktop"

### Windows filesystem technology
- **WinFsp** (FUSE for Windows) via the `winfsp` Rust crate (v0.12.4, actively maintained by SnowflakePowered)
- ProjFS rejected: built-in Windows API but Rust crate is immature (5 GitHub stars, no releases, minimal docs)
- WinFsp chosen for: mature Rust bindings, FUSE-compatible API enabling maximum code reuse with macOS FUSE layer, production-grade ecosystem
- WinFsp driver bundled inside the CipherBox NSIS installer (silent install during setup, user doesn't need to install separately)

### Mount point
- Folder mount at `C:\Users\<user>\CipherBox` (not a mapped drive letter)
- Matches macOS `~/CipherBox` pattern for cross-platform consistency
- Folder mount chosen specifically for testability: easy to clear stale data between process runs, no drive letter allocation/deallocation complexity, compatible with headless test mode

### Headless & test mode
- Full parity with macOS: `--dev-key`, `--headless` CLI flags, `test-login` endpoint
- Same E2E test harness infrastructure reused from macOS desktop
- Folder mount simplifies test cleanup (rm mount point between runs)

### Platform feature parity
- All macOS features ship on day one: WinFsp mount, system tray, Windows Credential Manager (via `keyring` crate), background sync, auto-start, headless mode
- No feature gaps between macOS and Windows desktop
- Auth methods: email + Google only (wallet SIWE not applicable — Tauri webview doesn't support browser wallet extensions)

### Installer & packaging
- NSIS (.exe) installer via Tauri's built-in NSIS support
- WinFsp driver bundled in the NSIS installer
- Code-signed build (eliminates Windows Defender SmartScreen warnings)

### CI/CD & build matrix
- Native Windows runner on GitHub Actions (`windows-latest`)
- Cross-compilation rejected: WinFsp native linking may not work cross-compiled
- Adds Windows to existing CI matrix alongside macOS

### Claude's Discretion
- WinFsp FUSE API adapter architecture (how to abstract macOS FUSE vs WinFsp differences)
- Windows-specific system tray implementation details
- Auto-start mechanism (registry vs startup folder vs Task Scheduler)
- Code signing certificate provider choice
- Tauri Windows-specific configuration

</decisions>

<specifics>
## Specific Ideas

- Mount point chosen for testability: "the route that will facilitate simplest headless testing should probably be chosen — mounting a folder in the user dir lets you easily clear stale data between process runs"
- WinFsp driver should be invisible to the user — bundled and silently installed

</specifics>

<deferred>
## Deferred Ideas

- Linux Desktop — Phase 11.3 (separate phase added to roadmap)
- ProjFS as future alternative if Rust ecosystem matures — revisit for Linux/Windows parity

</deferred>

---

*Phase: 11-windows-desktop*
*Context gathered: 2026-02-22*
