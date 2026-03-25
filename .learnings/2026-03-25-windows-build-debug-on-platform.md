# Windows Build Errors Must Be Debugged on Windows

**Date:** 2026-03-25

## Original Prompt

> In the phase 23 planning docs there is a markdown file related to the debug of the Windows build of the Tauri app. Continue debugging this issue locally until you have both working cargo scripts.

## What I Learned

- CI and build issues in the desktop app should **always be debugged on the target platform**. The Windows `winfsp` feature gate means the entire `platform/windows/` module tree and the desktop app's `fuse/windows/` module are never compiled on macOS or Linux. Errors are invisible until you run `cargo check` on an actual Windows machine.
- Rust's `super::` in nested modules is a common gotcha: if you wrap code in `mod implementation { }` inside a file, `super::` from inside that inner module resolves to the **file-level module**, not the file's parent. Reaching sibling modules requires `super::super::`.
- `pub(crate)` visibility on inner modules breaks cross-crate access. When a library crate exposes types consumed by a separate binary crate (like `cipherbox-fuse` -> `cipherbox-desktop`), those modules must be `pub`, not `pub(crate)`.
- The macOS and Windows mount code in the desktop app are structurally similar but were written at different times. The macOS version had `.map_err(|e| format!("{}", e))` on API calls; the Windows version used bare `.await?`. Always check parity when porting patterns across platform modules.

## What Would Have Helped

- Running `cargo check --workspace --no-default-features --features winfsp` on Windows before merging the Phase 23 extraction work
- A CI matrix that catches these errors before they accumulate (already exists but was failing)
- The debug doc in `.planning/phases/23-rust-sdk-extraction/WINDOWS-BUILD-DEBUG.md` was accurate about the symptoms but the hypothesis about feature resolution was a red herring — the real issue was `super::` path depth

## Key Files

- `crates/fuse/src/platform/windows/mod.rs` — module declarations
- `crates/fuse/src/platform/windows/operations.rs` — WinFsp FileSystemContext impl, delegates to sibling modules
- `crates/fuse/src/platform/windows/read_ops.rs` — read operation handlers
- `crates/fuse/src/platform/windows/write_ops.rs` — write operation handlers
- `crates/fuse/src/platform/windows/dir_ops.rs` — directory operation handlers
- `apps/desktop/src-tauri/src/fuse/windows/mod.rs` — desktop WinFsp mount/unmount
- `apps/desktop/src-tauri/src/fuse/mod.rs` — FUSE bridge re-exports
- `.github/workflows/ci.yml` — CI cargo-windows job definition
