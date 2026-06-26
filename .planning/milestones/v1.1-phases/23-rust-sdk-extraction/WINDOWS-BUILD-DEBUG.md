# Windows Build Debug Session Notes

## Problem

`cargo check --workspace --no-default-features --features winfsp` fails on Windows CI.
The CI job is `Cargo Check & Test (Windows)` in `.github/workflows/ci.yml`.

## Current State (commit 62557b0e4)

The fuser/fuse-gated crate-level module errors are **resolved**. The remaining errors
are exclusively from `crates/fuse/src/platform/windows/` modules:

```
error[E0433]: could not find `operations` in `super`  --> platform/windows/read_ops.rs:19
error[E0433]: could not find `operations` in `super`  --> platform/windows/write_ops.rs:20
error[E0433]: could not find `operations` in `super`  --> platform/windows/dir_ops.rs:13
error[E0433]: could not find `read_ops` in `super`    --> platform/windows/operations.rs:390+
error[E0433]: could not find `write_ops` in `super`   --> platform/windows/operations.rs:427+
```

## What Was Fixed (working)

1. **Vendored fuser compiles as empty crate on Windows** — `lib.rs` uses
   `#[cfg(unix)] include!("lib_impl.rs")` so fuser is a no-op on Windows.
   `build.rs` delegates to `unix_build()` on Unix, returns immediately otherwise.

2. **Workspace cipherbox-fuse dependency has `default-features = false`** —
   Root `Cargo.toml` line 50. This prevents the `fuse` feature (which pulls in
   fuser imports) from being activated through the desktop dependency chain.

3. **Desktop cipherbox-fuse dep also has `default-features = false`** —
   `apps/desktop/src-tauri/Cargo.toml` line 16.

4. **Crate-level fuse modules no longer compile on Windows** — `operations.rs`,
   `read_ops.rs`, `write_ops.rs`, `dir_ops.rs` are behind `#[cfg(feature = "fuse")]`
   and the `fuse` feature is now correctly disabled.

## Remaining Issue

The `platform/windows/` modules compile (gated on `#[cfg(feature = "winfsp")]`),
but their `super::` references fail to resolve sibling modules:

- `platform/windows/read_ops.rs:19` — `use super::operations::implementation::{...}`
- `platform/windows/write_ops.rs:20` — same pattern
- `platform/windows/dir_ops.rs:13` — same pattern
- `platform/windows/operations.rs:390+` — `super::read_ops::implementation::*`, `super::write_ops::implementation::*`

All sibling modules are declared in `platform/windows/mod.rs` with `#[cfg(feature = "winfsp")]`.
The `winfsp` feature IS being passed (`--features winfsp`).

## Hypothesis

The `winfsp` feature might not be reaching `cipherbox-fuse` on Windows. Possible causes:

1. **Cargo feature resolution with `--workspace --features`**: The `--features winfsp`
   flag may only apply to packages that are command-line targets, not transitive deps.
   With `--workspace`, all members are targets, but feature unification may behave
   differently on Windows.

2. **The `winfsp` dep itself** (the WinFsp Rust crate `winfsp = "0.12"`) may fail to
   resolve on CI, causing the entire feature to be silently disabled.

## How to Debug on Windows

```powershell
# 1. Check if winfsp feature is active
cargo tree -p cipherbox-fuse --no-default-features --features winfsp -e features 2>&1 | Select-String "winfsp"

# 2. Check feature resolution for the full workspace
cargo check --workspace --no-default-features --features winfsp 2>&1

# 3. Try checking just the fuse crate
cargo check -p cipherbox-fuse --no-default-features --features winfsp 2>&1

# 4. Check if WinFsp SDK is installed (required by winfsp crate)
# The winfsp crate needs WinFsp installed at C:\Program Files (x86)\WinFsp\
# CI installs it via: choco install winfsp -y

# 5. Verbose feature resolution
cargo check --workspace --no-default-features --features winfsp -vv 2>&1 | Select-String "feature|winfsp"
```

## Key Files

| File                                          | Role                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------ |
| `Cargo.toml:50`                               | Workspace dep: `cipherbox-fuse = { path = "crates/fuse", default-features = false }` |
| `crates/fuse/Cargo.toml`                      | Feature defs: `fuse = ["dep:fuser", ...]`, `winfsp = ["dep:winfsp", ...]`            |
| `crates/fuse/src/lib.rs:15-22`                | `#[cfg(feature = "fuse")]` gates on crate-level modules                              |
| `crates/fuse/src/platform/mod.rs:12-13`       | `#[cfg(feature = "winfsp")] pub mod windows`                                         |
| `crates/fuse/src/platform/windows/mod.rs`     | Module declarations all `#[cfg(feature = "winfsp")]`                                 |
| `apps/desktop/src-tauri/Cargo.toml:8-9`       | Desktop feature defs forwarding to cipherbox-fuse                                    |
| `.github/workflows/ci.yml` cargo-windows step | `cargo check --workspace --no-default-features --features winfsp`                    |

## Resolution (2026-03-25)

All errors resolved. Both CI cargo scripts pass locally on Windows:

- `cargo check --workspace --no-default-features --features winfsp`
- `cargo test --workspace --no-default-features --features winfsp`

### Root Causes

1. **`super::` path depth in nested modules (20 E0433 errors):** Each Windows module
   wraps code in `pub(crate) mod implementation { }`. From inside `implementation`,
   `super::` resolves to the file-level module (e.g., `operations`), NOT the parent
   `windows` module. Cross-module references like `super::read_ops` from inside
   `operations::implementation` failed because `read_ops` is a sibling of `operations`
   in the `windows` module, not a child of `operations`.
   **Fix:** Changed all cross-module refs from `super::` to `super::super::`.

2. **`pub(crate)` visibility (1 E0603 error):** The `implementation` submodules were
   `pub(crate)`, invisible to the separate `cipherbox-desktop` crate which imports
   `cipherbox_fuse::platform::windows::operations::implementation::WinFspContext`.
   **Fix:** Changed to `pub mod implementation`.

3. **Missing `cache` re-export (1 E0432 error):** Desktop's `fuse/windows/mod.rs`
   imported `crate::fuse::cache`, but the bridge `fuse/mod.rs` didn't re-export it.
   **Fix:** Added `pub use cipherbox_fuse::cache;`.

4. **`ApiError` not convertible to `String` via `?` (6 E0277 errors):** Async blocks
   in `fuse/windows/mod.rs` used `.await?` on API calls returning `Result<_, ApiError>`
   in a `Result<_, String>` context. The macOS version had `.map_err()` but Windows didn't.
   **Fix:** Added `.map_err(|e| e.to_string())` to all 6 call sites.

### Key Insight

These errors could only be diagnosed on Windows — the `winfsp` feature gate and WinFsp
SDK dependency mean the code is never compiled on macOS/Linux CI.

## CI Run References

- Latest failure: https://github.com/FSM1/cipher-box/actions/runs/23512770684
- Previous (fuser errors fixed but windows modules fail): run 23511827305
- Original (fuser build.rs panic): run 23495322643
