# Release Please Subdir Extra Files And Desktop Cascades

**Date:** 2026-04-02

## Original Prompt

> You jsut created a PR containing an API fix <https://github.com/FSM1/cipher-box/pull/445>
>
> The release preview manifest correctly updates the dependent rust crates, but for some reason the actual desktop app is not bumped, even though one or more of its dependencies have been updated.
>
> Why?
>
> ok please apply both of these fixes now
>
> Are these incurrect `extra files` patterns present in any of the other release please configs? Can you also log a learning according to the readme ?

## What I Learned

- In this repo, `release-please-config.json` is the only Release Please config file, and `apps/desktop` is the only component currently using `extra-files`.
- For manifest components in subdirectories, `extra-files` paths must be relative to the component path, not the repo root. For `apps/desktop`, `src-tauri/tauri.conf.json` works, while `apps/desktop/src-tauri/tauri.conf.json` does not.
- The desktop release preview logic is partly custom. Rust crate bumps do not automatically cascade into `apps/desktop` unless that dependency edge is explicitly modeled in `.github/scripts/pr-release-preview.js`.
- The desktop package can appear released while the actual Tauri app version lags if `package.json` is bumped but the Tauri `Cargo.toml` and `tauri.conf.json` are not updated.

## What Would Have Helped

- Checking `release-please-config.json` and `.github/scripts/pr-release-preview.js` first instead of assuming Release Please alone handled all dependency propagation.
- Verifying whether `extra-files` are repo-relative or component-relative before trusting the manifest config.
- Comparing `apps/desktop/package.json` against `apps/desktop/src-tauri/Cargo.toml` and `apps/desktop/src-tauri/tauri.conf.json` earlier.

## Key Files

- `release-please-config.json`
- `.github/scripts/pr-release-preview.js`
- `apps/desktop/package.json`
- `apps/desktop/src-tauri/Cargo.toml`
- `apps/desktop/src-tauri/tauri.conf.json`
