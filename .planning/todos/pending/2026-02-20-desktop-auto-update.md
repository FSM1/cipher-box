---
created: 2026-02-20T01:15
title: Add auto-update to desktop app via Tauri updater plugin
area: desktop
files:
  - apps/desktop/src-tauri/Cargo.toml
  - apps/desktop/src-tauri/tauri.conf.json
---

## Problem

The desktop app has no auto-update mechanism. Users must manually download a new DMG from GitHub Releases and replace the app in `/Applications` each time a new version is released. This is poor UX and means users can run stale versions indefinitely.

## Solution

Integrate `@tauri-apps/plugin-updater` which checks GitHub Releases for newer versions and prompts the user to update.

### Steps

1. Add the updater plugin: `cargo add tauri-plugin-updater` in `src-tauri/`
2. Add JS dependency: `pnpm --filter desktop add @tauri-apps/plugin-updater`
3. Configure the updater in `tauri.conf.json` with the GitHub Releases endpoint
4. Add update check logic — either on app launch or periodically (e.g. every 24h)
5. Show a native dialog or in-webview notification when an update is available
6. Handle the download + restart flow

### Notes

- Tauri updater requires code signing to verify update authenticity — this depends on having an Apple Developer account and signing certs configured in CI
- Without signing, the updater can still work but won't verify the update binary, which is a security concern
- Consider whether to auto-install or just notify (auto-install is better UX but needs signing)
- The `build-desktop` CI job already creates GitHub Releases via `tauri-apps/tauri-action` — the updater plugin reads from these same releases
- Reference: <https://v2.tauri.app/plugin/updater/>
