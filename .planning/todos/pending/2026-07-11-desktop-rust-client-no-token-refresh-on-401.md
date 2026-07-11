---
created: 2026-07-11T00:00:00.000Z
title: Desktop Rust background client does not refresh its access token, 401-locks after 15m
area: desktop-auth
severity: medium
source: Found while root-causing the macOS Desktop-E2E hang on PR #607. The E2E symptom is fixed via a longer ACCESS_TOKEN_TTL for the test stack, but the underlying product behavior is unaddressed.
files:
  - crates/api-client/src/client.rs
  - crates/api-client/src/auth.rs
  - apps/desktop/src-tauri/src/commands/auth.rs
  - apps/desktop/src/main.ts
resolves_phase: null
---

## Problem

The desktop app mints a 15-minute access token at login/session-restore
(`try_silent_refresh` in `auth.rs`, once) and never proactively refreshes it.
The Rust `api-client` has no auto-refresh-on-401 interceptor — background
threads (sync poll, metadata refresh, scope-exit rotation publish) that receive
a `401 Unauthorized` after the token expires simply log a WARN and fail, with no
retry-after-refresh. There is no periodic background refresh timer on the Rust
side, and the webview's only refresh is the one-shot startup `try_silent_refresh`.

Consequence: a real desktop session doing continuous background work for >15
minutes without a UI action that re-establishes tokens can 401-lock its
background sync/publish plane until the app is restarted. Observed directly in
CI as a total API lockout at exactly login+15m (macOS Desktop-E2E run
29160578737): every IPNS resolve/publish returned 401 for the rest of the run.

## Why the E2E fix does not close this

The E2E hang was unblocked by making `ACCESS_TOKEN_TTL` env-configurable
(default stays `15m`) and setting it to `2h` for the desktop-e2e stack — the
test-login binary intentionally skips Keychain refresh-token storage
(`auth.rs:111`, "skip in test-login mode to avoid popups"), so it *cannot*
silently refresh and needs a long-lived token instead. That is a test-harness
accommodation, not a product fix.

## Fix (proposed, not implemented)

Give the long-running Rust client a way to keep its access token fresh:

- Add an auto-refresh path in `api-client`: on a `401`, attempt one
  `POST /auth/refresh` with the stored refresh token, swap in the new access
  token, and retry the original request once (guard against refresh loops).
- OR spawn a proactive background refresh timer in the Tauri app (~every 10 min,
  under the 15m TTL) that calls the existing refresh command.

Either requires the refresh token to be available to the background client; the
test-login path would still need the long-TTL accommodation (or a test-only
refresh-token store) since it deliberately avoids Keychain.
