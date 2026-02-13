# Tauri Webview & Web3Auth Lifecycle

**Date:** 2026-02-08

## Original Prompt

> Phase 9 UAT: Test login, logout, re-login flows in the Tauri desktop client.

The login/logout/re-login cycle required 4 iterations to get right. Each fix revealed a new issue in the chain.

## What I Learned

### Window Reuse, Not Destroy+Recreate

- Tauri's `window.destroy()` does not immediately unregister the window label. Calling `WebviewWindowBuilder::new(app, "main", ...)` immediately after destroy causes "a webview with label `main` already exists" error.
- **Solution:** Never destroy the main window. Keep it alive, use `window.eval("location.reload()")` to reset state, then `window.show()` + `window.set_focus()`.
- The `on_new_window` handler (needed for OAuth popups) is set on the window object, not the page. It survives `location.reload()`. This is why reload works but destroy+recreate is fragile.

### OAuth Popup Windows Must Be Cleaned Up

- Web3Auth opens Google/social OAuth in a popup via `window.open()`. Tauri's `on_new_window` handler creates these as `oauth-popup-{N}` windows.
- After auth completes, these popup windows stay open. The user sees a dangling browser window.
- **Solution:** In `handle_auth_complete` (Rust side), iterate all webview windows and `destroy()` any with labels starting with `oauth-popup-`. Also `hide()` the main login window since auth is done.

### Web3Auth clearCache() vs logout({cleanup:true})

- `logout({ cleanup: true })` tears down Web3Auth's internal connectors (OpenLogin adapter, etc.). After this, `connect()` fails with "Wallet connector not ready."
- `clearCache()` clears the cached session without destroying the SDK state. Connectors remain initialized.
- **Rule:** Use `clearCache()` to clear stale sessions during init. Use plain `logout()` (no cleanup flag) when the user explicitly logs out. NEVER use `cleanup: true`.

### Web3Auth Session State Persists in WebView

- After tray logout clears Rust-side state, the webview's Web3Auth instance is still `status: "connected"`. The DOM shows stale content (disabled buttons, success messages).
- `location.reload()` resets both the DOM and the Web3Auth SDK. On page load, `initWeb3Auth()` runs fresh, detects the stale `connected` state, and calls `clearCache()`.

### Tauri App Runs as Background Utility

- `"windows": []` in `tauri.conf.json` — no windows on startup. App is tray-only.
- Windows are created on demand by the tray "Login" handler.
- This means the first login always creates a fresh window with `on_new_window`. Subsequent logins (after logout) reuse the existing hidden window via reload.

## What Would Have Helped

- Knowing that `window.destroy()` has async label cleanup would have saved an iteration.
- Documentation on Web3Auth's `cleanup` flag behavior — the difference between `clearCache()` and `logout({cleanup:true})` is not well documented.
- A state diagram for the login/logout/re-login lifecycle showing window states and Web3Auth states at each transition.

## Key Files

- `apps/desktop/src-tauri/src/tray/mod.rs` — Tray menu, login/logout/quit handlers
- `apps/desktop/src-tauri/src/commands.rs` — `handle_auth_complete` with OAuth popup cleanup
- `apps/desktop/src/auth.ts` — `initWeb3Auth()`, `login()`, `logout()` with clearCache/logout logic
- `apps/desktop/src-tauri/tauri.conf.json` — App config (no default windows)
