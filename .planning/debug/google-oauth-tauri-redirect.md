---
status: awaiting_human_verify
trigger: 'Google login fails in Tauri webview with Error 400: invalid_request. redirect_uri=tauri://localhost/google-callback.html rejected by Google OAuth.'
created: 2026-05-25T00:00:00Z
updated: 2026-05-25T00:02:00Z
---

## Current Focus

hypothesis: CONFIRMED - Google OAuth rejects tauri:// scheme redirect_uri
test: Fix applied - temporary localhost HTTP server for OAuth callback
expecting: Google login succeeds with http://localhost:PORT/callback redirect
next_action: Human verification of end-to-end Google login flow + Google Console configuration

## Symptoms

expected: Google login should complete successfully when clicking the login button in the Tauri desktop app
actual: Error 400: invalid_request shown inside the Tauri webview
errors: Error 400: invalid_request, redirect_uri=tauri://localhost/google-callback.html flowName=GeneralOAuthLite
reproduction: Click Google login button in the Tauri desktop app
started: First attempt ever - Google login in Tauri has never worked

## Eliminated

## Evidence

- timestamp: 2026-05-25T00:00:30Z
  checked: apps/desktop/src/auth.ts line 703
  found: redirectUri is built from window.location.origin - in production Tauri builds on macOS this resolves to "tauri://localhost", producing redirect_uri=tauri://localhost/google-callback.html
  implication: This is the direct cause - Google OAuth validates redirect_uri server-side and rejects non-http/https schemes

- timestamp: 2026-05-25T00:00:35Z
  checked: tauri.conf.json build section
  found: devUrl is http://localhost:1420 (works in dev mode), frontendDist is ../dist (production uses tauri:// custom protocol)
  implication: Bug only manifests in production builds; dev mode works because origin is http://localhost:1420

- timestamp: 2026-05-25T00:00:40Z
  checked: OAuth popup mechanism (commands/oauth.rs)
  found: Popup is a Tauri WebviewWindow loading Google OAuth URL as external URL. The redirect happens within this popup webview.
  implication: The popup webview can navigate to any URL but Google validates redirect_uri before granting auth

- timestamp: 2026-05-25T00:00:45Z
  checked: Web app auth flow (apps/web GoogleLoginButton.tsx)
  found: Web app uses Google Identity Services (GIS) One Tap / native button - no redirect_uri needed. Desktop uses manual OAuth2 implicit flow with redirect_uri because GIS doesn't work in Tauri webview
  implication: Desktop needs different OAuth approach than web, which is why it has a redirect_uri at all

- timestamp: 2026-05-25T00:01:00Z
  checked: Google OAuth documentation and RFC 8252
  found: Google allows http://localhost with dynamic ports for native/desktop app clients per RFC 8252. For web app clients, exact redirect URI must be pre-registered.
  implication: Using a fixed set of preferred ports (14200-14202) that can be pre-registered in Google Console is the safest approach

- timestamp: 2026-05-25T00:01:30Z
  checked: Rust compilation (cargo check) and TypeScript compilation (tsc --noEmit)
  found: Both compile cleanly with the fix applied
  implication: Code is syntactically and type-safe correct

## Resolution

root_cause: In production Tauri builds, window.location.origin resolves to "tauri://localhost" (macOS custom protocol). The getGoogleCredential() function in auth.ts uses window.location.origin to construct the OAuth redirect_uri, producing "tauri://localhost/google-callback.html". Google OAuth server-side validation rejects any redirect_uri with a non-http/https scheme, returning Error 400: invalid_request.

fix: Added a temporary localhost HTTP callback server on the Rust side (start_oauth_server command in commands/oauth.rs). The server tries fixed preferred ports (14200, 14201, 14202) and fails fast if none are available (no random port fallback). It serves a callback HTML page (with embedded nonce for POST validation) that extracts the OAuth fragment (#id_token=...) and POSTs it back to the same server, which validates the nonce and emits a port-scoped Tauri event (oauth-callback-{port}) to the main webview. The frontend (auth.ts) now calls start_oauth_server to get the port and event name, uses http://localhost:PORT/callback as redirect_uri, and listens for the scoped Tauri event.

verification: Rust cargo check passes. TypeScript tsc --noEmit passes. Awaiting human verification of end-to-end OAuth flow.

files_changed:

- apps/desktop/src-tauri/src/commands/oauth.rs
- apps/desktop/src-tauri/src/main.rs
- apps/desktop/src/auth.ts
