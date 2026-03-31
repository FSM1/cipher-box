---
status: diagnosed
trigger: 'Email OTP login fails with "Verification failed" in macOS desktop app (GitHub release build) but works fine in web app'
created: 2026-03-31T00:00:00Z
updated: 2026-03-31T00:30:00Z
---

## Current Focus

hypothesis: The Rust backend's API base URL falls back to http://localhost:3000 in release builds because CIPHERBOX_API_URL and VITE_API_URL are compile-time Vite vars (not runtime env vars). The JS side correctly hits staging API (baked by Vite), but after OTP verify succeeds, invoke('handle_auth_complete') triggers a Rust-side POST to localhost:3000 which fails. Tauri invoke rejects with a string (not Error), so the catch block shows the generic "Verification failed" fallback.
test: Verify that the Rust side indeed has no way to know the API URL at runtime in a release build installed from DMG
expecting: The Rust code at main.rs:82-84 reads env vars at runtime; installed DMG won't have them set
next_action: Confirm the hypothesis by checking if there's any mechanism to embed the API URL at compile time for Rust

## Symptoms

expected: After entering the correct email OTP code, login should succeed and proceed to the vault/dashboard
actual: After entering the OTP and clicking verify, the UI shows "Verification failed" in red text
errors: "Verification failed" displayed in the UI (exact text, screenshot confirmed)
reproduction:

1. Open CipherBox desktop app (v0.34.0, installed from GitHub release DMG: staging-cipher-box-v0.34.0-rc-1)
2. Click email/phone login
3. Enter email address, submit
4. Receive OTP email
5. Enter OTP code
6. Click verify
7. "Verification failed" appears
   started: First time testing GitHub Actions release build. Works in local dev builds and web app.

## Eliminated

## Evidence

- timestamp: 2026-03-31T00:10:00Z
  checked: "Verification failed" string location in codebase
  found: Two locations - apps/desktop/src/main.ts:281 (catch block in OTP verify handler) and apps/web/src/components/auth/EmailLoginForm.tsx:108. The desktop catch block at line 281 shows `err instanceof Error ? err.message : 'Verification failed'` -- the generic fallback means the error was NOT an Error instance.
  implication: Tauri invoke() rejects with a string (not Error) when Rust command returns Err(String), which would trigger the generic fallback message.

- timestamp: 2026-03-31T00:15:00Z
  checked: Desktop auth flow - how API URL is configured in JS vs Rust
  found: JS side uses `import.meta.env.VITE_API_URL` (compile-time, baked by Vite). Rust side at main.rs:82-84 reads `CIPHERBOX_API_URL` then `VITE_API_URL` as runtime env vars, fallback to `http://localhost:3000`.
  implication: In a release build installed from DMG, no runtime env vars exist. Rust backend falls back to localhost:3000.

- timestamp: 2026-03-31T00:18:00Z
  checked: GitHub Actions deploy-staging.yml build-desktop job
  found: Sets `VITE_API_URL: ${{ vars.STAGING_API_URL }}` as env var for tauri-action. This is available at build time for Vite (JS bundle), but at runtime the installed app won't have these env vars.
  implication: JS side correctly targets staging API; Rust side targets localhost:3000 in release builds.

- timestamp: 2026-03-31T00:20:00Z
  checked: Desktop auth flow sequence
  found: loginWithEmailOtp() in auth.ts: (1) fetch to API_BASE/auth/identity/email/verify-otp [JS, correct URL], (2) coreKit.loginWithJWT [Web3Auth network], (3) invoke('handle_auth_complete') -> Rust does POST to state.sdk.api which uses the misconfigured localhost URL.
  implication: Steps 1-2 succeed (JS has correct URL), step 3 fails because Rust hits localhost:3000

## Resolution

root_cause: The Rust backend in the Tauri app reads the API base URL from runtime environment variables (`CIPHERBOX_API_URL` or `VITE_API_URL`) at `apps/desktop/src-tauri/src/main.rs:82-84`, falling back to `http://localhost:3000`. In a release build installed from a GitHub Actions DMG, these runtime env vars don't exist. The JavaScript side (webview) correctly uses the staging API URL because Vite bakes `import.meta.env.VITE_API_URL` at compile time. But after OTP verification succeeds in JS, `invoke('handle_auth_complete')` triggers the Rust side to POST to `http://localhost:3000/auth/login`, which fails with connection refused. Tauri's invoke rejects with a plain string (not an Error object), so the catch block at `apps/desktop/src/main.ts:281` falls through to the generic "Verification failed" message. The split between JS compile-time env vars (Vite) and Rust runtime env vars (std::env::var) is the fundamental mismatch.
fix:
verification:
files_changed: []
