---
phase: 09-desktop-client
plan: 04
subsystem: auth
tags: [tauri, web3auth, keychain, ipc, ecies, jwt, keyring]

# Dependency graph
requires:
  - phase: 09-01
    provides: Tauri v2 scaffold with app structure
  - phase: 09-02
    provides: Rust crypto module (ECIES unwrap, Ed25519, AES-GCM)
  - phase: 09-03
    provides: Desktop auth endpoints (X-Client-Type header, body-based tokens)
provides:
  - Tauri IPC commands for auth flow (handle_auth_complete, try_silent_refresh, logout)
  - macOS Keychain refresh token storage via keyring crate
  - Vault key decryption including root IPNS keypair in AppState
  - Web3Auth SDK initialization in Tauri webview
  - Webview-side login/logout functions with IPC credential passing
affects: [09-05-fuse-filesystem, 09-06-tray-menu, 09-07-background-sync]

# Tech tracking
tech-stack:
  added: ['@web3auth/modal (desktop webview)']
  patterns:
    - 'Tauri IPC command pattern for webview-to-Rust credential passing'
    - 'Keychain-backed session persistence with keyring crate'
    - 'JWT payload decoding (base64url) for user ID extraction'
    - 'ECIES vault key decryption in Rust including root IPNS keypair'

key-files:
  created:
    - apps/desktop/src-tauri/src/commands.rs
    - apps/desktop/src/auth.ts
  modified:
    - apps/desktop/src-tauri/src/main.rs
    - apps/desktop/src/main.ts
    - apps/desktop/package.json
    - pnpm-lock.yaml

key-decisions:
  - 'Web3Auth runs in Tauri webview, NOT system browser -- private key stays in-process'
  - 'Private key passed to Rust via Tauri IPC invoke (secure in-process channel)'
  - 'Silent refresh only refreshes API tokens, not crypto keys -- full Web3Auth login still needed on cold start'
  - 'Dynamic import of @web3auth/modal for graceful handling when SDK not installed'
  - 'JWT sub claim extracted via base64url decode without verification (server already verified)'

patterns-established:
  - 'Tauri command pattern: async fn with State<AppState> parameter, returns Result<T, String>'
  - 'Keychain pattern: store_refresh_token/get_refresh_token/delete_refresh_token with idempotent delete'
  - 'Vault decryption pattern: hex decode -> ECIES unwrap -> store in AppState RwLock'

# Metrics
duration: 3min
completed: 2026-02-08
---

# Phase 9 Plan 4: Auth and Keychain Integration Summary

Tauri IPC auth commands with webview-based Web3Auth, macOS Keychain token persistence, and ECIES vault key decryption including root IPNS keypair.

## Performance

- **Duration:** 3 min
- **Started:** 2026-02-08T01:09:58Z
- **Completed:** 2026-02-08T01:12:33Z
- **Tasks:** 2 (1 pre-completed, 1 executed in this session)
- **Files modified:** 6

## Accomplishments

- Tauri IPC commands for full auth lifecycle: login, silent refresh, logout
- macOS Keychain integration for refresh token persistence across app restarts
- Vault key decryption in Rust: root folder key, root IPNS private key, root IPNS public key, TEE keys
- Web3Auth SDK initialization in Tauri webview with same config as web app
- Webview entry point with silent refresh attempt and login UI flow

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement API client, Keychain auth, and app state** - `0277bc5` (feat)
2. **Task 2: Implement Tauri commands for auth flow with webview-based Web3Auth** - `77bafb7` (feat)

## Files Created/Modified

- `apps/desktop/src-tauri/src/api/client.rs` - HTTP client with X-Client-Type: desktop header and Bearer auth injection
- `apps/desktop/src-tauri/src/api/auth.rs` - Keychain operations (store/get/delete refresh token, user ID tracking)
- `apps/desktop/src-tauri/src/api/types.rs` - Serde types for login, refresh, vault API responses
- `apps/desktop/src-tauri/src/api/mod.rs` - API module declarations
- `apps/desktop/src-tauri/src/state.rs` - AppState with RwLock fields for keys, IPNS data, TEE keys, mount status
- `apps/desktop/src-tauri/src/commands.rs` - Tauri IPC commands: handle_auth_complete, try_silent_refresh, logout + fetch_and_decrypt_vault helper
- `apps/desktop/src-tauri/src/main.rs` - Registered commands module and invoke_handler
- `apps/desktop/src/auth.ts` - Web3Auth SDK initialization and login/logout in Tauri webview
- `apps/desktop/src/main.ts` - App entry point with silent refresh and login UI
- `apps/desktop/package.json` - Added @web3auth/modal dependency

## Decisions Made

- **Web3Auth in webview (not system browser):** Private key stays in-process via Tauri IPC, avoiding insecure URL parameter transit
- **Silent refresh is API-only on cold start:** Private key cannot be restored from Keychain -- user must complete Web3Auth login to get the private key for vault decryption. Silent refresh only refreshes API tokens.
- **JWT decoding without verification:** The server already verified the token; client just needs the `sub` claim for Keychain entry lookup. Manual base64url decode avoids adding a JWT library dependency.
- **Dynamic Web3Auth import:** Uses `await import('@web3auth/modal')` to gracefully handle the case where SDK is not yet installed, with clear error messages.
- **secp256k1 public key derivation via ecies crate:** Reuses ecies crate's SecretKey/PublicKey exports to derive uncompressed 65-byte public key from private key, avoiding additional crypto dependency.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. The @web3auth/modal SDK uses the same VITE_WEB3AUTH_CLIENT_ID environment variable as the web app.

## Next Phase Readiness

- Auth flow complete: Web3Auth login, Keychain persistence, vault key decryption including root IPNS keypair
- AppState holds all decrypted keys in memory, ready for FUSE filesystem operations (plan 09-05)
- Root IPNS private key available for signing folder metadata updates on write operations
- 56 Rust tests pass (52 crypto + 4 command tests)

---

_Phase: 09-desktop-client_
_Completed: 2026-02-08_
