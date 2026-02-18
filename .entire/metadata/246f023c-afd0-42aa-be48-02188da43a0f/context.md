# Session Context

**Session ID:** 246f023c-afd0-42aa-be48-02188da43a0f

**Commit Message:** Implement the following plan:

# Plan: Wire Up Desktop Test-Mode for Aut

## Prompt

Implement the following plan:

# Plan: Wire Up Desktop Test-Mode for Automated E2E Testing

## Context

The desktop app's `--dev-key` headless auth mode is broken due to three bugs in `handleDevKeyAuth`. The staging API also blocks test-login because `NODE_ENV=production`. Fixing the outstanding Phase 11.1 bugs will be much easier once automated test-mode works, so we need to unblock this first.

**Bugs in `apps/desktop/src/main.ts:533-561`:**
1. References `data.idToken` — but `POST /auth/test-login` returns `accessToken`, not `idToken`
2. Passes CLI `devKeyHex` as private key — but test-login created the user with its own deterministic keypair (mismatch = vault ECIES failure)
3. Calls `handle_auth_complete` which POSTs to `/auth/login` expecting a CipherBox identity JWT — but test-login returns a plain API access token

## Two-Track Approach

### Track A: Staging infra (separate PR off `main` — merge + deploy first)

One small PR that enables test-login on the staging API.

**File:** `.github/workflows/deploy-staging.yml` (line 138)
- Change `NODE_ENV=production` → `NODE_ENV=staging`
- Add `TEST_LOGIN_SECRET=${{ secrets.STAGING_TEST_LOGIN_SECRET }}`

**Manual step:** Add `STAGING_TEST_LOGIN_SECRET` secret to GitHub staging environment.

### Track B: Desktop test-mode fixes (on current `feat/phase-11.1-01` branch)

All desktop-side changes to make `--dev-key` mode actually work.

#### B1. Extract shared post-auth helper in Rust

**File:** `apps/desktop/src-tauri/src/commands.rs`

Extract lines 76-228 of `handle_auth_complete` into a shared helper:

```rust
async fn complete_auth_setup(
    app: &tauri::AppHandle,
    state: &AppState,
    access_token: String,
    refresh_token: String,
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    is_new_user: bool,
) -> Result<(), String>
```

Refactor `handle_auth_complete` to call it after its `/auth/login` POST.

#### B2. Add `handle_test_login_complete` Rust command

**File:** `apps/desktop/src-tauri/src/commands.rs`

New command gated by `#[cfg(debug_assertions)]`:
- Accepts `{ access_token, refresh_token, private_key_hex, is_new_user }`
- Derives public key, calls `complete_auth_setup()` directly — **skips** `/auth/login`

#### B3. Register new command in Tauri builder

**File:** `apps/desktop/src-tauri/src/main.rs`

cfg-gated handler lists (since `generate_handler!` doesn't support inline `#[cfg]`):

```rust
#[cfg(debug_assertions)]
let handler = tauri::generate_handler![/* ...existing + handle_test_login_complete */];
#[cfg(not(debug_assertions))]
let handler = tauri::generate_handler![/* ...existing only */];
```

#### B4. Fix `handleDevKeyAuth` in TypeScript

**File:** `apps/desktop/src/main.ts` (lines 533-561)

- Use `data.accessToken` (not `data.idToken`)
- Use `data.privateKeyHex` from test-login response (matches the user record)
- Call `invoke('handle_test_login_complete', ...)` instead of `handle_auth_complete`
- Throw clear error when `VITE_TEST_LOGIN_SECRET` is missing

#### B5. Add test-login secret to desktop `.env`

**File:** `apps/desktop/.env`

Add: `VITE_TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production`

#### B6. Update desktop CLAUDE.md docs

**File:** `apps/desktop/CLAUDE.md` — update dev-key mode section to reflect fixed behavior.

## Execution Order

1. **Track A first** — create branch, make the one-file change, open PR, merge
2. User adds `STAGING_TEST_LOGIN_SECRET` GitHub secret and triggers staging deploy
3. **Track B** — implement all desktop fixes on `feat/phase-11.1-01`
4. Verify locally against local API, then against staging

## Verification

1. `cargo build` (debug) succeeds with new command
2. `cargo build --release` does NOT include `handle_test_login_complete`
3. Local test: `VITE_API_URL=http://localhost:3000 pnpm --filter desktop dev -- -- --dev-key test` — authenticates headlessly, vault initializes, FUSE mounts
4. Staging test: same with default `.env` pointing at staging API (after Track A deployed)


If you need specific details from before exiting plan mode (like exact code snippets, error messages, or content you generated), read the full transcript at: /Users/michael/.claude/projects/-Users-michael-Code-cipher-box/ae47e084-23a3-4040-b237-97481e61c9b4.jsonl

## Summary

All tasks complete. Here's a summary of all changes:

## Changes Made

### Track A: Staging infra
- **`.github/workflows/deploy-staging.yml`** — Changed `NODE_ENV=production` to `NODE_ENV=staging` and added `TEST_LOGIN_SECRET=${{ secrets.STAGING_TEST_LOGIN_SECRET }}` to the generated env file. This unblocks test-login on the staging API.

### Track B: Desktop test-mode fixes

1. **`apps/desktop/src-tauri/src/commands.rs`** — Extracted the shared post-auth logic (token storage, vault init/fetch, device registration, FUSE mount, window management) into a new `complete_auth_setup()` helper. `handle_auth_complete` now delegates to it after the `/auth/login` POST.

2. **`apps/desktop/src-tauri/src/commands.rs`** — Added `handle_test_login_complete` (gated by `#[cfg(debug_assertions)]`) that accepts `{ access_token, refresh_token, private_key_hex, is_new_user }` from the webview and calls `complete_auth_setup` directly, skipping the `/auth/login` POST.

3. **`apps/desktop/src-tauri/src/main.rs`** — cfg-gated the invoke handler list to include `handle_test_login_complete` only in debug builds.

4. **`apps/desktop/src/main.ts`** — Fixed all three bugs in `handleDevKeyAuth`:
   - Uses `data.accessToken` (not `data.idToken`)
   - Uses `data.privateKeyHex` from test-login response (not the CLI dev key)
   - Calls `handle_test_login_complete` (not `handle_auth_complete`)
   - Throws immediately when `VITE_TEST_LOGIN_SECRET` is missing

5. **`apps/desktop/.env`** — Added `VITE_TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production`

6. **`apps/desktop/CLAUDE.md`** — Updated dev-key mode docs to reflect the fixed behavior.

### Verification
- `cargo build` (debug) — compiles with new command
- `cargo build --release` — `handle_test_login_complete` is correctly excluded

### Next steps
- Add `STAGING_TEST_LOGIN_SECRET` secret to the GitHub staging environment
- Deploy to staging to enable test-login there

## Key Actions

- - **Bash**: Check current branch
- - **Read**: /Users/michael/Code/cipher-box/.github/workflows/deploy-staging.yml
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/src/commands.rs
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/src/main.rs
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src/main.ts
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/.env
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/CLAUDE.md
- - **Grep**: test-login
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/src/api/types.rs
- - **Grep**: test-login|testLogin
