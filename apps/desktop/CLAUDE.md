# Desktop App (`apps/desktop`) - Development Notes

## Default API Target

The desktop app defaults to the **staging API** (`https://api-staging.cipherbox.cc`). Most development and testing tasks can be completed against staging without running a local API.

To develop against the local API instead, update `.env`:

```env
VITE_API_URL=http://localhost:3000
VITE_ENVIRONMENT=local
```

Also set `CIPHERBOX_API_URL=http://localhost:3000` in the Rust env (used by the native backend):

```bash
CIPHERBOX_API_URL=http://localhost:3000 pnpm --filter desktop dev
```

## Running the Desktop App

```bash
pnpm --filter desktop dev
```

Vite env vars are loaded from `apps/desktop/.env` automatically. No need to pass them on the command line.

## Dev-Key Mode (Headless Auth for Debugging)

Debug builds accept `--dev-key <hex>` to bypass Web3Auth login entirely, enabling fast restart cycles during FUSE/backend debugging.

**How it works:**

1. Pass a 64-char hex secp256k1 private key via `--dev-key`
2. The webview detects it via the `get_dev_key` IPC command
3. Calls `POST /auth/test-login` with the configured `VITE_TEST_LOGIN_SECRET`
4. Gets a JWT, then calls `handle_auth_complete` with the JWT + dev key

**Requirements:**

- `VITE_TEST_LOGIN_SECRET` must be set in `.env` (must match the API's `TEST_LOGIN_SECRET`)
- The API must have `TEST_LOGIN_SECRET` configured and `NODE_ENV` != `production`
- **Staging currently does NOT support this** — staging API has `NODE_ENV=production` which blocks test-login. To enable: set `NODE_ENV=staging` and `TEST_LOGIN_SECRET=<secret>` in the staging Docker Compose env.

**Usage with local API:**

```bash
# Generate a dev key (any valid secp256k1 private key)
DEV_KEY=$(openssl rand -hex 32)

# Set up .env with test-login secret
echo 'VITE_TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production' >> apps/desktop/.env

# Also set TEST_LOGIN_SECRET in the API .env
echo 'TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production' >> apps/api/.env

# Run with dev key (local API)
VITE_API_URL=http://localhost:3000 pnpm --filter desktop dev -- -- --dev-key $DEV_KEY
```

**Note:** Each unique dev key creates its own vault. Use the same key across restarts to persist data.

## Stashed WIP: Proactive Readdir Prefetch

There is a stashed change on `feat/phase-11.1-01` with WIP FUSE improvements:

```bash
git stash list  # Look for: "WIP: proactive readdir prefetch + poll-based read fallback (phase 11.1 debugging)"
git stash show -p 'stash@{0}'  # Review the diff
git stash pop 'stash@{0}'     # Restore when ready
```

**What it does:**

- Proactive content prefetch on `readdir` (offset=0): starts downloading/decrypting all child file contents in background so they're cached before the user opens them
- Write-open (`O_WRONLY`/`O_RDWR`): checks content cache before falling back to sync download
- `read()` cache miss: replaces blocking sync download with poll-based approach (100ms increments, 3s max) to avoid stalling the single NFS thread
- Contains `eprintln!(">>>` debug lines that must be removed before merge

**Status:** Untested — was mid-debugging when stashed. Needs UAT verification.

## Tauri Webview Constraints

- No `window.ethereum` — wallet login is not available in the Tauri webview
- OAuth popups use `on_new_window` handler with shared WKWebViewConfiguration
- Use `clearCache()` not `logout({cleanup:true})` for Web3Auth session cleanup
