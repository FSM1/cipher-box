# Worktree E2E Environment Setup

**Date:** 2026-03-30
**Context:** Testing a web-only FileList.tsx fix in a fresh git worktree

## What I Learned

### Fresh worktrees have no .env files

Git worktrees are clean copies — `.env` files are gitignored and won't exist. Before running anything:

1. Copy `.env` files from the main repo checkout (`../cipher-box/apps/`):
   - `apps/api/.env`
   - `apps/web/.env`
   - `tests/web-e2e/.env`
2. Run `pnpm install` — worktrees share the git index but not `node_modules`

### For web-only changes, don't start the API locally

If the change is web-only (e.g., a React component fix):

1. Set `VITE_API_URL=https://api-staging.cipherbox.cc` in `apps/web/.env`
2. Start only the web dev server: `pnpm --filter @cipherbox/web dev`
3. Run E2E tests with `BASE_URL=http://localhost:5173`

Do NOT start a local API — the web app talks directly to staging via `VITE_API_URL`. The Vite proxy (`/api` -> `localhost:3000`) is only used when `VITE_API_URL` is not set.

### Playwright auto-starts servers when BASE_URL is localhost

The Playwright config (`tests/web-e2e/playwright.config.ts`) has a `webServer` block that auto-starts mock-ipns-routing, the API, and the web app when `BASE_URL` is localhost. This is fine in CI but causes problems locally:

- It starts a local API on port 3000 even if you don't want one
- If `VITE_API_URL` points at staging but Playwright also starts a local API, the two can conflict (different JWT secrets, different DB state)
- The `reuseExistingServer: !process.env.CI` flag means it reuses your running web dev server but still starts its own API

This is usually fine — the web app uses `VITE_API_URL` directly and ignores the Playwright-started API. But some tests (e.g., page reload/session restore) may behave differently when the environment is mixed.

### Don't overthink it — the simple path works

For a web-only fix against staging:

```bash
# 1. Copy env files
cp ../cipher-box/apps/api/.env apps/api/.env
cp ../cipher-box/apps/web/.env apps/web/.env
cp ../cipher-box/tests/web-e2e/.env tests/web-e2e/.env

# 2. Install deps
pnpm install

# 3. Point web at staging API
sed -i '' 's|VITE_API_URL=.*|VITE_API_URL=https://api-staging.cipherbox.cc|' apps/web/.env

# 4. Start web dev server
pnpm --filter @cipherbox/web dev &

# 5. Run the specific failing tests
BASE_URL=http://localhost:5173 pnpm --filter @cipherbox/web-e2e exec playwright test tests/<file>.spec.ts --timeout 180000

# 6. Revert .env change before committing
```

## What Would Have Helped

- Knowing upfront that `.env` files need to be copied from the main checkout
- Understanding that `VITE_API_URL` bypasses the Vite proxy entirely — no need to start a local API for web-only changes
- A checklist of env files to copy when setting up a worktree

## Key Files

- `apps/web/.env` — `VITE_API_URL` controls which API the web app talks to
- `apps/api/.env` — DB/IPFS/Redis connection config (only needed if running API locally)
- `tests/web-e2e/.env` — E2E test credentials
- `tests/web-e2e/playwright.config.ts` — webServer auto-start logic
- `apps/web/src/lib/api-config.ts` — where `VITE_API_URL` is read
