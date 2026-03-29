# E2E Test Debugging Workflow

**Date:** 2026-03-29
**Context:** Debugging batch-download and streaming-playback E2E test failures in CI

## Key Lessons

### Never blindly commit E2E fixes and wait for CI

CI round-trips take 15-20 minutes per iteration. Blindly pushing fixes and waiting for CI is extremely inefficient. Always reproduce failures locally first.

### Local reproduction approach

1. **Run against staging first:** The default Playwright `webServer` config often doesn't work locally (services may be misconfigured, mock wallet may not render). Instead, run tests against the staging environment:

   ```bash
   BASE_URL=https://app-staging.cipherbox.cc pnpm --filter @cipherbox/web-e2e exec playwright test tests/<file>.spec.ts --timeout 180000
   ```

2. **If staging isn't available:** Start API and web app manually before running tests (don't rely on Playwright's `webServer` auto-start):

   ```bash
   pnpm --filter @cipherbox/api dev &
   pnpm --filter @cipherbox/web dev &
   # Wait for both to be ready, then run tests
   ```

3. **Only commit after tests pass locally/staging.**

### Playwright beforeAll hook timeout

- `test.setTimeout()` at describe level only sets **test** timeouts, NOT hook timeouts
- `beforeAll`/`afterAll` hooks default to **30 seconds** regardless of `test.setTimeout()`
- To extend hook timeout: call `test.setTimeout(N)` **inside** the hook body
- When a hook times out, Playwright tears down the browser context — any pending `page.waitForURL` etc. fails with "Target page, context or browser has been closed", which looks like a crash but is just a timeout

### Escape key unreliable for UI dismissal in E2E

- `page.keyboard.press('Escape')` is unreliable for dismissing selection bars after certain operations (e.g., batch download)
- Prefer explicit UI actions like `selectionBar.clickClear()` over keyboard shortcuts
- CI headless Chrome handles keyboard events differently than headed browsers

### Soft assertions for environment-dependent features

- CTR streaming badge depends on: SW active + file encrypted with CTR + metadata resolution
- This pipeline may not work in all environments (staging deploys may be behind, Vite dev mode SW quirks)
- Use soft assertions (try/catch with timeout) for features that depend on the full pipeline
- Don't let environment-specific issues break the entire test suite
