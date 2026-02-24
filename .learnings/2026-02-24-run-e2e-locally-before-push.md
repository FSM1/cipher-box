# Run E2E Tests Locally Before Pushing to CI

**Date:** 2026-02-24

## Original Prompt

> You should always aim to have at least the specific feature suite running locally before pushing up to CI, since the feedback loop is much shorter.

## What I Learned

- **Always run the relevant E2E test suite locally before pushing** — CI feedback takes several minutes (build + deploy + test), while local runs give immediate results
- Even if a local run fails for infrastructure reasons (missing API server, stale credentials), the attempt itself is valuable — it confirms whether the test file parses correctly, imports resolve, and the test structure is valid
- The search workflow E2E test (`tests/e2e/tests/search-workflow.spec.ts`) can be run in isolation:

  ```bash
  cd tests/e2e && pnpm exec playwright test tests/search-workflow.spec.ts
  ```

- For local E2E runs to fully pass, the dev environment must be running:
  - API server: `pnpm --filter api dev` (port 3000)
  - Frontend: `pnpm --filter web dev` (port 5173)
  - Test credentials must be valid (see `tests/e2e/.env`)

## What Would Have Helped

- Running the test locally before the first push would have shortened the debug cycle
- The `CryptoError: Key unwrapping failed` seen locally indicates the test account's vault keys may need refreshing or the API server wasn't running
- A quick `pnpm exec playwright test tests/<feature>.spec.ts` after every change to E2E test files should be standard practice

## Key Files

- `tests/e2e/tests/search-workflow.spec.ts` — the search E2E test suite
- `tests/e2e/page-objects/dialogs/search-palette.page.ts` — search palette page object
- `tests/e2e/.env` — test credentials
- `tests/e2e/playwright.config.ts` — test configuration
