---
created: 2026-03-28T02:03:43.219Z
title: Add shared deleteAccount teardown to all E2E specs
area: testing
files:
  - tests/web-e2e/utils/api-helpers.ts
  - tests/web-e2e/tests/recovery.spec.ts
  - tests/sdk-e2e/src/fixtures/test-harness.ts
---

## Problem

Only 1 of 12 web-e2e specs (`recovery.spec.ts`) deletes its test account after running. The other 11 specs only close browser contexts in `afterAll`, leaving orphaned test accounts in the database. `load-test.spec.ts` has a `deleteAccount()` helper but doesn't call it in teardown.

A `deleteTestAccount()` helper already exists in `tests/sdk-e2e/src/fixtures/test-harness.ts` that calls `DELETE /auth/account` with `{ confirmation: "DELETE" }`.

## Solution

1. Create a shared web-e2e helper (e.g., `tests/web-e2e/utils/cleanup-helpers.ts`) wrapping the `DELETE /auth/account` call — can be done via `page.evaluate()` similar to `load-test.spec.ts`'s pattern
2. Wire the helper into every spec's `afterAll` hook, before `context.close()`
3. Update `closeWalletTestAccounts()` in `multi-account-wallet.ts` to also delete accounts
4. Ensure the deletion is best-effort (catch errors) so test failures still report properly
