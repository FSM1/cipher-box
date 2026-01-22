# Archived E2E Tests

These test files have been archived as part of the simplified E2E test approach.

## Why Archived?

The original tests used a storage-state-based approach that required:

1. Global setup to perform Web3Auth login and save session state
2. Each test file loading the saved storage state
3. Complex fixture handling for session restoration

This approach had issues with:

- Web3Auth session expiry causing flaky tests
- Storage state becoming stale between test runs
- Complex CI setup with state file management

## New Approach

The new `tests/full-workflow.spec.ts` uses a single sequential test session that:

1. Logs in once via Web3Auth at the start
2. Performs all file/folder operations in sequence
3. Cleans up and logs out at the end

This eliminates session expiry issues and reduces complexity.

## Restoring Archived Tests

If you need to restore these tests:

1. Move the test files back to `tests/e2e/tests/`
2. Restore `fixtures/auth.fixture.ts` and `fixtures/index.ts`
3. Restore `global-setup.ts`
4. Update `playwright.config.ts` to use globalSetup and storageState

Note: The archived tests may need updates to work with the current codebase.
