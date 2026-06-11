<!-- generated-by: gsd-doc-writer -->

# @cipherbox/sdk-e2e

SDK-level end-to-end tests that exercise the `@cipherbox/sdk` and `@cipherbox/core` packages
against a live API and IPFS/IPNS stack.

Part of the [CipherBox monorepo](../../README.md).

## What It Covers

Each test suite runs against real API accounts created via `/auth/test-login`:

- `vault-lifecycle` — vault init, export, quota, and deletion
- `file-operations` — upload, download, rename, delete
- `folder-crud` — create, rename, move, delete folders
- `bin-operations` — trash and restore flows
- `batch-upload` — concurrent multi-file upload
- `data-integrity` — round-trip content verification
- `concurrent-operations` — race-condition safety
- `error-cases` — SDK error handling for bad inputs
- `ipns-consistency` — IPNS metadata publish/resolve consistency
- `share-operations` — user-to-user file sharing
- `invite-link` — invite link create, claim, and revoke

## Prerequisites

A running local stack (API + IPFS node) is required. See
[../../docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md) for setup instructions.

## Environment Variables

| Variable                 | Required | Default                                    | Description                           |
| ------------------------ | -------- | ------------------------------------------ | ------------------------------------- |
| `SDK_E2E_API_URL`        | No       | `http://localhost:3000`                    | Base URL of the CipherBox API         |
| `SDK_E2E_SECRET`         | No       | `e2e-test-secret-do-not-use-in-production` | Shared secret for test-login endpoint |
| `THROTTLE_BYPASS_SECRET` | No       | _(empty)_                                  | Bypass rate-limiting in dev/staging   |

## Running Tests

```bash
# Run all suites once (no coverage)
pnpm test

# Watch mode for a single suite during development
pnpm test:watch

# Run a single suite by filename pattern
pnpm test:single file-operations
```

Tests run sequentially (`fileParallelism: false`) with a 120 s timeout per test.

## CI

These tests are not part of the standard `ci-e2e.yml` workflow (which covers web and desktop
E2E only). They are intended for local verification and targeted staging runs.

## Further Reading

- [../../docs/TESTING.md](../../docs/TESTING.md) — project-wide testing strategy and coverage policy
- [../TESTING_STRATEGY.md](../TESTING_STRATEGY.md) — E2E layer breakdown and test scope decisions
