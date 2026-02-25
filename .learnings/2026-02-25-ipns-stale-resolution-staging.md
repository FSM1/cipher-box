# IPNS Stale Resolution on Staging

**Date:** 2026-02-25

## Original Prompt

> Can you run the e2e tests against the local ui pointed at staging API, and make the tests resilient enough to execute reliably against the staging API?

## What I Learned

- **delegated-ipfs.dev serves stale IPNS records**: The network resolver caches records with a TTL that can be minutes behind the latest publish. This is invisible locally (same-machine IPFS resolves instantly) but causes consistent failures on staging.
- **DB cache is always fresh but was only used as a fallback**: The API writes the CID to the DB synchronously during `publishRecord()`, so the DB is always authoritative. But `resolveRecord()` only checked the DB when the network failed (502/timeout), not when it returned stale data.
- **The fix is sequence number comparison**: When both network and DB return results, compare `sequenceNumber` and prefer whichever is higher. Simple, correct, no API surface changes needed.
- **E2E test error context screenshots are captured AFTER assertion failure**: The page may have updated between the timeout expiring and the screenshot being taken. Don't be fooled by screenshots showing the expected element — it appeared too late.
- **Running tests in isolation doesn't work for serial test suites**: Tests like "3.7 Page reload" depend on prior tests (login, folder creation) having run. Use `-g` grep patterns only for standalone tests, not serial chains.

## What Would Have Helped

- Knowing upfront that the DB always has the freshest CID (written during publish) would have immediately pointed to the API fix instead of trying to add retry loops in tests
- Running `resolveRecord` with logging enabled to see whether the network or DB was being used
- The staging `.env` credentials (`TEST_LOGIN_SECRET`) matching local was a lucky coincidence — should document which env vars must match for cross-environment E2E

## Key Files

- `apps/api/src/ipns/ipns.service.ts:355-395` — `resolveRecord()` two-tier resolution logic
- `apps/api/src/ipns/ipns.service.spec.ts:512+` — unit tests for resolve behavior
- `tests/e2e/.env` — `API_BASE_URL` must match the target environment
- `tests/e2e/tests/full-workflow.spec.ts:530+` — test 3.7 (reload persistence)
- `tests/e2e/tests/sharing-workflow.spec.ts:412+` — test 7.2 (post-share visibility)
