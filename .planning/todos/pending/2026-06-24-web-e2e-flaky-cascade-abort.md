---
created: 2026-06-24
title: Stabilize flaky web-e2e suite (single-worker cascade-abort)
area: tests/web-e2e
files:
  - tests/web-e2e/playwright.config.ts
  - tests/web-e2e/tests/invite-link-workflow.spec.ts
  - tests/web-e2e/tests/journey-timing.spec.ts
  - tests/web-e2e/tests/media-preview.spec.ts
---

## Problem

The `tests/web-e2e` Playwright suite runs `workers: 1`, `fullyParallel: false`,
`retries: 0`, and aborts after a small number of failures. Because tests execute
sequentially in (alphabetical) file order, a flake in an *early* file skips every
later test as "did not run", so a single flaky test fails the whole suite and
hides the status of everything after it.

Observed flaky tests (intermittent, **pre-existing** — they predate Phase 60;
the pre-Phase-60 run 28043695361 failed on `media-preview` + `sharing-workflow`
1.1 account creation):

- `invite-link-workflow.spec.ts:157` — `1.1 Create test accounts (Alice, Dave, Eve)` (account-creation setup)
- `journey-timing.spec.ts:94` — `Journey 1: login-to-vault` (timing-sensitive)
- `media-preview.spec.ts:54` — `upload media fixtures`

Surfaced while shipping Phase 60 (PR #555): across three web-e2e dispatches the
failing test differed each run (writable-shares once it had a real bug, then
media-preview, then invite-link + journey-timing), and because `writable-shares`
sorts last it was repeatedly skipped — making it impossible to confirm a fix from
CI alone (had to run the spec locally to verify). Not merge-blocking: web-e2e is
not a required PR check (it only auto-runs on main push when web paths change).

## Solution

TBD — options, smallest-first:

1. Add a small `retries` count (e.g. 1-2) for known-flaky specs, or globally, so a
   single transient failure does not fail + truncate the run.
2. Stabilize the account-creation flow (`1.1 Create test accounts` in
   invite-link-workflow / sharing-workflow) — the Web3Auth mock login + first-publish
   timing is the most common flake source.
3. De-couple ordering so one early flake does not skip the rest (raise/remove the
   max-failures cap in CI, or shard independent specs), so a flaky test reports only
   itself rather than masking the whole tail.
4. Make `journey-timing` assertions tolerant of CI scheduling jitter (timing budgets).

Keep `retries: 0` philosophy in spirit (fix flakiness at the source) but stop a
single flake from masking unrelated coverage.
