---
created: 2026-06-24
title: Stabilize flaky e2e suites (web cascade-abort + desktop macOS FUSE-T sync)
area: tests/web-e2e, tests/desktop-e2e
files:
  - tests/web-e2e/playwright.config.ts
  - tests/web-e2e/tests/invite-link-workflow.spec.ts
  - tests/web-e2e/tests/journey-timing.spec.ts
  - tests/web-e2e/tests/media-preview.spec.ts
  - tests/desktop-e2e/scripts/test-cross-client-sync.sh
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

## Also: desktop-e2e macOS cross-client sync (FUSE-T timing)

`tests/desktop-e2e/scripts/test-cross-client-sync.sh:194` —
`FUSE mount still shows original content after 120s` — flakes on **macOS only**
(Linux + Windows pass). Root cause is FUSE-T's SMB backend caching (noted in
`test-round-trip.sh:125`) stacked on the 30s IPNS poll: the test allows 120s
("two full polling cycles", line 172) for a cross-client write to surface in the
other client's FUSE mount, and on macOS the SMB cache occasionally exceeds that
window. The folder-rename leg is already marked "optional on macOS" for the same
reason (it warns instead of failing); the content-sync leg is not.

Evidence it is a flake, not a regression (PR #555 full CI E2E dispatch, run
28112732258 on commit 1f8f8d85d): the same macOS job PASSED on the immediately
prior full dispatch (run 28105996601, commit 88f096505), and `git diff
88f096505..1f8f8d85d` shows the ONLY Rust change is inside `crates/api-client/src/ipns.rs`
`mod tests` (skew boundary tests) — zero production-code delta in any path the
desktop binary exercises. macOS desktop also shows intermittent failures on `main`
history independent of this branch.

PROVEN pre-existing (not a Phase 60 regression): the IDENTICAL failure
(`Test 5: Wait for FUSE mount to detect edit` → `FUSE mount still shows original
content after 120s`) occurred on **main**, commit 541e4c6, run 28043695361
(2026-06-23) — BEFORE Phase 60 existed. On the PR branch (commit 1f8f8d85d) the
same macOS job is 1-fail/1-pass across two dispatches; Linux + Windows always pass.

Failure mode (from desktop logs, run 28112732258): the desktop DOES detect the
remote edit (`File 'sync-test-NNNNN.txt': modified_at changed (remote edit
detected), marking for re-resolution`) but the re-resolution then never completes
— no new-CID fetch is logged for the remaining ~90s. When it passes, it completes
fast (`Sync detected on attempt 7 (35s)`). So it is a STALL, not a too-short
timeout (a longer timeout would not help a re-resolution that never lands). Likely
root cause: on macOS FUSE-T's SMB backend the test's `ls`/`stat`/`cat` poll does
not reliably fire the FUSE callback that drives `drain_refresh_completions()` ->
`populate_folder()`, so the marked re-resolution is never drained/applied (SMB
caches readdir/getattr). The `baseChildren not provided ... union fallback` warning
seen near here is unrelated benign noise — it appears in passing runs too.

Options: (a) make the macOS content-sync leg optional/warn like the sibling
folder-rename leg already is (consistent, but loses macOS content-sync coverage);
(b) force a FUSE-T SMB cache/dir invalidation between write and read in the harness
so the drain fires deterministically; (c) root-cause the desktop-side drain trigger
on macOS so re-resolution completions are applied without depending on a FUSE
callback the SMB backend may swallow. Prefer (c) (real fix) or (b); (a) is the
quick test-hygiene stopgap. A blanket timeout bump is NOT a fix (the failure is a
stall, not slowness).
