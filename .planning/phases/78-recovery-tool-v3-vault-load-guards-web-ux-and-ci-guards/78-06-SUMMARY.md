---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 06
subsystem: docs-ci
tags: [testing, ci, docs, web-vitest, D-06]
requires: []
provides:
  - documented apps/web vitest CI split (D-06)
affects:
  - docs/DEVELOPMENT.md
tech-stack:
  added: []
  patterns:
    - logic->packages/sdk Vitest (CI-gated); UI->Playwright web-e2e; apps/web vitest excluded from blocking CI
key-files:
  created: []
  modified:
    - docs/DEVELOPMENT.md
decisions:
  - "D-06: apps/web vitest intentionally kept OUT of a blocking CI unit-test job; documented split instead"
metrics:
  duration: ~10m
  completed: 2026-07-12
status: complete
---

# Phase 78 Plan 06: Web-vitest CI Decision (D-06) Summary

Documented the deliberate testing split in `docs/DEVELOPMENT.md` and confirmed the residual `apps/web` `*.test.ts` suite is green (10 files / 67 tests: 61 passed + 6 skipped) after the cross-package dist build — implementing decision D-06 (SC3b) without adding any apps/web unit tests or a blocking CI job.

## What Was Built

### Task 1 — Document the apps/web vitest CI split

Added a `### Test architecture and CI coverage (the deliberate split)` subsection to the `docs/DEVELOPMENT.md` Testing section documenting:

- Reusable/business logic is hoisted into `packages/sdk` and covered by Vitest, which IS gated in the blocking CI `Test` job (`.github/workflows/ci.yml`).
- UI behavior is covered by Playwright web-e2e (dispatch/main-push gated, not a per-PR blocking unit job).
- The residual `apps/web` `*.test.ts` suite (10 files / 67 tests) must stay green but is intentionally NOT added to a blocking CI unit-test job — decision D-06, to avoid inviting UI-coupled unit tests.
- Caveat: apps/web vitest `include` matches `*.test.ts` only, so `.spec.ts` files are silently skipped.
- Local prerequisite: build the `crypto`/`core`/`api-client`/`sdk-core`/`sdk` dist chain before running the web suite, or workspace-package resolution fails.

Markdownlint (`pnpm lint:md`) passes for the file; headings use `###`, lists/fences have surrounding blank lines.

### Task 2 — Confirm the residual suite is green; de-rot if needed

Built the workspace dist chain, then ran `cd apps/web && pnpm vitest run`. Result: **10 files passed, 61 passed + 6 skipped (67 tests), 0 failed** — exactly the expected baseline. The single stderr `ERROR` line is an intentional logged-error assertion inside a passing best-effort poll-invalidation test, not a failure.

Nothing rotted, so no test relocation or removal was required. Confirmed `apps/web` remains absent from ci.yml's blocking `Test` job (job body lines 266+ contain no `apps/web`/`vitest`/`web test` invocation) and no new `apps/web` `*.test.ts` files were added.

## Deviations from Plan

None - plan executed exactly as written. Task 2 produced no committed artifact (verification-only; nothing rotted), as anticipated by the plan.

## Verification

- `grep -niE "packages/sdk|web-e2e|blocking|*.test.ts" docs/DEVELOPMENT.md` — split documented in Testing section.
- `pnpm lint:md docs/DEVELOPMENT.md` — passes (no MD036/MD031/MD032).
- Dist chain build + `cd apps/web && pnpm vitest run` — 10 files / 67 tests green (61 passed + 6 skipped), 0 failed.
- `grep "apps/web" .github/workflows/ci.yml` Test job body — no vitest/test invocation; apps/web stays out of the blocking job.
- `git status --porcelain apps/web | grep '.test.ts$'` — no additions.

## Self-Check: PASSED

- docs/DEVELOPMENT.md modified and committed (dfac54bb6): FOUND
- Commit dfac54bb6 in git log: FOUND
- Residual apps/web suite green (0 failed): CONFIRMED
- apps/web absent from ci.yml blocking Test job: CONFIRMED
