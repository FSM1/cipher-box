---
created: 2026-02-10T14:45
title: Fix flaky post-reload e2e tests (3.8, 3.10)
area: testing
files:
  - tests/e2e/tests/full-workflow.spec.ts:537-548
  - tests/e2e/tests/full-workflow.spec.ts:452-465
---

## Problem

E2E tests 3.8 ("Navigate into subfolder after reload and verify contents") and 3.10 ("Upload file to subfolder after reload") are consistently flaky. After `page.reload()`, the Zustand store is wiped and the app must re-authenticate and cold-load subfolder contents via IPNS resolve + key unwrapping. The IPNS cold-load timing is unreliable — document files in subfolders are often not visible within the assertion timeout.

This was observed across 5 consecutive test runs during the details dialog feature work. The tests block all subsequent serial tests when they fail.

Failure pattern: navigating into a subfolder after reload, then asserting `fileList.isItemVisible(file.name)` returns false because the IPNS resolve + decrypt hasn't completed yet.

## Solution

Options to investigate:

- Add `waitForItemToAppear()` with longer timeout before asserting visibility in post-reload tests
- Add retry/polling logic for IPNS resolve completion (e.g., wait for file list to stabilize)
- Use `expect.poll()` or `toPass()` Playwright helpers for eventual consistency assertions
- Consider whether the mock IPNS service response timing needs adjustment
