---
created: 2026-03-28T02:03:43.219Z
title: Add batch download zip E2E tests
area: testing
files:
  - apps/web/src/components/file-browser/FileBrowser.tsx
---

## Problem

Batch download (select multiple files, download as zip) is a web-only feature with no E2E coverage. Listed in the feature matrix under "Features Without E2E Coverage".

## Solution

Create `tests/web-e2e/tests/batch-download.spec.ts` covering:

1. Upload 2-3 small test files to a folder
2. Select multiple files (checkbox selection UI)
3. Trigger batch download (toolbar action)
4. Verify a zip file downloads via Playwright's `page.waitForEvent('download')`
5. Optionally: extract zip and verify contents match uploaded files

Could also be added as additional tests within `full-workflow.spec.ts` if a separate suite feels too thin.
