---
created: 2026-07-03T00:00:00Z
title: Download progress UX — useFileDownload is dead, spinners never activate
area: ui
files:
  - apps/web/src/components/file-browser/useFileBrowserActions.ts:67
  - apps/web/src/hooks/useFileDownload.ts
source: ship-phase 68.1 simplify review
resolves_phase: 78
---

## Problem

`useFileBrowserActions` takes `isOperating` / `isDownloading` / `downloadFromIpns`
params that its body never reads (destructure at :86-100 omits them; :97 comment
admits it), which leaves `useFileDownload` with zero live consumers. Side effect:
the new `handleDownload` path bypasses the download-progress store, so
FileBrowser's download spinners never activate — downloads work but give no
progress feedback.

## Solution

Decide the intended download-progress UX first: either wire `handleDownload`
through the progress store (restoring spinners), or accept spinnerless downloads
and delete `useFileDownload` + the dead params. Either way remove the dead
parameter surface. Verify via Puppeteer/web-e2e on a large-file download.
