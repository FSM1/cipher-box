---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 04
subsystem: ui
tags: [react, zustand, download-progress, recycle-bin, web]

# Dependency graph
requires:
  - phase: 78
    provides: "useDownloadStore + useFileDownload store-driven download wrapper; FileBrowser isLoading binding (pre-existing, unwired)"
provides:
  - "handleDownload/handleBatchDownload drive useDownloadStore so the existing FileBrowser spinner fires on real downloads (D-05)"
  - "useRestoreStore metadata-only status state machine for bin restore"
  - "useBin restore/restoreMultiple surface a store-driven restoring/success/error affordance"
affects: [web-e2e download-spinner assertion, bin restore UI]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Store-driven async status: reuse the download.store status state machine shape for metadata-only ops, dropping byte-count fields"

key-files:
  created:
    - apps/web/src/stores/restore.store.ts
  modified:
    - apps/web/src/components/file-browser/useFileBrowserActions.ts
    - apps/web/src/hooks/useBin.ts

key-decisions:
  - "Reused useFileDownload().downloadFromIpns directly in the file-browser handlers (single source of truth) instead of re-wrapping the raw download.service call — params lined up, so the canonical store-driven wrapper is the only download path."
  - "restore.store omits progress/loadedBytes/totalBytes — restore is a metadata-only op (bin re-link + IPNS publish), not a byte stream."
  - "restoreMultiple drives startRestore once per entry so the affordance tracks each in-flight restore, with a single terminal setRestoreSuccess."

patterns-established:
  - "Metadata-only status store: status idle|restoring|success|error + currentItem + error, mirroring download.store minus byte fields."

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "handleDownload/handleBatchDownload drive useDownloadStore so isDownloading is true during a real download and the existing FileBrowser spinner lights up (D-05)."
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "apps/web pnpm vitest run (10 files / 67 tests, 61 pass + 6 skip) — no regression after wiring"
        status: pass
      - kind: automated_ui
        ref: "playwright: NO existing spinner-visibility assertion (Wave 0 gap) — flagged for follow-up; manual/Puppeteer acceptable per CLAUDE.md"
        status: unknown
    human_judgment: true
    rationale: "Spinner visibility has no Playwright assertion (Wave 0 gap). Vitest proves no regression and typecheck/lint prove the store lifecycle is invoked, but the actual on-screen spinner needs a human/Puppeteer check."
  - id: D2
    description: "useRestoreStore added; useBin restore/restoreMultiple drive startRestore/setRestoreSuccess/setRestoreError — the dead download-progress scaffolding is wired, not deleted (D-05)."
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "grep -f restore.store.ts exists && useBin drives useRestoreStore && no byte-count fields; tsc -p tsconfig.json --noEmit exit 0; eslint exit 0"
        status: pass
      - kind: unit
        ref: "apps/web pnpm vitest run green (10 files / 67 tests)"
        status: pass
    human_judgment: false

# Metrics
duration: 8min
completed: 2026-07-12
status: complete
---

# Phase 78 Plan 04: Download/Restore Progress Wiring Summary

**Wired the pre-built-but-unused download-progress scaffolding (D-05): file-browser downloads now drive useDownloadStore so the existing FileBrowser spinner fires, and bin restore surfaces a new store-driven status affordance via useRestoreStore.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-12T01:18:00Z
- **Completed:** 2026-07-12T01:27:00Z
- **Tasks:** 2
- **Files modified:** 3 (1 created, 2 modified)

## Accomplishments
- `handleDownload`/`handleBatchDownload` now call `useFileDownload().downloadFromIpns`, driving the `useDownloadStore` lifecycle (startDownload → setProgress → setDecrypting → setSuccess/setError) so `isDownloading` is true during a real download and the existing `FileBrowser` spinner lights up — `FileBrowser.tsx` unchanged.
- New `useRestoreStore` (Zustand) with a metadata-only status state machine (`status`, `currentItem`, `error` + `startRestore`/`setRestoreSuccess`/`setRestoreError`/`resetRestore`).
- `useBin` `restore`/`restoreMultiple` drive the restore store, replacing the previously silent local boolean with a UI-visible restoring/success/error affordance.

## Task Commits

Each task was committed atomically:

1. **Task 1: Route handleDownload/handleBatchDownload through useDownloadStore** - `f0672a5b7` (feat)
2. **Task 2: Add restore.store and wire useBin restore/restoreMultiple** - `b5622e297` (feat)

## Files Created/Modified
- `apps/web/src/stores/restore.store.ts` (created) - `useRestoreStore` metadata-only status state machine for bin restore.
- `apps/web/src/components/file-browser/useFileBrowserActions.ts` (modified) - both download handlers now reuse the store-driven `useFileDownload().downloadFromIpns`; dropped the direct `download.service`/`triggerBrowserDownload` call sites.
- `apps/web/src/hooks/useBin.ts` (modified) - `restore`/`restoreMultiple` drive `useRestoreStore` on start/success/error.

## Decisions Made
- Reused `useFileDownload().downloadFromIpns` directly rather than re-wrapping the raw `downloadFileFromIpns` service — the params (`fileRef`/`folderKey`/`fileName`) lined up exactly, so the canonical store-driven wrapper becomes the single download path (per D-05's "prefer reusing" guidance). This removed the now-unused `downloadFileFromIpns`/`triggerBrowserDownload` imports from the file.
- `restore.store` deliberately omits byte-count/progress fields: restore is a metadata-only op (bin re-link + IPNS publish), not a byte stream.

## Deviations from Plan
None - plan executed exactly as written. (The plan explicitly permitted choosing between reusing `useFileDownload().downloadFromIpns` and inline store wrapping; the former was chosen and is within plan scope.)

## Issues Encountered
- Initial `restore.store.ts` doc comment literally listed the field names `progress`/`loadedBytes`/`totalBytes`, which tripped the metadata-only-shape grep. Reworded the comment to "the download store's byte-count fields" so the AC grep returns nothing. No behavioral change.

## Known Stubs
None introduced.

## Verification Gap (flagged for follow-up)
- **Spinner visibility has no Playwright assertion (Wave 0 gap).** Vitest (10 files / 67 tests), web typecheck (`tsc --noEmit` exit 0), and `pnpm lint` (exit 0) all pass and prove the store lifecycle is invoked, but the actual on-screen download spinner / restore affordance rendering was not asserted end-to-end. A Puppeteer/manual check is acceptable per CLAUDE.md; a deterministic Playwright assertion is recommended in a later wave. Tracked via coverage deliverable D1 (`human_judgment: true`).

## Next Phase Readiness
- Download and restore progress UX is now live-wired. No blockers. Recommend adding a web-e2e assertion for spinner/affordance visibility when the download-spinner test surface is built.

## Self-Check: PASSED

All created/modified files exist on disk; all three task/doc commits (`f0672a5b7`, `b5622e297`, `8d2111612`) are present in git history.

---
*Phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards*
*Completed: 2026-07-12*
