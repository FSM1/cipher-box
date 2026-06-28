---
phase: 62-unified-node-codec-core-keystone
plan: 08b
subsystem: web-components
status: complete
tags: [node-v3, type-migration, compile-gate, file-browser, SealedChildRef]
requires: [62-08a-SUMMARY.md]
provides: [D-02-gate-web-components]
affects: [apps/web/src/components/file-browser]
tech-stack:
  patterns: [type-swap, behavior-stub, phase-63-discrimination-stub]
key-files:
  modified:
    - apps/web/src/components/file-browser/FileBrowser.tsx
    - apps/web/src/components/file-browser/SharedFileBrowser.tsx
    - apps/web/src/components/file-browser/FileList.tsx
    - apps/web/src/components/file-browser/FileListItem.tsx
    - apps/web/src/components/file-browser/useFileBrowserActions.ts
    - apps/web/src/components/file-browser/ShareDialog.tsx
    - apps/web/src/components/file-browser/TextEditorDialog.tsx
    - apps/web/src/components/file-browser/SelectionActionBar.tsx
    - apps/web/src/components/file-browser/SharedFolderRow.tsx
    - apps/web/src/components/file-browser/SharedMoveDialog.tsx
    - apps/web/src/components/file-browser/MoveDialog.tsx
    - apps/web/src/components/file-browser/InviteLinkTab.tsx
    - apps/web/src/components/file-browser/ImagePreviewDialog.tsx
    - apps/web/src/components/file-browser/PdfPreviewDialog.tsx
    - apps/web/src/components/file-browser/AudioPlayerDialog.tsx
    - apps/web/src/components/file-browser/VideoPlayerDialog.tsx
    - apps/web/src/components/file-browser/ContextMenu.tsx
    - apps/web/src/components/file-browser/DetailsDialog.tsx
    - apps/web/src/components/file-browser/details/FileDetails.tsx
    - apps/web/src/components/file-browser/details/FolderDetails.tsx
    - apps/web/src/components/file-browser/details/VersionHistory.tsx
    - apps/web/src/utils/fileTypes.ts
decisions:
  - "Phase-63 kind-discrimination stubs: isFolder=true, fileCount=0, itemType='folder' — all items treated as folders until Node.kind is available"
  - "UploadVirtualEntry reshaped to be SealedChildRef-compatible (same required fields) so unified sorting works without a union type"
  - "ShareDialog.handleShare + handleUpgrade fully stubbed with throw (phase 65) — legacy FolderEntry/FilePointer key-wrapping path removed"
  - "tsconfig.scripts.json TS2688 error is pre-existing and out-of-scope — web tsc -b + all package builds pass clean"
  - "No test files required quarantine — both grep matches were comment-only references, tests already use SealedChildRef"
metrics:
  duration: "~4 hours (split across context windows)"
  completed: "2026-06-29"
  tasks_completed: 1
  files_changed: 22
---

# Phase 62 Plan 08b: Web Component Layer node/v3 Compile Gate Summary

One-liner: Replace all FolderChild/FilePointer/FolderEntry in ~20 file-browser components with SealedChildRef, fix JSX and ESLint issues, confirm web tsc -b passes clean.

## What Was Built

Mechanical type-swap sweep of the `apps/web/src/components/file-browser/` component layer — the second half of the Phase-62 D-02 web compile gate (Plan 08a covered the logic/hook layer).

### Key changes per file

- **FileBrowser.tsx / SharedFileBrowser.tsx**: Removed all `FolderChild`, `FilePointer`, `isFilePointer` imports and usages. Kind discrimination stubs (`itemType='folder'`, `isFolder=true`). Fixed `{/* JSX comment */}` blocks placed in attribute positions (invalid syntax — TS1005 errors).
- **FileList.tsx**: Reshaped `UploadVirtualEntry` to match `SealedChildRef` required fields so it sorts alongside real children. Removed `.type`-based sort, alphabetical only. Stubbed `onDropOnFolder`/`onExternalFileDrop` as `_` params (phase-63 stubs).
- **FileListItem.tsx**: Full rewrite — `ipnsName` as identifier, `isFolder=true` stub, `sizeDisplay='-'`, `dateDisplay=formatDate(0)`.
- **useFileBrowserActions.ts**: Rewritten to use `SealedChildRef` throughout. `childIds` keyed by `ipnsName`. Behavioral handlers (download, batch-download) stubbed with `logger.warn`. `handleSync` uses `metadata.children ?? []` (Node.children is optional). Omitted `downloadFromIpns` from destructuring (phase-65 stub).
- **ShareDialog.tsx**: Removed `isValidPublicKey`, `collectChildKeys`, `reWrapEncryptedKey`, all legacy crypto imports. `handleShare` + `handleUpgrade` throw `not implemented — phase 65`. Recipients upgrade section simplified from `{true && (...)}` to plain fragment.
- **TextEditorDialog.tsx**: `item.fileMetaIpnsName` → `item.ipnsName`. Owner save path stubs to throw phase-65.
- **SelectionActionBar.tsx**: `fileCount=0` constant removed; description uses `folderCount`. Download button removed (phase-63 stub). `onDownload` prop prefixed `_onDownload`.
- **SharedMoveDialog.tsx**: `item?.type === 'folder'` ternary → `'Move Folder'` constant.
- **Preview dialogs (Image/Pdf/Audio/Video)**: Simple `FilePointer` → `SealedChildRef` prop type swap.
- **details/FileDetails.tsx**: Removed unused `formatDate` import.
- **details/VersionHistory.tsx**: `fileName` → `_fileName` (unused stub).
- **utils/fileTypes.ts**: Removed `isFilePointer` export (replaced by name-extension helpers).

## Test Quarantine

Grep scan for all web test files importing retired types (`FolderMetadata|FileMetadata|FilePointer|FolderEntry|FolderChild`) found 2 files:

- `apps/web/src/stores/__tests__/folder.store.test.ts` — match was a comment only; file already uses `SealedChildRef`
- `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` — match was a comment only; file already uses `SealedChildRef`

No test files required quarantine.

## D-02 Gate Result

- `pnpm --filter @cipherbox/web exec tsc -b`: PASS (zero errors)
- All upstream package builds (crypto, core, api-client, sdk-core, sdk): PASS
- `tsc -p tsconfig.scripts.json --noEmit`: FAIL with pre-existing `TS2688: Cannot find type definition file for 'node'` — confirmed pre-existing via `git stash` test, unrelated to this plan's changes. Out-of-scope per deviation boundary rules.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Invalid JSX comment syntax in attribute positions**

- Found during: Task 1 (tsc run)
- Issue: `{/* TODO(phase 63): ... */}` blocks placed between JSX attributes in element opening tags (valid only as children, not attributes) — caused TS1005 errors in FileBrowser.tsx (3 sites) and SharedFileBrowser.tsx (7 sites)
- Fix: Changed all such blocks to `// line comments` or moved to JSX children section
- Files modified: FileBrowser.tsx, SharedFileBrowser.tsx

**2. [Rule 1 - Bug] ESLint no-constant-binary-expression stubs**

- Found during: Task 1 (pre-commit lint hook)
- Issue: `{true && (...)}` in ShareDialog and `if (true /* TODO */)` in SharedMoveDialog triggered `no-constant-binary-expression`/`no-constant-condition`; `{false && ...}` in SelectionActionBar also flagged
- Fix: Removed `true &&` wrappers (plain fragments or constant expressions), simplified SharedMoveDialog title assignment, removed dead download button in SelectionActionBar
- Files modified: ShareDialog.tsx, SharedMoveDialog.tsx, SelectionActionBar.tsx

**3. [Rule 2 - Missing critical] Unused import/variable cleanup**

- Found during: Task 1 (tsc run)
- Issue: Several unused imports and variables introduced by the type swap (`isValidPublicKey` in ShareDialog, `formatDate` in FileDetails, `fileName` in VersionHistory, `onDropOnFolder`/`onExternalFileDrop` in FileList, `downloadFromIpns` in useFileBrowserActions)
- Fix: Removed dead imports; prefixed unused destructured vars with `_` or omitted from destructuring

## Known Stubs

All stubs are intentional phase-63/65 deferred items, not plan-goal blockers:

| Stub | File | Reason |
|------|------|--------|
| `isFolder = true` | FileListItem, SharedFolderRow, etc. | Node.kind discrimination deferred to phase 63 |
| `fileCount = 0` (removed download button) | SelectionActionBar | Same |
| `handleShare` throws | ShareDialog | Share creation via Node write-chain: phase 65 |
| `handleUpgrade` throws | ShareDialog | Permission upgrade via Node write-chain: phase 65 |
| Owner save throws | TextEditorDialog | Owner file save via Node write-chain: phase 65 |
| `onDropOnFolder = undefined` | FileList/FileListItem | Drop targets: phase 63 |
| `dateDisplay = formatDate(0)` | FileListItem | Dates come from Node envelope: phase 63 |
| `sizeDisplay = '-'` | FileListItem | Size from NodeContent.content.size: phase 63 |

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes introduced. Pure compile-gate sweep.

## Self-Check: PASSED

- [x] Commit 76e0bdc2f exists: `feat(62-08b): migrate file-browser components to node/v3 type system`
- [x] 22 files modified and committed
- [x] `cd apps/web && npx tsc --noEmit` exits 0
- [x] All upstream package builds pass in `pnpm typecheck`
- [x] No retired types in non-test source files
- [x] No test files required quarantine
