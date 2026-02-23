---
status: resolved
trigger: "File sizes are not being displayed in the web file browser interface. All files show '--' instead of actual file sizes."
created: 2026-02-19T00:00:00Z
updated: 2026-02-19T00:02:00Z
---

## Current Focus

hypothesis: CONFIRMED AND FIXED
test: TypeScript compiles cleanly, all 22 existing tests pass
expecting: N/A
next_action: Archive session

## Symptoms

expected: File sizes should display actual human-readable sizes (e.g., "1.2 MB", "340 KB") in the file browser table
actual: All files show "--" as their size in the file browser, regardless of file or location
errors: No visible error messages reported
reproduction: Navigate to any file browser view - all files show "--" for size
started: Used to work before, broke at some point. Affects all file browser views.

## Eliminated

## Evidence

- timestamp: 2026-02-19T00:00:30Z
  checked: FileListItem.tsx line 327
  found: `const sizeDisplay = isFile(item) ? '--' : '-';` hardcodes "--" for all files
  implication: Size is never fetched or formatted for display in the file list

- timestamp: 2026-02-19T00:00:35Z
  checked: FilePointer type in packages/crypto/src/file/types.ts
  found: FilePointer type (used in v2 folder metadata) has no `size` field - only id, name, fileMetaIpnsName, createdAt, modifiedAt
  implication: Size data must be fetched from the per-file IPNS metadata record

- timestamp: 2026-02-19T00:00:40Z
  checked: git log and diff for FileListItem.tsx
  found: Commit dee300a (feat(12.6): per-file IPNS metadata split) changed the size display from `formatBytes(item.size)` to hardcoded `'--'` with comment "v2 FilePointers don't have inline size"
  implication: This was an intentional deferral during the v2 migration, not an accidental regression

- timestamp: 2026-02-19T00:00:45Z
  checked: resolveFileMetadata in file-metadata.service.ts
  found: resolveFileMetadata(fileMetaIpnsName, folderKey) returns FileMetadata which includes `size: number`
  implication: The service to fetch file sizes already exists, just needs to be called from FileListItem

- timestamp: 2026-02-19T00:00:50Z
  checked: DetailsDialog.tsx
  found: Already uses resolveFileMetadata to fetch and display file metadata (including size via formatBytes) when the details dialog is opened
  implication: Pattern for lazy-loading file metadata already established in codebase

- timestamp: 2026-02-19T00:01:30Z
  checked: TypeScript compilation and test suite
  found: Zero TypeScript errors, all 22 existing tests pass
  implication: Fix is type-safe and does not cause regressions

## Resolution

root_cause: When the codebase migrated from v1 (inline file data) to v2 (per-file IPNS metadata) in commit dee300a, the FilePointer type no longer carries inline `size`. The FileListItem component was updated to hardcode "--" as a placeholder but was never updated to lazily resolve file sizes from per-file IPNS records. The resolveFileMetadata service exists and works (used by DetailsDialog), but FileListItem never calls it.

fix: Created useFileSize hook with module-level caching and request deduplication. Updated FileListItem to use the hook for lazy file size resolution. Threaded folderKey prop through FileList -> FileListItem. Added cache cleanup on logout.

verification: TypeScript compiles with zero errors. All 22 existing tests pass. The fix follows established patterns (same resolveFileMetadata service used by DetailsDialog).

files_changed:

- apps/web/src/hooks/useFileSize.ts (NEW - hook for lazy file size resolution with caching)
- apps/web/src/components/file-browser/FileListItem.tsx (use useFileSize hook instead of hardcoded "--")
- apps/web/src/components/file-browser/FileList.tsx (thread folderKey prop to FileListItem)
- apps/web/src/components/file-browser/FileBrowser.tsx (pass folderKey to FileList)
- apps/web/src/hooks/useAuth.ts (clear file size cache on logout)
