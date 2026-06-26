---
phase: 55-large-source-file-refactor
plan: "04"
subsystem: sdk-core/folder, api/ipns, web/file-browser
tags: [refactor, typescript, barrel-split, component-split, codec-extract]
dependency_graph:
  requires: []
  provides: [sdk-core-folder-split, ipns-codec-module, details-subcomponents]
  affects: [packages/sdk-core, apps/api, apps/web]
tech_stack:
  added: []
  patterns: [barrel-export-star, codec-module-logger-param, react-subcomponent-split]
key_files:
  created:
    - packages/sdk-core/src/folder/load.ts
    - packages/sdk-core/src/folder/metadata-ops.ts
    - packages/sdk-core/src/folder/registration.ts
    - apps/api/src/ipns/ipns-record.codec.ts
    - apps/web/src/components/file-browser/details/DetailsPrimitives.tsx
    - apps/web/src/components/file-browser/details/VersionHistory.tsx
    - apps/web/src/components/file-browser/details/FileDetails.tsx
    - apps/web/src/components/file-browser/details/FolderDetails.tsx
  modified:
    - packages/sdk-core/src/folder/index.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/web/src/components/file-browser/DetailsDialog.tsx
decisions:
  - "registration.ts imports fetchAndDecryptMetadata from ./load directly (not via barrel) to avoid circular dependency in decodeRemote callback"
  - "ipns-record.codec.ts takes Logger as a plain parameter (not NestJS DI) — codec fns are pure helpers, @Injectable stays on IpnsService only"
  - "FolderDetails.tsx uses em dash literal (—) matching original unicode escape \\u2014"
  - "FileDetails.tsx: formatBytes not imported (it is unused in FileDetails; used only in VersionHistory)"
metrics:
  duration: ~25 minutes
  completed: "2026-06-21"
  tasks_completed: 3
  files_changed: 11
---

# Phase 55 Plan 04: Tier-1 TypeScript/Web Splits Summary

Three large TypeScript/React files split into cohesive modules with zero public-surface change (D-05): the `../folder` barrel, the `IpnsService` DI class, and the `DetailsDialog` container props are all byte-identical after the split.

## What Was Built

### Task 1: sdk-core folder/index.ts barrel split (28fa2beca)

Split `packages/sdk-core/src/folder/index.ts` (602 LoC) into three sibling modules:

- `load.ts`: `fetchAndDecryptMetadata` + `loadFolderMetadata` (IPFS fetch + decrypt)
- `metadata-ops.ts`: `renameInFolder`, `deleteFromFolder`, `addFilePointerToFolder`, `moveItem` (pure transforms, no network side effects)
- `registration.ts`: `createSubfolder`, `updateFolderMetadataAndPublish`, `addFileToFolder`, `addFilesToFolder`, `replaceFileInFolder` + private `buildFolderIpnsRecord` + private `uint8ToBase64` (IPNS record build and batch-publish)

`index.ts` reduced to ~20 LoC barrel using `export *` from each sibling. Tree/merge re-exports preserved verbatim. `registration.ts` imports `fetchAndDecryptMetadata` from `./load` directly.

### Task 2: ipns-record.codec.ts extraction from ipns.service.ts (17b259862)

Extracted the ~99 LoC codec section from `apps/api/src/ipns/ipns.service.ts` into `apps/api/src/ipns/ipns-record.codec.ts`:

- `IpnsRecordFields` interface (the shared return shape)
- `parseIpnsRecordBytes(recordBytes, logger)` — async, parses IPNS binary record
- `parseCachedRecord(cached, logger)` — async, reads from DB cache entity
- `withCachedPublicKey(result, publicKey)` — sync, enriches result with cached key

`Logger` passed as a parameter (not via DI). `IpnsService` keeps `@Injectable`, constructor, and all orchestration; replaced three `this.*` calls with imported function calls passing `this.logger`.

### Task 3: DetailsDialog.tsx split into details/ sub-components (5465337c5)

Split `apps/web/src/components/file-browser/DetailsDialog.tsx` (664 LoC) into:

- `details/DetailsPrimitives.tsx`: `CopyableValue`, `DetailRow`, `formatDateWithTime`
- `details/VersionHistory.tsx`: version history component with download/restore/delete; `void folderKey;` preserved verbatim (Pitfall 7 lint suppression)
- `details/FileDetails.tsx`: file metadata display including version history section
- `details/FolderDetails.tsx`: folder IPNS/key/timestamp display

`DetailsDialog.tsx` remains the exported container with both cross-guarded `useEffect` hooks (folder IPNS resolution + file metadata IPNS resolution) — they share `setMetadataCid`/`setMetadataLoading` state and cannot be split (Pitfall 4). CSS import stays in container. Container props unchanged. File-browser barrel untouched.

## Verification

- `pnpm --filter @cipherbox/sdk-core test`: 211 tests passed (18 test files)
- `pnpm --filter @cipherbox/api test`: 893 tests passed (44 test suites)
- `pnpm --filter @cipherbox/web test`: 63 tests passed (8 test files)
- `pnpm --filter @cipherbox/web exec tsc --noEmit`: clean
- `pnpm api:generate`: NOT run (no API DTO/endpoint change — pure internal refactor)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed unused `formatBytes` import from FileDetails.tsx**

- **Found during:** Task 3 tsc --noEmit check
- **Issue:** `formatBytes` was included in the initial FileDetails.tsx import (copied from the original file's imports) but is not used in the `FileDetails` component — it is used in `VersionHistory`. tsc reported TS6133.
- **Fix:** Removed `formatBytes` from the import in `FileDetails.tsx`
- **Files modified:** `apps/web/src/components/file-browser/details/FileDetails.tsx`
- **Commit:** included in Task 3 commit (5465337c5)

## Known Stubs

None — this is a pure refactor; no data wiring or UI behavior changed.

## Threat Flags

None — pure internal code reorganization with no new network endpoints, auth paths, file access patterns, or schema changes.

## Self-Check: PASSED

Files created:

- packages/sdk-core/src/folder/load.ts: FOUND
- packages/sdk-core/src/folder/metadata-ops.ts: FOUND
- packages/sdk-core/src/folder/registration.ts: FOUND
- apps/api/src/ipns/ipns-record.codec.ts: FOUND
- apps/web/src/components/file-browser/details/DetailsPrimitives.tsx: FOUND
- apps/web/src/components/file-browser/details/VersionHistory.tsx: FOUND
- apps/web/src/components/file-browser/details/FileDetails.tsx: FOUND
- apps/web/src/components/file-browser/details/FolderDetails.tsx: FOUND

Commits verified:

- 28fa2beca: sdk-core folder split
- 17b259862: ipns codec extraction
- 5465337c5: DetailsDialog sub-components
