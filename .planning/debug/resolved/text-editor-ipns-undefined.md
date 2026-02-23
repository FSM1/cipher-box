---
status: resolved
trigger: 'Opening the text editor modal to edit a text file triggers a 400 error with ipnsName=undefined'
created: 2026-02-18T00:00:00Z
updated: 2026-02-18T00:00:02Z
---

## Current Focus

hypothesis: CONFIRMED - isFilePointer type guard only checks type==='file', not fileMetaIpnsName presence
test: Code trace confirmed the data flow
expecting: N/A - root cause found, fix applied and verified
next_action: Complete

## Symptoms

expected: Text editor modal opens and loads the file content for editing without errors.
actual: 400 error when opening the text editor modal. Browser console shows failed request to `/ipns/resolve?ipnsName=undefined`.
errors: `Failed to load resource: the server responded with a status of 400 ()` -- request URL: `https://api-staging.cipherbox.cc/ipns/resolve?ipnsName=undefined`
reproduction: Open the web app, navigate to a text file, click to edit it (open text editor modal).
started: Unknown -- likely a regression or the text editor feature has this bug.

## Eliminated

## Evidence

- timestamp: 2026-02-18T00:00:01Z
  checked: TextEditorDialog.tsx line 72-73
  found: downloadFileFromIpns called with item.fileMetaIpnsName which comes from the item prop
  implication: If item lacks fileMetaIpnsName, the value is undefined

- timestamp: 2026-02-18T00:00:01Z
  checked: FileBrowser.tsx line 46-48 (isFilePointer type guard)
  found: isFilePointer only checks item.type === 'file', does NOT verify fileMetaIpnsName exists
  implication: v1 FileEntry objects (type='file' but with cid, no fileMetaIpnsName) pass the guard

- timestamp: 2026-02-18T00:00:01Z
  checked: folder.service.ts line 133, FileBrowser.tsx line 287
  found: metadata.children cast to FolderChildV2[] without version check -- v1 FileEntry objects pass through
  implication: If IPNS data is v1 format, FileEntry objects get treated as FilePointer

- timestamp: 2026-02-18T00:00:01Z
  checked: packages/crypto/src/folder/metadata.ts line 73-81 (validateFolderMetadata)
  found: Validation accepts file entries with EITHER cid OR fileMetaIpnsName
  implication: v1 FileEntry with cid but no fileMetaIpnsName passes validation

- timestamp: 2026-02-18T00:00:02Z
  checked: TypeScript compilation and ESLint
  found: All 3 modified files compile without errors and pass linting
  implication: Fix is type-safe and follows project code style

## Resolution

root_cause: The `isFilePointer` type guard in FileBrowser.tsx only checked `item.type === 'file'` but did not verify that `fileMetaIpnsName` exists. When folder metadata is decrypted (either v1 data cast as v2, or corrupted/incomplete v2 data), file entries without `fileMetaIpnsName` pass the type guard and get treated as `FilePointer` objects. The TextEditorDialog (and other consumers) then access `item.fileMetaIpnsName` which is `undefined`, causing the request to `/ipns/resolve?ipnsName=undefined` (400 error).

fix: Three-layer defense:

1. Fixed `isFilePointer` type guard to check `type === 'file'` AND `'fileMetaIpnsName' in item` AND `typeof fileMetaIpnsName === 'string'` -- this protects ALL consumers (text editor, image preview, PDF preview, audio/video player, download, batch download)
2. Added early guard in TextEditorDialog.useEffect before calling downloadFileFromIpns -- shows user-friendly error message
3. Added early guard in DetailsDialog file metadata resolution -- gracefully handles missing fileMetaIpnsName

verification: TypeScript compilation passes (0 errors). ESLint passes (0 errors). The fix prevents undefined ipnsName from reaching the API call.

files_changed:

- apps/web/src/components/file-browser/FileBrowser.tsx (isFilePointer type guard)
- apps/web/src/components/file-browser/TextEditorDialog.tsx (early guard for missing fileMetaIpnsName)
- apps/web/src/components/file-browser/DetailsDialog.tsx (early guard for missing fileMetaIpnsName)
