---
slug: decrypt-fail-after-move
status: resolved
trigger: 'Preview/edit/download of a file fails with CryptoError: Decryption failed after the file is moved from root into a subfolder. Reproducible on staging.'
created: 2026-06-17
updated: 2026-06-17
---

# Debug: Decryption fails after moving a file into a subfolder

## Symptoms

**Expected behavior:** After moving a previewable file (txt, pdf) from root into a
subfolder, previewing/editing and downloading the file should still succeed — the
file content must decrypt with the same key regardless of its parent folder.

**Actual behavior:** After the move, the file is correctly listed in the subfolder,
but previewing/editing shows a `Decryption failed` notification, and downloading
silently fails with `ERROR: [FileBrowser] Download failed: CryptoError: Decryption failed`
in the browser console.

**Error messages:**

- Preview/edit dialog: `Decryption failed`
- Console (download): `ERROR: [FileBrowser] Download failed: CryptoError: Decryption failed`

**Timeline:** Noticed as a repeatable failure on staging. Not yet tested locally.
Environment: staging (web app). Unknown when it first appeared.

**Reproduction (deterministic):**

1. Upload a previewable file (txt or pdf) to root.
2. Preview/edit the file — works.
3. Close the preview.
4. Move the file into a subfolder.
5. Navigate to the subfolder — file is correctly listed.
6. Attempt to preview/edit the file → `Decryption failed`.
7. Download also fails with `CryptoError: Decryption failed`.

## Suspected area (seed for investigation — verify, do not assume)

The move succeeds structurally (file lists in the subfolder) but the content key no
longer decrypts. In CipherBox, a file's content is AES-256-GCM encrypted with a
`fileKey`; that key is wrapped and the FilePointer/metadata lives under a folder's
IPNS. A move relocates the FilePointer between folders with different `folderKey`s.
Likely failure modes to check:

- The move re-points/re-publishes the FilePointer into the subfolder but does NOT
  re-wrap the `fileKey` for the new parent folder context, so the reader derives/uses
  the wrong wrapping key on decrypt.
- The move regenerates or drops the `fileKey` / file-metadata IPNS key, or the
  encrypted file-metadata is re-encrypted under the wrong key.
- The reader resolves the file key relative to the destination folder rather than
  carrying the original key, so the wrong key is used post-move.
- Possible interaction with recent SDK folder-state / self-bootstrap work
  (PRs #489/#494/#498/#500 — folderTree / sequence reconciliation) where the moved
  file's pointer is read from a stale or wrong folder snapshot.

Start by reading the web/SDK move-file path (move operation, folder metadata publish,
file key handling) and the preview/download decrypt path, then form a falsifiable
hypothesis from the code before changing anything.

## Current Focus

- hypothesis: "moveItem copies the FilePointer between folders but never re-encrypts the FileMetadata IPNS record from source folderKey to dest folderKey; the decrypt path always uses currentFolder.folderKey (dest), so after move the decryption fails with a key mismatch."
- test: "Write a unit test that (1) creates source FileMetadata encrypted with source folderKey, (2) calls moveItem, (3) calls resolveFileMetadata with dest folderKey → assert decryption fails. Then apply fix and assert it passes."
- expecting: "Test is RED before fix, GREEN after."
- next_action: Write failing test, then apply fix in packages/sdk/src/client.ts moveItem to re-encrypt FileMetadata IPNS record for each moved file using dest folderKey.
- reasoning_checkpoint:
    hypothesis: "moveItem copies the FilePointer to dest folder without re-encrypting the FileMetadata IPNS record — FileMetadata stays encrypted with source.folderKey, but decrypt path uses dest.folderKey"
    confirming_evidence:
      - "packages/sdk-core/src/file/index.ts:136 — createFileMetadata encrypts with params.folderKey (the parent at upload time)"
      - "packages/sdk-core/src/file/index.ts:193-207 — resolveFileMetadata decrypts with folderKey passed by caller"
      - "apps/web/src/components/file-browser/useFileBrowserActions.ts:372-377 — download passes currentFolder?.folderKey (dest after move)"
      - "packages/sdk/src/client.ts:696-756 — moveItem calls sdkCore.moveItem (pure child-array shuffle) + updateFolderMetadataAndPublish (re-encrypts folder metadata only), no call to updateFileMetadata"
      - "packages/sdk-core/src/folder/index.ts:328-354 — moveItem is a pure children-array operation, no file IPNS interaction"
    falsification_test: "If moveItem DID re-encrypt file metadata, packages/sdk/src/client.ts would contain a call to resolveFileMetadata + updateFileMetadata inside moveItem — it does not (lines 696-756)"
    fix_rationale: "After moving the FilePointer to dest folder, re-encrypt each moved file's FileMetadata with dest.folderKey by: resolving the file's IPNS record using source.folderKey, re-encrypting with dest.folderKey, and publishing the updated IPNS record"
    blind_spots: "Shared folder moves may have separate code path; bin restore moves are not checked; multi-move batch may also need the fix"
- tdd_checkpoint:
    test_file: "packages/sdk/src/__tests__/client-move-reencrypt.test.ts"
    test_name: "CipherBoxClient.moveItem — file metadata re-encryption"
    status: "green"
    failure_output: "AssertionError: expected 'spy' to be called at least once (before fix)"

## Evidence

- timestamp: 2026-06-17
  checked: "packages/sdk-core/src/file/index.ts — createFileMetadata"
  found: "FileMetadata encrypted with params.folderKey at line 136; upload-time parent folderKey is baked in"
  implication: "After move to a folder with a different key, the FileMetadata IPNS record cannot be decrypted by the new folder's key"

- timestamp: 2026-06-17
  checked: "packages/sdk-core/src/file/index.ts — resolveFileMetadata"
  found: "Caller passes folderKey at line 193-207; decrypts with whatever key the caller provides"
  implication: "The decrypt side trusts the caller to supply the correct key — if the key is wrong, AES-GCM tag verification fails → CryptoError: Decryption failed"

- timestamp: 2026-06-17
  checked: "packages/sdk/src/client.ts moveItem lines 696-756"
  found: "Calls sdkCore.moveItem (pure children shuffle) + updateFolderMetadataAndPublish for both folders. No call to resolveFileMetadata or updateFileMetadata."
  implication: "File metadata IPNS records are never touched during a move — confirmed missing re-encryption"

- timestamp: 2026-06-17
  checked: "apps/web/src/components/file-browser/useFileBrowserActions.ts line 372-377"
  found: "handleDownload passes currentFolder?.folderKey (= destination folder key post-move) to downloadFromIpns"
  implication: "After move, the decrypt path uses dest.folderKey but the file was encrypted with source.folderKey → decryption fails"

- timestamp: 2026-06-17
  checked: "apps/web/src/hooks/useStreamingPreview.ts line 115"
  found: "resolveFileMetadata(item.fileMetaIpnsName, folderKey) — folderKey is the parent passed prop, which is currentFolder.folderKey post-move"
  implication: "Preview path fails for the same reason as download"

## Eliminated

- hypothesis: "Move regenerates or drops the fileKey / file-metadata IPNS key"
  evidence: "moveItem at packages/sdk/src/client.ts:704-708 calls sdkCore.moveItem which is a pure children-array operation; IPNS records are untouched"
  timestamp: 2026-06-17

- hypothesis: "Stale folderTree / sequence reconciliation (PRs #489/#494) causes wrong key to be used"
  evidence: "The folderKey is looked up from store node at runtime (currentFolder.folderKey); the issue is structural — wrong key not stale key"
  timestamp: 2026-06-17

## Resolution

- root_cause: "FileMetadata IPNS records are AES-256-GCM encrypted with the parent folder's folderKey at upload time. The moveItem operation only shuffled the FilePointer between folder metadata children arrays without re-encrypting the per-file IPNS record. After a move, the decrypt path (download/preview/edit) supplies the destination folder's key, which doesn't match the source key used for encryption → CryptoError: Decryption failed."

- fix: "Added file metadata re-encryption step inside CipherBoxClient.moveItem (packages/sdk/src/client.ts). After computing the moved item via sdkCore.moveItem, when the moved child is a FilePointer: (1) unwrap the file's IPNS private key from FilePointer.ipnsPrivateKeyEncrypted using the vault keypair, (2) resolve the current FileMetadata from IPNS using source.folderKey, (3) call sdkCore.updateFileMetadata with folderKey = dest.folderKey, createVersion = false, updates = {} to re-encrypt and publish the FileMetadata record under the destination folder key before the folder metadata publish."

- fix_extended: "The same re-parent class affects bin restore (restoreFromBin re-inserted the FilePointer without re-encrypting). Fixed restoreFromBin to re-encrypt when the restore target differs from the original parent. To handle the case where the original parent no longer exists (delete file, then delete its parent, then restore elsewhere), addToBin now captures the source folder's folderKey on the BinEntry (originalFolderKeyEncrypted, ECIES-wrapped for the vault); restoreFromBin uses it as the source key and falls back to the live folder tree for legacy entries. Batch move routes per-item through the fixed moveItem (covered). Folder move is unaffected (children keep the subfolder's own folderKey). Shared-folder move does not exist yet — captured as a todo with the re-encrypt requirement."

- verification: "sdk unit: client-move-reencrypt.test.ts (3) + bin.test.ts (15, incl. captured-key + legacy-fallback + skip-in-place + missing-parent-throw) green; core bin/schema tests green (196). Web e2e move-restore-content.spec.ts (3/3) passes against the local full stack — asserts decrypted CONTENT after a move into a subfolder and after delete-to-bin+restore (fresh decrypt via the text editor). Desktop e2e test-cross-client-sync.sh gained a move-content check via a fresh SDK read under the destination folderKey (verify-filepointer.mjs extended to traverse one subfolder level); runs in CI desktop-e2e.yml (FUSE), not validated locally."

- files_changed:
  - "packages/sdk/src/client.ts (moveItem re-encrypt + missing-key guard)"
  - "packages/sdk/src/bin/index.ts (restoreFromBin re-encrypt + addToBin key capture)"
  - "packages/core/src/bin/types.ts (BinEntry.originalFolderKeyEncrypted)"
  - "packages/core/src/bin/schema.ts (validate new field)"
  - "packages/sdk/src/__tests__/client-move-reencrypt.test.ts (new)"
  - "packages/sdk/src/__tests__/client-extended.test.ts (updated mocks)"
  - "packages/sdk/src/__tests__/bin.test.ts (re-encrypt tests)"
  - "packages/sdk-core/scripts/verify-filepointer.mjs (subfolder traversal)"
  - "tests/web-e2e/tests/move-restore-content.spec.ts (new)"
  - "tests/desktop-e2e/scripts/test-cross-client-sync.sh (move-content check)"
  - ".planning/todos/pending/2026-06-17-shared-folder-move-must-reencrypt-file-metadata.md (new)"
