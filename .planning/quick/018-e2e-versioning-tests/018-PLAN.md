---
phase: quick
plan: 018
type: execute
wave: 1
depends_on: []
files_modified:
  - tests/e2e/page-objects/dialogs/details-dialog.page.ts
  - tests/e2e/tests/full-workflow.spec.ts
autonomous: true

must_haves:
  truths:
    - 'Version history section appears in Details dialog after a text editor save'
    - 'Restoring a past version swaps current content with restored version'
    - 'Deleting a version removes it from the version list'
  artifacts:
    - path: 'tests/e2e/page-objects/dialogs/details-dialog.page.ts'
      provides: 'Version history page object methods'
    - path: 'tests/e2e/tests/full-workflow.spec.ts'
      provides: 'Versioning E2E test cases'
  key_links:
    - from: 'tests/e2e/tests/full-workflow.spec.ts'
      to: 'tests/e2e/page-objects/dialogs/details-dialog.page.ts'
      via: 'detailsDialog version methods'
      pattern: "detailsDialog\\.(getVersionCount|clickVersionRestore|clickVersionDelete)"
---

<objective>
Add E2E tests covering the file versioning feature (Phase 13) to the existing full-workflow test suite.

Purpose: Verify that version history creation, display, restore, and delete work end-to-end through the UI.
Output: Extended DetailsDialogPage page object + new test cases in full-workflow.spec.ts
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@tests/e2e/tests/full-workflow.spec.ts
@tests/e2e/page-objects/dialogs/details-dialog.page.ts
@apps/web/src/components/file-browser/DetailsDialog.tsx
@apps/web/src/styles/details-dialog.css
</context>

<tasks>

<task type="auto">
  <name>Task 1: Extend DetailsDialogPage with version history methods</name>
  <files>tests/e2e/page-objects/dialogs/details-dialog.page.ts</files>
  <action>
Add the following methods to the existing DetailsDialogPage class for interacting with the version history section in the Details dialog.

Locators to add:

- `versionSection()` -> `.details-version-section` within dialog
- `versionEntries()` -> `.details-version-entry` within version section
- `versionEntry(index: number)` -> nth version entry (0-based, where 0 = newest displayed)
- `versionNumber(index: number)` -> `.details-version-number` within entry
- `versionActions(index: number)` -> `.details-version-actions` within entry
- `versionDownloadBtn(index: number)` -> button with aria-label matching `Download version`
- `versionRestoreBtn(index: number)` -> button with aria-label matching `Restore version`
- `versionDeleteBtn(index: number)` -> button with aria-label matching `Delete version`
- `versionConfirm()` -> `.details-version-confirm` within dialog
- `versionConfirmYes()` -> `.details-version-confirm-btn--yes` within confirm
- `versionConfirmNo()` -> `.details-version-confirm-btn--no` within confirm
- `versionError()` -> `.details-version-error` within dialog

Methods to add:

- `async isVersionSectionVisible(): Promise<boolean>` - checks if version history section exists
- `async getVersionCount(): Promise<number>` - count of `.details-version-entry` elements
- `async getVersionNumberText(index: number): Promise<string>` - e.g. "v1", "v2"
- `async getVersionSizeText(index: number): Promise<string>` - text of `.details-version-size` in entry
- `async clickVersionDownload(index: number): Promise<void>` - click dl button
- `async clickVersionRestore(index: number): Promise<void>` - click restore button (opens inline confirm)
- `async clickVersionDelete(index: number): Promise<void>` - click rm button (opens inline confirm)
- `async isVersionConfirmVisible(): Promise<boolean>` - whether inline confirm is showing
- `async confirmVersionAction(): Promise<void>` - click the confirm button in inline confirm
- `async cancelVersionAction(): Promise<void>` - click the cancel button in inline confirm
- `async getVersionErrorText(): Promise<string | null>` - get error text if visible, null otherwise
- `async waitForVersionSection(options?: { timeout?: number }): Promise<void>` - wait for version section to appear

Follow the existing patterns in the class: use `this.dialog()` as the root scope for all locators. Use `this.page.locator(...)` for nested queries.
</action>
<verify>
Run `npx tsc --noEmit -p tests/e2e/tsconfig.json` (or equivalent) to verify the page object compiles. If no tsconfig exists for e2e, just verify the file has no obvious syntax errors by reading it back.
</verify>
<done>DetailsDialogPage has all version history locators and interaction methods needed by Task 2.</done>
</task>

<task type="auto">
  <name>Task 2: Add versioning test cases to full-workflow.spec.ts</name>
  <files>tests/e2e/tests/full-workflow.spec.ts</files>
  <action>
Insert a new test section between the existing Phase 6.5 text editor tests and Phase 7 rename tests. The section header comment should be:

```typescript
// ============================================
// Phase 6.6: File Versioning (Version History)
// ============================================
```

Important context for the tests:

- After test 6.5.3, the editable file (`editableFileName`) has been edited via text editor. That edit triggered `updateFile` which calls `shouldCreateVersion`. Since no prior versions existed, the first version IS created (the original content before the edit becomes v1 in the versions array).
- The test cursor is at root level after 6.5.5.
- The editable file content is `textEditorEditedContent` (current) with v1 being the previous content (`editableFileUpdatedContent`).
- After 6.5.4 the CID changed, confirming the edit and re-encryption.
- The 15-minute version cooldown prevents creating additional versions within the same test run. All tests work with the single v1 version created by the text editor save in 6.5.3.

Test 6.6.1 -- Version history visible in Details dialog:

1. We are at root. Right-click `editableFileName`, open Details.
2. Wait for the dialog to open and file metadata to resolve (the `fileMetaLoading` state). Wait for the version section to become visible using `detailsDialog.waitForVersionSection({ timeout: 30000 })`.
3. Assert `detailsDialog.isVersionSectionVisible()` is true.
4. Assert `detailsDialog.getVersionCount()` is 1 (one past version created by the text editor save in 6.5.3).
5. Assert `detailsDialog.getVersionNumberText(0)` is "v1".
6. Assert the section header `// version history` is present in `detailsDialog.getVisibleSectionHeaders()`.
7. Close the dialog.

Test 6.6.2 -- Restore a past version:

1. Set `test.setTimeout(60000)` (restore involves IPNS publish).
2. Right-click `editableFileName`, open Details.
3. Wait for version section to appear.
4. Click restore on version entry index 0 (the only version, v1).
5. Assert `detailsDialog.isVersionConfirmVisible()` is true.
6. Click confirm (`detailsDialog.confirmVersionAction()`).
7. Wait for the version section to refresh. After restore, the OLD current content (which was `textEditorEditedContent`) becomes v1, and the restored content is now current. So the version count should still be 1 (restored version is removed from list, previous current becomes new v1).
8. Close the details dialog.
9. Verify the restore worked by opening text editor: right-click `editableFileName`, click Edit, wait for content to load. The content should now be `editableFileUpdatedContent` (the pre-6.5.3 content that was versioned).
10. Close text editor without saving (`textEditorDialog.clickCancel()`).

Test 6.6.3 -- Delete a past version:

1. Set `test.setTimeout(60000)`.
2. Right-click `editableFileName`, open Details.
3. Wait for version section (should show v1 = the content that was current before the restore, i.e. `textEditorEditedContent`).
4. Assert version count is 1.
5. Click delete on version entry index 0.
6. Assert `detailsDialog.isVersionConfirmVisible()` is true.
7. Click confirm.
8. After deletion, wait for the version section to disappear (since count is now 0, the VersionHistory component only renders when `versions.length > 0`). Use Playwright retry pattern: `expect(async () => { expect(await detailsDialog.isVersionSectionVisible()).toBe(false); }).toPass({ timeout: 15000 })`.
9. Close the details dialog.

IMPORTANT: After these tests, the editable file content is `editableFileUpdatedContent` (restored in 6.6.2). The existing test 6.5.5 re-opens the editor to check content is `textEditorEditedContent`. Since the new tests run AFTER 6.5.5, this is fine. The cleanup tests in Phase 8 still work because they just delete the file by name, which is unchanged.
</action>
<verify>

1. Run TypeScript check from the e2e directory to verify compilation without errors.
2. Visual inspection: The new tests 6.6.1, 6.6.2, 6.6.3 are inserted between test 6.5.5 and test 7.1 in the serial test suite.
3. The test file imports have not been modified (DetailsDialogPage was already imported).
   </verify>
   <done>
   Three new serial test cases (6.6.1, 6.6.2, 6.6.3) exist in full-workflow.spec.ts covering:

- Version history section visibility and version count after text editor save
- Restoring a past version via the Details dialog inline confirm UI
- Deleting a past version via the Details dialog inline confirm UI
  </done>
  </task>

</tasks>

<verification>

1. TypeScript compilation passes for both modified files
2. New tests are correctly positioned in serial order (after 6.5.5, before 7.1)
3. DetailsDialogPage has all methods needed by the tests
4. No existing tests are broken by the additions

</verification>

<success_criteria>

- DetailsDialogPage extended with version history locators and interaction methods
- 3 new test cases cover: version history display, version restore, version delete
- Tests use existing test fixtures (editableFileName from the full-workflow suite)
- No modifications to existing tests
- TypeScript compiles cleanly

</success_criteria>

<output>
After completion, create `.planning/quick/018-e2e-versioning-tests/018-SUMMARY.md`
</output>
