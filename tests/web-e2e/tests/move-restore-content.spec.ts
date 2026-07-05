import { test, expect, type Browser } from '@playwright/test';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToFiles,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { MoveDialogPage } from '../page-objects/dialogs/move-dialog.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { TextEditorDialogPage } from '../page-objects/dialogs/text-editor-dialog.page';
import { BinPage } from '../page-objects/pages/bin.page';

/**
 * Regression: file content must survive re-parenting operations, and an
 * owned file must stay WRITE-CAPABLE (not just readable) after being moved.
 *
 * A file's FileMetadata IPNS record is AES-256-GCM encrypted with its parent
 * folder's folderKey. Moving a file to a subfolder (different folderKey) without
 * re-encrypting the record made every later preview/edit/download fail with
 * "CryptoError: Decryption failed" (fixed in CipherBoxClient.moveItem; the same
 * gap existed in restoreFromBin). These specs assert the DECRYPTED CONTENT is
 * intact — not just that the file is listed — after a move into a subfolder and
 * after a delete-to-bin + restore.
 *
 * Content is read back via the text editor dialog, which decrypts the file and
 * renders it in a textarea (getContent()) — i.e. it exercises the real
 * decrypt-on-read path that the bug broke.
 *
 * Test 2b (68.1-31) covers a SECOND, distinct live bug: moveItem re-linked the
 * read-plane SealedChildRef but left the moved file's WriteChildRef orphaned in
 * the SOURCE write-body, so the file stayed READABLE but became permanently
 * un-editable in its new location ("File ... is not write-capable (no
 * WriteChildRef)"). Test 2b edits and SAVES the file after each move (both
 * directions) to prove write-link re-homing, not just the read-plane re-seal.
 */
test.describe.serial('Move / restore preserves decrypted file content', () => {
  let browser: Browser;
  let alice: WalletTestAccount;

  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  let moveDialog: MoveDialogPage;
  let createFolderDialog: CreateFolderDialogPage;
  let confirmDialog: ConfirmDialogPage;
  let textEditor: TextEditorDialogPage;
  let binPage: BinPage;

  const runId = Date.now().toString(36).toLowerCase();
  const moveFileName = `move-content-${runId}.txt`;
  const moveContent = `move integrity ${runId} — line A\nsecond line B`;
  const subfolderName = `subfolder-${runId}`;
  const restoreFileName = `restore-content-${runId}.txt`;
  const restoreContent = `restore integrity ${runId} — payload`;

  async function createSubfolder(name: string): Promise<void> {
    await alice.page.locator('.file-browser-new-folder-button').click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(name);
    await fileList.waitForItemToAppear(name, { timeout: 30_000 });
  }

  async function openFolder(name: string): Promise<void> {
    await fileList.doubleClickFolder(name);
    await alice.page
      .locator('.breadcrumb-item', { hasText: name.toLowerCase() })
      .waitFor({ state: 'visible', timeout: 30_000 });
  }

  async function readContentViaEditor(name: string): Promise<string> {
    await fileList.rightClickItem(name);
    await contextMenu.waitForOpen();
    await contextMenu.clickEdit();
    await textEditor.waitForOpen({ timeout: 10_000 });
    await textEditor.waitForContentLoaded({ timeout: 30_000 });
    const content = await textEditor.getContent();
    await textEditor.clickCancel();
    await textEditor.waitForClose();
    return content;
  }

  /**
   * Edit a file's content and save, asserting the save SUCCEEDS (no
   * "not write-capable" / other error banner). This is the user's exact
   * repro path (68.1-31): open the editor via the context-menu Edit action,
   * type new content, and save. `clickSave()` races the dialog closing
   * (success -- TextEditorDialog.handleSave calls onClose()) against the
   * error banner becoming visible (failure -- handleSave sets `error` and
   * leaves the dialog open) so a real write-capability regression fails
   * with a clear assertion instead of an ambiguous 30s timeout.
   */
  async function editAndSaveViaEditor(name: string, newContent: string): Promise<void> {
    await fileList.rightClickItem(name);
    await contextMenu.waitForOpen();
    await contextMenu.clickEdit();
    await textEditor.waitForOpen({ timeout: 10_000 });
    await textEditor.waitForContentLoaded({ timeout: 30_000 });
    await textEditor.setContent(newContent);
    expect(await textEditor.isModified()).toBe(true);
    expect(await textEditor.isSaveDisabled()).toBe(false);

    await textEditor.clickSave();
    await Promise.race([
      textEditor.dialog().waitFor({ state: 'hidden', timeout: 30_000 }),
      textEditor.errorMessage().waitFor({ state: 'visible', timeout: 30_000 }),
    ]);

    if (await textEditor.hasError()) {
      throw new Error(`Save failed for "${name}": ${await textEditor.getErrorText()}`);
    }
    await textEditor.waitForClose({ timeout: 5_000 });
  }

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (alice) await closeWalletTestAccounts([alice]);
  });

  test('1. Create account', async () => {
    test.setTimeout(300_000);
    alice = await createWalletTestAccount(browser, 'alice');
    fileList = new FileListPage(alice.page);
    uploadZone = new UploadZonePage(alice.page);
    contextMenu = new ContextMenuPage(alice.page);
    moveDialog = new MoveDialogPage(alice.page);
    createFolderDialog = new CreateFolderDialogPage(alice.page);
    confirmDialog = new ConfirmDialogPage(alice.page);
    textEditor = new TextEditorDialogPage(alice.page);
    binPage = new BinPage(alice.page);
  });

  test('2. Content survives a move into a subfolder', async () => {
    test.setTimeout(120_000);
    await navigateToFiles(alice);

    // Sanity: content reads correctly at root BEFORE the move.
    const moveFile = createTestTextFile(moveFileName, moveContent);
    await uploadZone.uploadFile(moveFile.path);
    await fileList.waitForItemToAppear(moveFileName, { timeout: 30_000 });
    expect(await readContentViaEditor(moveFileName)).toBe(moveContent);

    // Create a destination subfolder (its own distinct folderKey).
    await createSubfolder(subfolderName);

    // Move the file into the subfolder.
    await fileList.rightClickItem(moveFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickMove();
    await moveDialog.waitForOpen();
    await moveDialog.selectFolder(subfolderName);
    await moveDialog.clickMove();
    await moveDialog.waitForClose({ timeout: 30_000 });
    await fileList.waitForItemToDisappear(moveFileName, { timeout: 30_000 });

    // Navigate into the subfolder and assert the DECRYPTED content is intact.
    await openFolder(subfolderName);
    await fileList.waitForItemToAppear(moveFileName, { timeout: 30_000 });
    expect(await readContentViaEditor(moveFileName)).toBe(moveContent);
  });

  test('2b. An owned file stays editable-and-savable after being moved into a subfolder (68.1-31 repro)', async () => {
    test.setTimeout(180_000);
    // Continues from test 2's state: currently inside `subfolderName`, viewing
    // `moveFileName` (moved but never edited there). This is the user's exact
    // repro -- edit and SAVE an owned file AFTER moving it into a subfolder.
    // Before the 68.1-31 fix, moveItem left the moved file's WriteChildRef
    // orphaned in the SOURCE (root) write-body, so this save failed with
    // "File ... is not write-capable (no WriteChildRef)".
    const editedInSubfolder = `${moveContent} — edited after move ${runId}`;
    await editAndSaveViaEditor(moveFileName, editedInSubfolder);

    // Re-open and confirm the edit actually persisted (not just "no error").
    expect(await readContentViaEditor(moveFileName)).toBe(editedInSubfolder);

    // Round-trip: move the file back to root and prove re-homing is
    // symmetric -- it must stay write-capable there too. Root is always
    // exposed in MoveDialog as "My Vault" regardless of current depth.
    await fileList.rightClickItem(moveFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickMove();
    await moveDialog.waitForOpen();
    await moveDialog.selectFolder('My Vault');
    await moveDialog.clickMove();
    await moveDialog.waitForClose({ timeout: 30_000 });
    await fileList.waitForItemToDisappear(moveFileName, { timeout: 30_000 });

    await navigateToFiles(alice);
    await fileList.waitForItemToAppear(moveFileName, { timeout: 30_000 });
    expect(await readContentViaEditor(moveFileName)).toBe(editedInSubfolder);

    const editedAtRoot = `${editedInSubfolder} — edited after move-back ${runId}`;
    await editAndSaveViaEditor(moveFileName, editedAtRoot);
    expect(await readContentViaEditor(moveFileName)).toBe(editedAtRoot);
  });

  test('3. Content survives delete-to-bin then restore', async () => {
    test.setTimeout(120_000);
    await navigateToFiles(alice);

    const restoreFile = createTestTextFile(restoreFileName, restoreContent);
    await uploadZone.uploadFile(restoreFile.path);
    await fileList.waitForItemToAppear(restoreFileName, { timeout: 30_000 });

    // Delete to bin.
    await fileList.rightClickItem(restoreFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(restoreFileName, { timeout: 30_000 });

    // Restore from bin (returns to its original parent — root here).
    await binPage.navigate();
    await binPage.waitForBinItem(restoreFileName, { timeout: 30_000 });
    await binPage.restoreItem(restoreFileName);
    await binPage.waitForBinItemToDisappear(restoreFileName, { timeout: 30_000 });

    // Back to files; assert the DECRYPTED content is intact after restore.
    await navigateToFiles(alice);
    await fileList.waitForItemToAppear(restoreFileName, { timeout: 60_000 });
    expect(await readContentViaEditor(restoreFileName)).toBe(restoreContent);
  });
});
