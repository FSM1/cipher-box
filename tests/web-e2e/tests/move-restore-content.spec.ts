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
 * Regression: file content must survive re-parenting operations.
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
