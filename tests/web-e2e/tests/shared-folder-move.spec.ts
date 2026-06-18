import { test, expect, type Browser } from '@playwright/test';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  navigateToFiles,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';
import { SharedMoveDialogPage } from '../page-objects/file-browser/shared-move-dialog.page';
import { TextEditorDialogPage } from '../page-objects/dialogs/text-editor-dialog.page';

/**
 * Regression: intra-share file move must keep file content decryptable for the
 * recipient AND the owner after cross-client sync.
 *
 * A file's FileMetadata IPNS record is AES-256-GCM sealed with its parent
 * folder's folderKey. Moving a file between two subfolders within a shared
 * folder tree without re-encrypting the record would make every subsequent
 * preview/edit/download fail with "CryptoError: Decryption failed"
 * (T-49-03/T-49-14).
 *
 * This spec asserts the DECRYPTED content is intact for both Bob (recipient,
 * who performs the move) and Alice (owner, who reads it after IPNS propagation).
 * Content is read back via the TextEditorDialog decrypt-on-read path (getContent)
 * — list-row visibility alone is NOT accepted as proof of correctness.
 *
 * Infra: requires local docker stack (docker compose -f docker/docker-compose.yml up -d).
 * Playwright auto-starts api :3000 + web :5173. Runs on push to main / manual dispatch.
 */
test.describe.serial('Shared-folder intra-share move (decrypt-survival)', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let bob: WalletTestAccount;

  // Page objects
  let aliceFileList: FileListPage;
  let aliceUploadZone: UploadZonePage;
  let aliceContextMenu: ContextMenuPage;
  let aliceCreateFolderDialog: CreateFolderDialogPage;
  let aliceShareDialog: ShareDialogPage;
  let aliceTextEditor: TextEditorDialogPage;

  let bobSharedBrowser: SharedFileBrowserPage;
  let bobContextMenu: ContextMenuPage;
  let bobSharedMoveDialog: SharedMoveDialogPage;
  let bobTextEditor: TextEditorDialogPage;

  // Unique per run to avoid state pollution between runs
  const runId = Date.now().toString(36).toLowerCase();
  const parentFolderName = `shared-move-parent-${runId}`;
  const subfolderName = `shared-move-dest-${runId}`;
  const fileName = `shared-move-file-${runId}.txt`;
  const fileContent = `shared-move integrity ${runId} — content line A\nsecond line B`;

  function truncateKey(key: string): string {
    const hex = key.startsWith('0x') ? key.slice(2) : key;
    return `0x${hex.slice(0, 4)}...${hex.slice(-4)}`;
  }

  // ============================================
  // Helper: read file content via TextEditor
  // Exercises the decrypt-on-read path (not mere list visibility).
  // Mirrors move-restore-content.spec.ts readContentViaEditor.
  // ============================================

  async function readContentViaEditor(
    page: SharedFileBrowserPage | FileListPage,
    contextMenu: ContextMenuPage,
    textEditor: TextEditorDialogPage,
    name: string
  ): Promise<string> {
    if (page instanceof SharedFileBrowserPage) {
      await page.rightClickFolderItem(name);
    } else {
      await page.rightClickItem(name);
    }
    await contextMenu.waitForOpen();
    await contextMenu.clickEdit();
    await textEditor.waitForOpen({ timeout: 10_000 });
    await textEditor.waitForContentLoaded({ timeout: 30_000 });
    const content = await textEditor.getContent();
    await textEditor.clickCancel();
    await textEditor.waitForClose();
    return content;
  }

  // ============================================
  // Setup and Teardown
  // ============================================

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (alice || bob) {
      await closeWalletTestAccounts([alice, bob].filter(Boolean));
    }
  });

  // ============================================
  // Phase 1: Account setup
  // ============================================

  test('1.1 Create Alice and Bob test accounts', async () => {
    test.setTimeout(300_000);

    alice = await createWalletTestAccount(browser, 'alice');
    bob = await createWalletTestAccount(browser, 'bob');

    aliceFileList = new FileListPage(alice.page);
    aliceUploadZone = new UploadZonePage(alice.page);
    aliceContextMenu = new ContextMenuPage(alice.page);
    aliceCreateFolderDialog = new CreateFolderDialogPage(alice.page);
    aliceShareDialog = new ShareDialogPage(alice.page);
    aliceTextEditor = new TextEditorDialogPage(alice.page);

    bobSharedBrowser = new SharedFileBrowserPage(bob.page);
    bobContextMenu = new ContextMenuPage(bob.page);
    bobSharedMoveDialog = new SharedMoveDialogPage(bob.page);
    bobTextEditor = new TextEditorDialogPage(bob.page);

    expect(alice.publicKey).not.toBe(bob.publicKey);
  });

  // ============================================
  // Phase 2: Alice sets up the shared folder
  // ============================================

  test('2.1 Alice creates parent folder with a subfolder and a text file', async () => {
    test.setTimeout(120_000);

    await navigateToFiles(alice);

    // Create parent folder
    await alice.page.locator('.file-browser-new-folder-button').click();
    await aliceCreateFolderDialog.waitForOpen();
    await aliceCreateFolderDialog.createFolder(parentFolderName);
    await aliceFileList.waitForItemToAppear(parentFolderName, { timeout: 30_000 });

    // Navigate into parent folder
    await aliceFileList.doubleClickFolder(parentFolderName);
    await alice.page
      .locator('.breadcrumb-item', { hasText: parentFolderName.toLowerCase() })
      .waitFor({ state: 'visible', timeout: 15_000 });

    // Create destination subfolder (distinct folderKey from parent)
    await alice.page.locator('.file-browser-new-folder-button').click();
    await aliceCreateFolderDialog.waitForOpen();
    await aliceCreateFolderDialog.createFolder(subfolderName);
    await aliceFileList.waitForItemToAppear(subfolderName, { timeout: 30_000 });

    // Upload the text file that Bob will move
    const testFile = createTestTextFile(fileName, fileContent);
    await aliceUploadZone.uploadFile(testFile.path);
    await aliceFileList.waitForItemToAppear(fileName, { timeout: 30_000 });

    // Verify content decrypts correctly for Alice BEFORE the move (sanity)
    expect(
      await readContentViaEditor(aliceFileList, aliceContextMenu, aliceTextEditor, fileName)
    ).toBe(fileContent);
  });

  test('2.2 Alice shares parent folder with Bob with READ-WRITE permission', async () => {
    test.setTimeout(120_000);

    // Navigate back to files root
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(parentFolderName, { timeout: 15_000 });

    // Open share dialog
    await aliceFileList.rightClickItem(parentFolderName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
    await aliceShareDialog.waitForRecipientsLoaded();

    // Select write permission
    const writeBtn = alice.page.locator('.share-perm-btn', { hasText: '[ READ-WRITE ]' });
    await writeBtn.click();
    await expect(writeBtn).toHaveClass(/share-perm-btn--active/);

    // Share with Bob
    await aliceShareDialog.shareWithKey(bob.publicKey);
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 60_000 });
    expect(successText).toContain(truncateKey(bob.publicKey));
    expect(successText).toContain('read-write');

    await aliceShareDialog.close();
  });

  // ============================================
  // Phase 3: Bob moves the file via SharedMoveDialog
  // ============================================

  test('3.1 Bob sees the shared folder with [RW] badge', async () => {
    test.setTimeout(60_000);

    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30_000 });
    await bobSharedBrowser.waitForSharedItem(parentFolderName, { timeout: 15_000 });

    const rwBadge = bobSharedBrowser.getSharedItem(parentFolderName).locator('.shared-rw-badge');
    await expect(rwBadge).toBeVisible();
    await expect(rwBadge).toContainText('[RW]');
  });

  test('3.2 Bob navigates into the shared parent folder and sees the file and subfolder', async () => {
    test.setTimeout(60_000);

    await bobSharedBrowser.navigateIntoFolder(parentFolderName);

    const itemNames = await bobSharedBrowser.getFolderItemNames();
    expect(itemNames).toContain(fileName);
    expect(itemNames).toContain(subfolderName);
  });

  test('3.3 Bob moves the file into the subfolder via SharedMoveDialog', async () => {
    test.setTimeout(120_000);

    // Right-click the file to open context menu
    await bobSharedBrowser.rightClickFolderItem(fileName);
    await bobContextMenu.waitForOpen();

    // Click "Move to..." — wired only for files in folder-view (plan 49-03)
    await bobContextMenu.clickMove();

    // Wait for the SharedMoveDialog to open and the subtree to load
    await bobSharedMoveDialog.waitForOpen({ timeout: 10_000 });
    await bobSharedMoveDialog.waitForTreeLoaded({ timeout: 30_000 });

    // Verify the destination subfolder is available
    const folderNames = await bobSharedMoveDialog.getVisibleFolderNames();
    expect(folderNames).toContain(subfolderName);

    // Select the subfolder and confirm
    await bobSharedMoveDialog.selectFolder(subfolderName);
    expect(await bobSharedMoveDialog.isFolderSelected(subfolderName)).toBe(true);
    expect(await bobSharedMoveDialog.isMoveDisabled()).toBe(false);

    await bobSharedMoveDialog.clickMove();

    // Dialog should close as the move is processed
    await bobSharedMoveDialog.waitForClose({ timeout: 30_000 });
  });

  // ============================================
  // Phase 4: Assert decrypt-survival for Bob
  // ============================================

  test('4.1 File disappears from source (parent folder) in Bob view', async () => {
    test.setTimeout(60_000);

    // The file should no longer appear in the parent folder view
    await bobSharedBrowser.getFolderItem(fileName).waitFor({ state: 'hidden', timeout: 30_000 });
  });

  test('4.2 Bob navigates into the subfolder and the file appears there', async () => {
    test.setTimeout(60_000);

    await bobSharedBrowser.navigateIntoSubfolder(subfolderName);
    await bobSharedBrowser.getFolderItem(fileName).waitFor({ state: 'visible', timeout: 30_000 });
  });

  test('4.3 Bob reads the file via TextEditor — content decrypts correctly (decrypt-on-read)', async () => {
    test.setTimeout(60_000);

    // This is the core decrypt-survival assertion for the recipient.
    // readContentViaEditor drives: right-click → Edit → waitForContentLoaded → getContent.
    // It exercises the real decrypt-on-read path (FileMetadata re-sealed under dest folderKey).
    // Mere list visibility is NOT sufficient — the bug only surfaces on preview/edit/download.
    const bobDecrypted = await readContentViaEditor(
      bobSharedBrowser,
      bobContextMenu,
      bobTextEditor,
      fileName
    );
    expect(bobDecrypted).toBe(fileContent);
  });

  // ============================================
  // Phase 5: Assert decrypt-survival for Alice (owner)
  // ============================================

  test('5.1 Alice reloads and navigates into the subfolder to verify decrypted content', async () => {
    test.setTimeout(120_000);

    // Cross-client sync: reload Alice's page to pick up Bob's IPNS publish.
    await navigateToFiles(alice);
    await alice.page.reload({ waitUntil: 'networkidle' });

    // Navigate into parent → subfolder on Alice's private-vault file browser
    await aliceFileList.waitForItemToAppear(parentFolderName, { timeout: 30_000 });
    await aliceFileList.doubleClickFolder(parentFolderName);
    await alice.page
      .locator('.breadcrumb-item', { hasText: parentFolderName.toLowerCase() })
      .waitFor({ state: 'visible', timeout: 15_000 });

    // Subfolder should be present (pre-existed from phase 2)
    await aliceFileList.waitForItemToAppear(subfolderName, { timeout: 30_000 });
    await aliceFileList.doubleClickFolder(subfolderName);
    await alice.page
      .locator('.breadcrumb-item', { hasText: subfolderName.toLowerCase() })
      .waitFor({ state: 'visible', timeout: 15_000 });

    // File should now appear in the subfolder (IPNS propagation)
    await aliceFileList.waitForItemToAppear(fileName, { timeout: 60_000 });

    // Decrypt-survival assertion for the owner — same TextEditor path.
    // Alice must be able to decrypt the file after Bob's re-keying move.
    const aliceDecrypted = await readContentViaEditor(
      aliceFileList,
      aliceContextMenu,
      aliceTextEditor,
      fileName
    );
    expect(aliceDecrypted).toBe(fileContent);
  });
});
