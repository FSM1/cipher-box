import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { BinPage } from '../page-objects/pages/bin.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';

/**
 * Recycle Bin: restore-after-reload regression
 *
 * Reproduces the "Target folder not loaded" bug class: restoring a bin item
 * whose original parent is a SUBFOLDER that was never navigated to in the
 * current session. After a reload only the root folder is re-seeded into the
 * SDK folderTree, so the subfolder's keys are absent — pre-fix, restoreFromBin
 * threw 'Target folder not loaded'.
 *
 * The fix gives the SDK client the root IPNS keypair so it can self-bootstrap:
 * client.restoreFromBin → ensureFolderLoaded walks from root, unwraps the
 * subfolder's keys, and loads it before republishing the parent.
 *
 * The existing recycle-bin.spec.ts misses this because it uploads in-session
 * (parent already loaded) and never reloads. This spec lives on its own with
 * its own login so nothing pre-seeds the subfolder into folderTree.
 */
test.describe.serial('Recycle Bin: restore after reload (subfolder parent)', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  let confirmDialog: ConfirmDialogPage;
  let binPage: BinPage;
  let createFolderDialog: CreateFolderDialogPage;

  let account: PrivateKeyAccount;

  test.beforeAll(async ({ browser: testBrowser }) => {
    test.setTimeout(90_000); // Core Kit init + SIWE can be slow
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    account = createTestAccount();
    await setupMockWallet(page, account);

    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    contextMenu = new ContextMenuPage(page);
    confirmDialog = new ConfirmDialogPage(page);
    binPage = new BinPage(page);
    createFolderDialog = new CreateFolderDialogPage(page);

    await loginViaWallet(page, { timeout: 60_000 });
    await page.waitForURL('**/files', { timeout: 60000 });
    await Promise.race([
      fileList.fileListContainer().waitFor({ state: 'visible', timeout: 30000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30000 }),
    ]);
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (page) {
      await deleteAccountViaPage(page);
    }
    if (context) {
      await context.close();
    }
  });

  test('restores a subfolder item after reload without navigating into the subfolder', async () => {
    test.slow(); // folder create + upload + delete + reload + restore IPNS cycles

    const runId = Date.now().toString();
    const subfolderName = `reload-sub-${runId}`;
    const fileName = `reload-restore-${runId}.txt`;

    // 1. Create a subfolder under root.
    await page.locator('.file-browser-new-folder-button').click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(subfolderName);
    await fileList.waitForItemToAppear(subfolderName, { timeout: 30000 });

    // 2. Navigate into it (empty-state confirms we are inside the new folder).
    await fileList.doubleClickFolder(subfolderName);
    await page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30000 });

    // 3. Upload a file into the subfolder.
    const testFile = createTestTextFile(fileName, `restore-after-reload ${runId}`);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });

    // 4. Delete it → moves to the recycle bin (originalParent = subfolder).
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileName, { timeout: 30000 });

    // 5. Reload — wipes Zustand store AND the SDK folderTree. Only root is
    //    re-seeded on session restore; the subfolder is NOT loaded.
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.locator('[data-testid="user-menu"]').waitFor({ state: 'visible', timeout: 120000 }); // session auto-restore

    // 6. Go straight to the bin WITHOUT navigating into the subfolder, so the
    //    subfolder's keys are absent from folderTree at restore time.
    await binPage.navigate();
    await binPage.waitForBinItem(fileName, { timeout: 30000 });

    // 7. Restore. Pre-fix this throws 'Target folder not loaded'; post-fix the
    //    SDK self-bootstraps the subfolder from root and succeeds.
    await binPage.restoreItem(fileName);
    await binPage.waitForBinItemToDisappear(fileName, { timeout: 60000 });

    // 8. Verify the file is restored back into the subfolder.
    await page.getByTestId('nav-item-files').click();
    await page.waitForURL('**/files', { timeout: 15000 });
    await fileList.waitForItemToAppear(subfolderName, { timeout: 30000 });
    await fileList.doubleClickFolder(subfolderName);
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });
    expect(await fileList.isItemVisible(fileName)).toBe(true);
  });
});
