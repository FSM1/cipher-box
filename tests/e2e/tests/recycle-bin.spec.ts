import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { loginViaEmail, loginViaTestEndpoint, TEST_CREDENTIALS } from '../utils/web3auth-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { BinPage } from '../page-objects/pages/bin.page';

/**
 * Recycle Bin E2E Test Suite
 *
 * Verifies the full recycle bin lifecycle end-to-end:
 * 1. Delete a file from the file browser -> file moves to bin
 * 2. Navigate to the bin -> deleted file is visible with metadata
 * 3. Restore a file from the bin -> file reappears in file browser
 * 4. Permanently delete a file from the bin -> file is gone forever
 * 5. Empty the bin -> all items removed
 * 6. Sidebar navigation to bin works
 *
 * Depends on:
 * - Plan 17-01: Bin crypto primitives (HKDF derivation, ECIES encrypt/decrypt)
 * - Plan 17-02: Bin store and API integration
 * - Plan 17-03: Bin UI components (BinBrowser, BinListItem, BinEmptyState)
 */
test.describe.serial('Recycle Bin', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  // Page objects
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  let confirmDialog: ConfirmDialogPage;
  let binPage: BinPage;

  // Unique suffix per test run to avoid naming collisions
  const runId = Date.now().toString();

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    // Initialize page objects
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    contextMenu = new ContextMenuPage(page);
    confirmDialog = new ConfirmDialogPage(page);
    binPage = new BinPage(page);

    // Login using test-login endpoint (bypasses Core Kit, decouples from Web3Auth)
    if (process.env.TEST_LOGIN_SECRET) {
      await loginViaTestEndpoint(page, TEST_CREDENTIALS.email);
    } else {
      await loginViaEmail(page, TEST_CREDENTIALS.email);
    }

    // Verify we're on the files page
    await page.waitForURL('**/files', { timeout: 60000 });
    await Promise.race([
      fileList.fileListContainer().waitFor({ state: 'visible', timeout: 30000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30000 }),
    ]);
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (context) {
      await context.close();
    }
  });

  // ============================================================
  // Helper: Navigate back to files from bin
  // ============================================================

  async function navigateToFiles(): Promise<void> {
    // Click the "My Files" nav item to go back to file browser
    await page.getByTestId('nav-item-files').click();
    await page.waitForURL('**/files', { timeout: 15000 });
  }

  // ============================================================
  // TC01: Delete file moves to bin
  // ============================================================

  test('TC01: delete file moves it to bin', async () => {
    test.slow(); // Allow time for IPNS publish cycles

    const fileName = `bin-delete-${runId}.txt`;

    // Upload a test file
    const testFile = createTestTextFile(fileName, `Bin delete test - ${runId}`);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });

    // Delete the file via context menu
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();

    // Wait for file to disappear from file list
    await fileList.waitForItemToDisappear(fileName, { timeout: 30000 });

    // Navigate to bin
    await binPage.navigate();

    // Verify the deleted file appears in the bin
    await binPage.waitForBinItem(fileName, { timeout: 30000 });
    const binItem = binPage.getBinItemByName(fileName);
    await expect(binItem).toBeVisible();
  });

  // ============================================================
  // TC02: Restore file from bin
  // ============================================================

  test('TC02: restore file from bin back to files', async () => {
    test.slow(); // Allow time for restore + IPNS publish

    const fileName = `bin-restore-${runId}.txt`;

    // Navigate to files and upload a test file
    await navigateToFiles();
    const testFile = createTestTextFile(fileName, `Bin restore test - ${runId}`);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });

    // Delete the file
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileName, { timeout: 30000 });

    // Navigate to bin
    await binPage.navigate();
    await binPage.waitForBinItem(fileName, { timeout: 30000 });

    // Restore via context menu
    await binPage.restoreItem(fileName);

    // Wait for item to disappear from bin
    await binPage.waitForBinItemToDisappear(fileName, { timeout: 30000 });

    // Navigate back to files and verify file is restored
    await navigateToFiles();
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });
    const isVisible = await fileList.isItemVisible(fileName);
    expect(isVisible).toBe(true);

    // Cleanup: delete file permanently
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileName, { timeout: 30000 });
  });

  // ============================================================
  // TC03: Permanently delete from bin
  // ============================================================

  test('TC03: permanently delete item from bin', async () => {
    test.slow();

    const fileName = `bin-perma-${runId}.txt`;

    // Upload and delete a file to put it in the bin
    await navigateToFiles();
    const testFile = createTestTextFile(fileName, `Permanent delete test - ${runId}`);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });

    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileName, { timeout: 30000 });

    // Navigate to bin
    await binPage.navigate();
    await binPage.waitForBinItem(fileName, { timeout: 30000 });

    // Permanently delete
    await binPage.permanentlyDeleteItem(fileName);

    // Verify item is gone from bin
    await binPage.waitForBinItemToDisappear(fileName, { timeout: 30000 });
  });

  // ============================================================
  // TC04: Empty bin removes all items
  // ============================================================

  test('TC04: empty bin removes all items', async () => {
    test.slow();

    const fileA = `bin-empty-a-${runId}.txt`;
    const fileB = `bin-empty-b-${runId}.txt`;

    // Upload and delete two files
    await navigateToFiles();

    const testFileA = createTestTextFile(fileA, `Empty bin test A - ${runId}`);
    await uploadZone.uploadFile(testFileA.path);
    await fileList.waitForItemToAppear(fileA, { timeout: 60000 });

    const testFileB = createTestTextFile(fileB, `Empty bin test B - ${runId}`);
    await uploadZone.uploadFile(testFileB.path);
    await fileList.waitForItemToAppear(fileB, { timeout: 60000 });

    // Delete both files
    await fileList.rightClickItem(fileA);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileA, { timeout: 30000 });

    await fileList.rightClickItem(fileB);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileB, { timeout: 30000 });

    // Navigate to bin, verify both are present
    await binPage.navigate();
    await binPage.waitForBinItem(fileA, { timeout: 30000 });
    await binPage.waitForBinItem(fileB, { timeout: 30000 });

    // Empty the bin
    await binPage.emptyBin();

    // Verify bin is now empty
    await binPage.emptyState().waitFor({ state: 'visible', timeout: 30000 });
  });

  // ============================================================
  // TC05: Bin item shows metadata
  // ============================================================

  test('TC05: bin item displays metadata (name, time remaining)', async () => {
    test.slow();

    const fileName = `bin-meta-${runId}.txt`;

    // Upload and delete a file
    await navigateToFiles();
    const testFile = createTestTextFile(fileName, `Metadata display test - ${runId}`);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });

    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await fileList.waitForItemToDisappear(fileName, { timeout: 30000 });

    // Navigate to bin
    await binPage.navigate();
    await binPage.waitForBinItem(fileName, { timeout: 30000 });

    // Verify the item shows its name
    const binItem = binPage.getBinItemByName(fileName);
    await expect(binItem).toContainText(fileName);

    // Verify time remaining is displayed (e.g., "30d", "29d", "< 1 day")
    // The remaining text is in a .bin-list-item-remaining cell
    const remainingCell = binItem.locator('.bin-list-item-remaining');
    await expect(remainingCell).toBeVisible();
    const remainingText = await remainingCell.textContent();
    // Should contain a day indicator (Xd or "< 1 day" or "expired")
    expect(remainingText).toMatch(/\d+d|< 1 day|expired/);

    // Cleanup: permanently delete the item
    await binPage.permanentlyDeleteItem(fileName);
    await binPage.waitForBinItemToDisappear(fileName, { timeout: 30000 });
  });

  // ============================================================
  // TC06: Bin sidebar navigation works
  // ============================================================

  test('TC06: sidebar navigation to bin page works', async () => {
    // Navigate to bin via sidebar
    await binPage.navigate();

    // Verify URL contains #/bin
    expect(page.url()).toContain('#/bin');

    // Verify we see either the bin list or the empty state
    const hasList = await binPage
      .binList()
      .isVisible()
      .catch(() => false);
    const hasEmpty = await binPage
      .emptyState()
      .isVisible()
      .catch(() => false);
    expect(hasList || hasEmpty).toBe(true);
  });
});
