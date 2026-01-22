import { test, expect, Page, Browser, BrowserContext } from '@playwright/test';
import { loginViaEmail, TEST_CREDENTIALS } from '../utils/web3auth-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { RenameDialogPage } from '../page-objects/dialogs/rename-dialog.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';

/**
 * Full Workflow E2E Test Suite
 *
 * Single sequential test session that:
 * 1. Logs in once via Web3Auth
 * 2. Performs all file/folder operations
 * 3. Cleans up and logs out
 *
 * This approach eliminates session expiry issues from storage-state-based tests.
 */
test.describe.serial('Full Workflow', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  // Page objects (initialized after login)
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  let renameDialog: RenameDialogPage;
  let confirmDialog: ConfirmDialogPage;

  // Track created items for cleanup
  const createdFiles: string[] = [];
  // const createdFolders: string[] = []; // TODO: Enable when folder tests are implemented

  // Test data
  const testFileName = `test-file-${Date.now()}.txt`;
  const renamedFileName = `renamed-file-${Date.now()}.txt`;

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    // Initialize page objects
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    contextMenu = new ContextMenuPage(page);
    renameDialog = new RenameDialogPage(page);
    confirmDialog = new ConfirmDialogPage(page);
  });

  test.afterAll(async () => {
    // Cleanup test files from filesystem
    cleanupTestFiles();

    // Close context
    if (context) {
      await context.close();
    }
  });

  // ============================================
  // Phase 1: Login
  // ============================================

  test('1.1 Login with Web3Auth credentials', async () => {
    // Verify test credentials are configured
    expect(TEST_CREDENTIALS.email, 'WEB3AUTH_TEST_EMAIL must be set').toBeTruthy();
    expect(TEST_CREDENTIALS.otp, 'WEB3AUTH_TEST_OTP must be set').toBeTruthy();

    // Navigate to login page
    await page.goto('/');

    // Perform login
    await loginViaEmail(page, TEST_CREDENTIALS.email, TEST_CREDENTIALS.otp);

    // Verify we're on the dashboard
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify logout button is visible (authenticated state)
    await expect(page.getByRole('button', { name: /logout|sign out/i })).toBeVisible();
  });

  // ============================================
  // Phase 2: Folders (placeholder for now)
  // ============================================

  test.skip('2.1 Create root-level folder', async () => {
    // TODO: Implement when folder creation UI is available
    // const folderName = `test-folder-${Date.now()}`;
    // createdFolders.push(folderName);
  });

  test.skip('2.2 Create nested folder', async () => {
    // TODO: Implement when folder creation UI is available
  });

  // ============================================
  // Phase 3: Upload
  // ============================================

  test('3.1 Upload file to root folder', async () => {
    // Create a test file
    const testFile = createTestTextFile(testFileName, 'This is test content for E2E upload.');
    createdFiles.push(testFileName);

    // Wait for the upload zone to be visible (use first() as there may be multiple)
    await expect(uploadZone.dropzone().first()).toBeVisible({ timeout: 10000 });

    // Upload the file (uploadFile already handles the file input)
    await uploadZone.uploadFile(testFile.path);

    // Wait for either:
    // 1. File to appear in list (success)
    // 2. Error alert to appear (IPNS conflict - may happen with stale test account state)
    const result = await Promise.race([
      fileList.waitForItemToAppear(testFileName, { timeout: 30000 }).then(() => 'success' as const),
      page
        .locator('.upload-zone-error, [role="alert"]')
        .filter({ hasText: /could not be added/ })
        .waitFor({ state: 'visible', timeout: 30000 })
        .then(() => 'error' as const),
    ]);

    if (result === 'error') {
      // This can happen when IPNS has stale state from previous test runs.
      // The file was uploaded to IPFS but couldn't be added to folder metadata.
      // This is a known limitation with IPNS sequence numbers.
      const errorText = await page.locator('[role="alert"]').textContent();
      throw new Error(
        `Upload succeeded but file could not be added to folder (IPNS conflict). ` +
          `This typically happens when running tests multiple times with the same account. ` +
          `Error: ${errorText}`
      );
    }

    // Verify file is visible
    const isVisible = await fileList.isItemVisible(testFileName);
    expect(isVisible).toBe(true);
  });

  // ============================================
  // Phase 4: Operations
  // ============================================

  test('4.1 Rename file', async () => {
    // Right-click the file to open context menu
    await fileList.rightClickItem(testFileName);

    // Wait for context menu to open
    await contextMenu.waitForOpen();

    // Click rename option
    await contextMenu.clickRename();

    // Wait for rename dialog to open
    await renameDialog.waitForOpen();

    // Enter new name and save
    await renameDialog.rename(renamedFileName);

    // Wait for file to appear with new name
    await fileList.waitForItemToAppear(renamedFileName, { timeout: 15000 });

    // Verify old name is gone
    const oldNameVisible = await fileList.isItemVisible(testFileName);
    expect(oldNameVisible).toBe(false);

    // Verify new name is visible
    const newNameVisible = await fileList.isItemVisible(renamedFileName);
    expect(newNameVisible).toBe(true);

    // Update tracking array
    const index = createdFiles.indexOf(testFileName);
    if (index > -1) {
      createdFiles[index] = renamedFileName;
    }
  });

  test('4.2 Download file', async () => {
    // Set up download handler
    const downloadPromise = page.waitForEvent('download');

    // Right-click the file to open context menu
    await fileList.rightClickItem(renamedFileName);

    // Wait for context menu to open
    await contextMenu.waitForOpen();

    // Click download option
    await contextMenu.clickDownload();

    // Wait for download to start
    const download = await downloadPromise;

    // Verify download started with correct filename
    expect(download.suggestedFilename()).toBe(renamedFileName);

    // Cancel the download (we don't need to save it)
    await download.cancel();
  });

  // ============================================
  // Phase 5: Cleanup
  // ============================================

  test('5.1 Delete files', async () => {
    // Delete each created file
    for (const fileName of createdFiles) {
      // Check if file still exists (might have been renamed)
      const isVisible = await fileList.isItemVisible(fileName);
      if (!isVisible) continue;

      // Right-click to open context menu
      await fileList.rightClickItem(fileName);
      await contextMenu.waitForOpen();

      // Click delete
      await contextMenu.clickDelete();

      // Wait for confirm dialog
      await confirmDialog.waitForOpen();

      // Confirm deletion
      await confirmDialog.clickConfirm();

      // Wait for dialog to close
      await confirmDialog.waitForClose({ timeout: 15000 });

      // Wait for file to disappear
      await fileList.waitForItemToDisappear(fileName, { timeout: 15000 });
    }

    // Clear tracking array
    createdFiles.length = 0;
  });

  test.skip('5.2 Delete folders', async () => {
    // TODO: Implement when folder deletion is tested
    // Delete folders in reverse order (nested first, then root)
    // for (const folderName of createdFolders.reverse()) { ... }
  });

  // ============================================
  // Phase 6: Logout
  // ============================================

  test('6.1 Logout', async () => {
    // Click logout button
    const logoutButton = page.getByRole('button', { name: /logout|sign out/i });
    await expect(logoutButton).toBeVisible();
    await logoutButton.click();

    // Wait for redirect to login page (root URL or /login)
    // The app redirects to "/" when logged out
    await expect(page).toHaveURL(/localhost:\d+\/?$/);

    // Verify Sign In button is visible (logged out state)
    // The button text varies based on Web3Auth configuration - could be "Sign In", "Login", or "Continue with Google"
    await expect(
      page.getByRole('button', { name: /sign in|login|continue with google/i })
    ).toBeVisible({
      timeout: 10000,
    });
  });
});
