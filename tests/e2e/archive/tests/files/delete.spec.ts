import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { UploadZonePage } from '../../page-objects/file-browser/upload-zone.page';
import { FileListPage } from '../../page-objects/file-browser/file-list.page';
import { ContextMenuPage } from '../../page-objects/file-browser/context-menu.page';
import { ConfirmDialogPage } from '../../page-objects/dialogs/confirm-dialog.page';
import { createTestTextFile, cleanupTestFiles } from '../../utils/test-files';

/**
 * E2E tests for file delete functionality.
 * Tests delete via context menu with confirmation dialog.
 */
authenticatedTest.describe('File Delete', () => {
  authenticatedTest.afterEach(async () => {
    // Clean up test files after each test
    cleanupTestFiles();
  });

  authenticatedTest('can delete file via context menu', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const confirmDialog = new ConfirmDialogPage(authenticatedPage);

    // Create and upload test file
    const testFile = createTestTextFile('delete-me.txt', 'Test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(testFile.name, { timeout: 5000 });

    // Open context menu and click delete
    await fileList.rightClickItem(testFile.name);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickDelete();

    // Wait for confirmation dialog
    await confirmDialog.waitForOpen({ timeout: 2000 });

    // Confirm deletion
    await confirmDialog.clickConfirm();
    await confirmDialog.waitForClose({ timeout: 5000 });

    // Verify file is removed from list
    await fileList.waitForItemToDisappear(testFile.name, { timeout: 5000 });
    await expect(fileList.getItem(testFile.name)).not.toBeVisible();
  });

  authenticatedTest('delete confirmation shows file name', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const confirmDialog = new ConfirmDialogPage(authenticatedPage);

    // Create and upload test file
    const fileName = 'important-file.txt';
    const testFile = createTestTextFile(fileName, 'Test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(fileName, { timeout: 5000 });

    // Open delete confirmation
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen({ timeout: 2000 });

    // Verify dialog shows file name in message
    const message = await confirmDialog.getMessage();
    expect(message).toContain(fileName);

    // Cancel without deleting
    await confirmDialog.clickCancel();
    await confirmDialog.waitForClose({ timeout: 2000 });
  });

  authenticatedTest('can cancel delete', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const confirmDialog = new ConfirmDialogPage(authenticatedPage);

    // Create and upload test file
    const fileName = 'keep-me.txt';
    const testFile = createTestTextFile(fileName, 'Test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(fileName, { timeout: 5000 });

    // Open delete confirmation
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen({ timeout: 2000 });

    // Cancel deletion
    await confirmDialog.clickCancel();
    await confirmDialog.waitForClose({ timeout: 2000 });

    // Verify file is still in list
    await expect(fileList.getFileItem(fileName)).toBeVisible();

    // Verify file count hasn't changed (at least 1 file)
    const itemCount = await fileList.getItemCount();
    expect(itemCount).toBeGreaterThanOrEqual(1);
  });
});
