import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { UploadZonePage } from '../../page-objects/file-browser/upload-zone.page';
import { FileListPage } from '../../page-objects/file-browser/file-list.page';
import { ContextMenuPage } from '../../page-objects/file-browser/context-menu.page';
import { RenameDialogPage } from '../../page-objects/dialogs/rename-dialog.page';
import { createTestTextFile, cleanupTestFiles } from '../../utils/test-files';

/**
 * E2E tests for file rename functionality.
 * Tests rename via context menu and rename dialog.
 */
authenticatedTest.describe('File Rename', () => {
  authenticatedTest.afterEach(async () => {
    // Clean up test files after each test
    cleanupTestFiles();
  });

  authenticatedTest('can rename file via context menu', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const renameDialog = new RenameDialogPage(authenticatedPage);

    // Create and upload test file
    const testFile = createTestTextFile('old-name.txt', 'Test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(testFile.name, { timeout: 5000 });

    // Open context menu and click rename
    await fileList.rightClickItem(testFile.name);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickRename();

    // Wait for rename dialog
    await renameDialog.waitForOpen({ timeout: 2000 });

    // Enter new name and save
    const newName = 'new-name.txt';
    await renameDialog.clearAndEnterName(newName);
    await renameDialog.clickSave();

    // Wait for dialog to close
    await renameDialog.waitForClose({ timeout: 5000 });

    // Verify old name is gone and new name appears
    await fileList.waitForItemToDisappear(testFile.name, { timeout: 5000 });
    await fileList.waitForItemToAppear(newName, { timeout: 5000 });
    await expect(fileList.getFileItem(newName)).toBeVisible();
  });

  authenticatedTest('rename dialog shows current name', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const renameDialog = new RenameDialogPage(authenticatedPage);

    // Create and upload test file
    const fileName = 'current-name.txt';
    const testFile = createTestTextFile(fileName, 'Test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(fileName, { timeout: 5000 });

    // Open rename dialog
    await fileList.rightClickItem(fileName);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickRename();
    await renameDialog.waitForOpen({ timeout: 2000 });

    // Verify current name is pre-filled in input
    const currentName = await renameDialog.getCurrentName();
    expect(currentName).toBe(fileName);

    // Close dialog without saving
    await renameDialog.clickCancel();
    await renameDialog.waitForClose({ timeout: 2000 });
  });

  authenticatedTest('can cancel rename', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const renameDialog = new RenameDialogPage(authenticatedPage);

    // Create and upload test file
    const originalName = 'original.txt';
    const testFile = createTestTextFile(originalName, 'Test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(originalName, { timeout: 5000 });

    // Open rename dialog
    await fileList.rightClickItem(originalName);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickRename();
    await renameDialog.waitForOpen({ timeout: 2000 });

    // Enter new name but cancel
    await renameDialog.clearAndEnterName('cancelled-name.txt');
    await renameDialog.clickCancel();
    await renameDialog.waitForClose({ timeout: 2000 });

    // Verify original name is still there
    await expect(fileList.getFileItem(originalName)).toBeVisible();

    // Verify new name was not created
    const visibleNames = await fileList.getVisibleItemNames();
    expect(visibleNames).not.toContain('cancelled-name.txt');
  });
});
