import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { FileListPage, FolderTreePage, ContextMenuPage } from '../../page-objects/file-browser';
import { ConfirmDialogPage } from '../../page-objects/dialogs';

/**
 * Folder deletion E2E tests.
 * Tests deleting folders via context menu and confirming warnings.
 */
authenticatedTest.describe('Folder Delete', () => {
  authenticatedTest('delete empty folder', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const confirmDialog = new ConfirmDialogPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create a folder to delete
    const folderName = `Empty Folder ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(folderName);

    // Right-click to delete
    await fileList.rightClickItem(folderName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();

    // Confirm dialog should appear
    await confirmDialog.waitForOpen();

    const title = await confirmDialog.getTitle();
    expect(title).toContain('Delete');

    // Confirm deletion
    await confirmDialog.clickConfirm();
    await confirmDialog.waitForClose();

    // Verify folder is removed from list
    await fileList.waitForItemToDisappear(folderName);
    await expect(fileList.getItem(folderName)).not.toBeVisible();

    // Verify folder is removed from tree
    await expect(folderTree.getFolder(folderName)).not.toBeVisible();
  });

  authenticatedTest('delete folder with contents shows warning', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const confirmDialog = new ConfirmDialogPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create parent folder
    const parentName = `Parent With Content ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    let folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(parentName);

    let createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(parentName);

    // Navigate into parent
    await fileList.doubleClickFolder(parentName);
    await authenticatedPage.waitForTimeout(500);

    // Create child folder
    const childName = `Child ${Date.now()}`;
    await newFolderButton.click();

    folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(childName);

    createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(childName);

    // Navigate back to root
    const homeButton = authenticatedPage.locator('.breadcrumb-item').first();
    await homeButton.click();
    await authenticatedPage.waitForTimeout(500);

    // Try to delete parent folder
    await fileList.rightClickItem(parentName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();

    // Confirm dialog should appear with warning about contents
    await confirmDialog.waitForOpen();

    const message = await confirmDialog.getMessage();
    // Message should warn about deleting folder with contents
    expect(message.toLowerCase()).toMatch(/content|subfolder|file/);

    // Confirm deletion
    await confirmDialog.clickConfirm();
    await confirmDialog.waitForClose();

    // Verify parent and all contents are deleted
    await fileList.waitForItemToDisappear(parentName);
    await expect(fileList.getItem(parentName)).not.toBeVisible();
  });

  authenticatedTest('can cancel folder delete', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const confirmDialog = new ConfirmDialogPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create folder
    const folderName = `Folder To Keep ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(folderName);

    // Start delete but cancel
    await fileList.rightClickItem(folderName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();

    // Cancel deletion
    await confirmDialog.clickCancel();
    await confirmDialog.waitForClose();

    // Verify folder still exists in list
    await expect(fileList.getFolderItem(folderName)).toBeVisible();

    // Verify folder still exists in tree
    await expect(folderTree.getFolder(folderName)).toBeVisible();
  });
});
