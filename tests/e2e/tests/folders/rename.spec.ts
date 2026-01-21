import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { FileListPage, FolderTreePage, ContextMenuPage } from '../../page-objects/file-browser';
import { RenameDialogPage } from '../../page-objects/dialogs';

/**
 * Folder rename E2E tests.
 * Tests renaming folders via context menu and verifying changes.
 */
authenticatedTest.describe('Folder Rename', () => {
  authenticatedTest('can rename folder via context menu', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const renameDialog = new RenameDialogPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create a test folder first
    const originalName = `Folder To Rename ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(originalName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(originalName);

    // Right-click the folder to open context menu
    await fileList.rightClickItem(originalName);
    await contextMenu.waitForOpen();

    // Click rename option
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();

    // Verify dialog shows correct title
    const title = await renameDialog.getTitle();
    expect(title).toContain('Rename');

    // Enter new name
    const newName = `Renamed Folder ${Date.now()}`;
    await renameDialog.clearAndEnterName(newName);
    await renameDialog.clickSave();

    // Wait for dialog to close
    await renameDialog.waitForClose();

    // Verify old name is gone
    await fileList.waitForItemToDisappear(originalName);
    await expect(fileList.getItem(originalName)).not.toBeVisible();

    // Verify new name appears in file list
    await fileList.waitForItemToAppear(newName);
    await expect(fileList.getFolderItem(newName)).toBeVisible();

    // Verify new name appears in tree
    await folderTree.waitForFolderToAppear(newName);
    await expect(folderTree.getFolder(newName)).toBeVisible();
  });

  authenticatedTest('renamed folder maintains contents', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const renameDialog = new RenameDialogPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create parent folder
    const parentName = `Parent With Child ${Date.now()}`;
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

    // Rename parent folder
    await fileList.rightClickItem(parentName);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();

    const newParentName = `Renamed Parent ${Date.now()}`;
    await renameDialog.clearAndEnterName(newParentName);
    await renameDialog.clickSave();
    await renameDialog.waitForClose();

    // Wait for rename to complete
    await fileList.waitForItemToAppear(newParentName);

    // Navigate into renamed parent
    await fileList.doubleClickFolder(newParentName);
    await authenticatedPage.waitForTimeout(500);

    // Verify child still exists
    await expect(fileList.getFolderItem(childName)).toBeVisible();
  });

  authenticatedTest('can cancel folder rename', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);
    const renameDialog = new RenameDialogPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create test folder
    const folderName = `Folder To Not Rename ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(folderName);

    // Open rename dialog
    await fileList.rightClickItem(folderName);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();

    // Enter new name but cancel
    await renameDialog.clearAndEnterName('This Should Not Apply');
    await renameDialog.clickCancel();
    await renameDialog.waitForClose();

    // Verify original name still exists
    await expect(fileList.getFolderItem(folderName)).toBeVisible();

    // Verify new name was not applied
    await expect(fileList.getItem('This Should Not Apply')).not.toBeVisible();
  });
});
