import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { FileListPage, FolderTreePage } from '../../page-objects/file-browser';

/**
 * Folder creation E2E tests.
 * Tests creating folders via UI and verifying they appear correctly.
 */
authenticatedTest.describe('Folder Creation', () => {
  authenticatedTest('can create a new folder', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);

    // Navigate to dashboard
    await authenticatedPage.goto('/dashboard');

    // Wait for file browser to load
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create a new folder via "New Folder" button or keyboard shortcut
    // Assuming there's a "New Folder" button in the UI
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await expect(newFolderButton).toBeVisible();
    await newFolderButton.click();

    // Dialog should appear for folder name input
    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await expect(folderNameInput).toBeVisible();

    // Enter folder name
    const folderName = `Test Folder ${Date.now()}`;
    await folderNameInput.fill(folderName);

    // Submit the form
    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    // Verify folder appears in file list
    await fileList.waitForItemToAppear(folderName);
    await expect(fileList.getFolderItem(folderName)).toBeVisible();

    // Verify folder appears in tree
    await folderTree.waitForFolderToAppear(folderName);
    await expect(folderTree.getFolder(folderName)).toBeVisible();
  });

  authenticatedTest('new folder appears in tree and list', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Get initial counts
    const initialListCount = await fileList.getItemCount();
    const initialTreeFolders = await folderTree.getVisibleFolderNames();

    // Create folder
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    const folderName = `Verified Folder ${Date.now()}`;
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    // Wait for folder to appear
    await fileList.waitForItemToAppear(folderName);

    // Verify count increased
    const newListCount = await fileList.getItemCount();
    expect(newListCount).toBe(initialListCount + 1);

    // Verify folder is in visible names
    const visibleNames = await fileList.getVisibleItemNames();
    expect(visibleNames).toContain(folderName);

    // Verify folder appears in tree
    await folderTree.waitForFolderToAppear(folderName);
    const newTreeFolders = await folderTree.getVisibleFolderNames();
    expect(newTreeFolders).toContain(folderName);
    expect(newTreeFolders.length).toBe(initialTreeFolders.length + 1);
  });

  authenticatedTest('can create nested folders', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create parent folder
    const parentName = `Parent ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    let folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(parentName);

    let createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(parentName);

    // Navigate into parent folder
    await fileList.doubleClickFolder(parentName);

    // Wait for navigation
    await authenticatedPage.waitForTimeout(500);

    // Create child folder
    const childName = `Child ${Date.now()}`;
    await newFolderButton.click();

    folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(childName);

    createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    // Verify child folder appears in list
    await fileList.waitForItemToAppear(childName);
    await expect(fileList.getFolderItem(childName)).toBeVisible();

    // Expand parent in tree to see child
    await folderTree.expandFolder(parentName);

    // Verify child appears in tree under parent
    await folderTree.waitForFolderToAppear(childName);
    await expect(folderTree.getFolder(childName)).toBeVisible();
  });
});
