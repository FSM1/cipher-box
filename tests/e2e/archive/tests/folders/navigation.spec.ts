import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { FileListPage, FolderTreePage, BreadcrumbsPage } from '../../page-objects/file-browser';

/**
 * Folder navigation E2E tests.
 * Tests navigating between folders via double-click, tree, and breadcrumbs.
 */
authenticatedTest.describe('Folder Navigation', () => {
  authenticatedTest('double-click folder navigates into it', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const breadcrumbs = new BreadcrumbsPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create a test folder
    const folderName = `Nav Test Folder ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(folderName);

    // Get initial breadcrumb count (should be at root)
    const initialBreadcrumbCount = await breadcrumbs.getBreadcrumbCount();

    // Double-click to navigate into folder
    await fileList.doubleClickFolder(folderName);

    // Wait for navigation
    await authenticatedPage.waitForTimeout(500);

    // Verify breadcrumbs updated
    const newBreadcrumbCount = await breadcrumbs.getBreadcrumbCount();
    expect(newBreadcrumbCount).toBe(initialBreadcrumbCount + 1);

    // Verify current breadcrumb shows folder name
    const currentBreadcrumb = await breadcrumbs.getCurrentBreadcrumb();
    expect(currentBreadcrumb).toContain(folderName);

    // Verify URL or state changed (depends on implementation)
    // File list should be empty (new folder has no contents)
    const itemCount = await fileList.getItemCount();
    expect(itemCount).toBe(0);
  });

  authenticatedTest('clicking folder in tree navigates', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const folderTree = new FolderTreePage(authenticatedPage);
    const breadcrumbs = new BreadcrumbsPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create test folder
    const folderName = `Tree Nav Folder ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(folderName);
    await folderTree.waitForFolderToAppear(folderName);

    // Click folder in tree
    await folderTree.clickFolder(folderName);

    // Wait for navigation
    await authenticatedPage.waitForTimeout(500);

    // Verify folder is selected in tree
    const isSelected = await folderTree.isFolderSelected(folderName);
    expect(isSelected).toBe(true);

    // Verify breadcrumbs show navigation
    const currentBreadcrumb = await breadcrumbs.getCurrentBreadcrumb();
    expect(currentBreadcrumb).toContain(folderName);

    // Verify file list is empty (new folder)
    const itemCount = await fileList.getItemCount();
    expect(itemCount).toBe(0);
  });

  authenticatedTest('breadcrumb click navigates to parent', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const breadcrumbs = new BreadcrumbsPage(authenticatedPage);

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

    // Navigate into child
    await fileList.doubleClickFolder(childName);
    await authenticatedPage.waitForTimeout(500);

    // Verify we're in child (breadcrumbs show parent > child)
    const pathInChild = await breadcrumbs.getCurrentPath();
    expect(pathInChild.length).toBeGreaterThan(2);

    // Click parent breadcrumb to navigate back
    await breadcrumbs.clickBreadcrumb(parentName);
    await authenticatedPage.waitForTimeout(500);

    // Verify we're back in parent
    const currentBreadcrumb = await breadcrumbs.getCurrentBreadcrumb();
    expect(currentBreadcrumb).toContain(parentName);

    // Verify child folder is visible in list
    await expect(fileList.getFolderItem(childName)).toBeVisible();
  });

  authenticatedTest('home breadcrumb navigates to root', async ({ authenticatedPage }) => {
    const fileList = new FileListPage(authenticatedPage);
    const breadcrumbs = new BreadcrumbsPage(authenticatedPage);

    await authenticatedPage.goto('/dashboard');
    await fileList.fileListContainer().waitFor({ state: 'visible' });

    // Create nested structure
    const folderName = `Deep Folder ${Date.now()}`;
    const newFolderButton = authenticatedPage.locator('button:has-text("New Folder")');
    await newFolderButton.click();

    const folderNameInput = authenticatedPage.locator('input[placeholder*="folder" i]');
    await folderNameInput.fill(folderName);

    const createButton = authenticatedPage.locator('button[type="submit"]:has-text("Create")');
    await createButton.click();

    await fileList.waitForItemToAppear(folderName);

    // Navigate into folder
    await fileList.doubleClickFolder(folderName);
    await authenticatedPage.waitForTimeout(500);

    // Verify we're not at root
    const breadcrumbCount = await breadcrumbs.getBreadcrumbCount();
    expect(breadcrumbCount).toBeGreaterThan(1);

    // Click home breadcrumb
    await breadcrumbs.clickHome();
    await authenticatedPage.waitForTimeout(500);

    // Verify we're back at root
    const newBreadcrumbCount = await breadcrumbs.getBreadcrumbCount();
    expect(newBreadcrumbCount).toBe(1);

    // Verify folder we created is visible in root
    await expect(fileList.getFolderItem(folderName)).toBeVisible();
  });
});
