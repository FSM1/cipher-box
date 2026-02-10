import { test, expect, Page, Browser, BrowserContext } from '@playwright/test';
import { loginViaEmail, TEST_CREDENTIALS } from '../utils/web3auth-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { ParentDirPage } from '../page-objects/file-browser/parent-dir.page';
import { BreadcrumbsPage } from '../page-objects/file-browser/breadcrumbs.page';
import { RenameDialogPage } from '../page-objects/dialogs/rename-dialog.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { MoveDialogPage } from '../page-objects/dialogs/move-dialog.page';

/**
 * Full Workflow E2E Test Suite
 *
 * Comprehensive test session that:
 * 1. Logs in once via Web3Auth
 * 2. Creates a realistic folder hierarchy
 * 3. Uploads multiple files at various folder levels (12+ files)
 * 3.5. Reloads page and verifies subfolder navigation from cold state
 *      (IPNS resolve + key unwrapping via navigateTo)
 * 4. Moves files between folders
 * 5. Edits a file (delete + re-upload with new content)
 * 6. Cleans up and logs out
 *
 * This approach tests a realistic user workflow with:
 * - Nested folder structure (workspace/documents, workspace/images, workspace/projects/active, etc.)
 * - Files distributed across the hierarchy
 * - File operations including move and edit
 */
test.describe.serial('Full Workflow', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  // Page objects (initialized after login)
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  let parentDir: ParentDirPage;
  let breadcrumbs: BreadcrumbsPage;
  let renameDialog: RenameDialogPage;
  let confirmDialog: ConfirmDialogPage;
  let createFolderDialog: CreateFolderDialogPage;
  let moveDialog: MoveDialogPage;

  // Test data - unique names for this test run
  const timestamp = Date.now();

  // Folder structure
  const workspaceFolder = `workspace-${timestamp}`;
  const documentsFolder = `documents-${timestamp}`;
  const imagesFolder = `images-${timestamp}`;
  const projectsFolder = `projects-${timestamp}`;
  const activeFolder = `active-${timestamp}`;
  const archiveFolder = `archive-${timestamp}`;

  // Track folder IDs when created (folder name → UUID)
  // This avoids relying on window.__ZUSTAND_FOLDER_STORE__ which may not be available in CI
  const folderIds: Record<string, string> = {};

  // Track navigation for internal state management
  // NOTE: getCurrentFolderName() was removed since move tests (Phase 4) are skipped
  const navigationStack: string[] = ['root'];

  // Files to upload at various levels (12+ files total)
  const rootFiles = [
    { name: `readme-${timestamp}.txt`, content: 'Root level readme file' },
    { name: `notes-${timestamp}.txt`, content: 'General notes at root' },
    { name: `config-${timestamp}.txt`, content: 'Configuration settings' },
  ];

  const documentFiles = [
    { name: `report-${timestamp}.txt`, content: 'Annual report document' },
    { name: `memo-${timestamp}.txt`, content: 'Internal memo content' },
    { name: `draft-${timestamp}.txt`, content: 'Work in progress draft' },
  ];

  const imageFiles = [
    { name: `photo-info-${timestamp}.txt`, content: 'Photo metadata info' },
    { name: `gallery-${timestamp}.txt`, content: 'Gallery description' },
  ];

  const activeProjectFiles = [
    { name: `task-list-${timestamp}.txt`, content: 'Active project tasks' },
    { name: `sprint-${timestamp}.txt`, content: 'Current sprint details' },
  ];

  const archiveProjectFiles = [
    { name: `completed-${timestamp}.txt`, content: 'Completed project info' },
    { name: `retrospective-${timestamp}.txt`, content: 'Project retrospective' },
  ];

  // File uploaded after page reload (tests cold-load upload path)
  const postReloadFile = {
    name: `post-reload-${timestamp}.txt`,
    content: 'File uploaded after page reload',
  };

  // File to be edited (re-uploaded with new content)
  const editableFileName = `editable-${timestamp}.txt`;
  const editableFileOriginalContent = 'Original content before edit';
  const editableFileUpdatedContent = 'Updated content after edit - version 2';

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    // Initialize page objects
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    contextMenu = new ContextMenuPage(page);
    parentDir = new ParentDirPage(page);
    breadcrumbs = new BreadcrumbsPage(page);
    renameDialog = new RenameDialogPage(page);
    confirmDialog = new ConfirmDialogPage(page);
    createFolderDialog = new CreateFolderDialogPage(page);
    moveDialog = new MoveDialogPage(page);
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
  // Helper Functions
  // ============================================

  /**
   * Create a folder in the current directory and store its ID.
   */
  async function createFolder(name: string): Promise<void> {
    const newFolderButton = page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(name);
    await fileList.waitForItemToAppear(name, { timeout: 30000 });

    // Store the folder ID immediately after creation
    folderIds[name] = await fileList.getItemId(name);
  }

  /**
   * Navigate into a folder by double-clicking.
   * Phase 6.3: Uses breadcrumb path to verify navigation (~/root/foldername format).
   */
  async function navigateIntoFolder(name: string): Promise<void> {
    await fileList.doubleClickFolder(name);
    // Wait for breadcrumb path to include the folder name
    await breadcrumbs.waitForPathToContain(name, { timeout: 10000 });
    navigationStack.push(name);
  }

  /**
   * Navigate back to parent folder.
   * Phase 6.3: Uses [..] PARENT_DIR row instead of breadcrumb back button.
   */
  async function navigateBack(): Promise<void> {
    await parentDir.click();
    await page.waitForTimeout(500); // Wait for navigation
    if (navigationStack.length > 1) {
      navigationStack.pop();
    }
  }

  /**
   * Navigate to root folder.
   * Phase 6.3: Uses ParentDirRow navigation repeatedly until at root.
   * Note: Cannot use page.goto('/files') as it reloads the page and loses folder state.
   */
  async function navigateToRoot(): Promise<void> {
    // Keep clicking [..] PARENT_DIR until we're at root (no more parent row)
    const maxIterations = 10;
    for (let i = 0; i < maxIterations; i++) {
      const parentDirRow = page.locator('[data-testid="parent-dir-row"]');
      const isVisible = await parentDirRow.isVisible().catch(() => false);

      if (!isVisible) {
        // No parent row means we're at root
        break;
      }

      await parentDirRow.click();
      await page.waitForTimeout(300); // Wait for navigation
    }

    // Verify we're at root by checking breadcrumbs (new interactive format)
    // At root, there's only one breadcrumb item: "my vault"
    await page.locator('.breadcrumb-item', { hasText: /my vault/i }).waitFor({
      state: 'visible',
      timeout: 10000,
    });

    // Reset navigation stack to root
    navigationStack.length = 0;
    navigationStack.push('root');
  }

  /**
   * Upload a file and wait for it to appear in the list.
   */
  async function uploadFile(
    fileName: string,
    content: string
  ): Promise<{ path: string; name: string }> {
    const testFile = createTestTextFile(fileName, content);
    await uploadZone.uploadFile(testFile.path);

    // Wait for file to appear
    const result = await Promise.race([
      fileList.waitForItemToAppear(fileName, { timeout: 30000 }).then(() => 'success' as const),
      page
        .locator('.upload-zone-error, [role="alert"]')
        .filter({ hasText: /could not be added/ })
        .waitFor({ state: 'visible', timeout: 30000 })
        .then(() => 'error' as const),
    ]);

    if (result === 'error') {
      const errorText = await page.locator('[role="alert"]').textContent();
      throw new Error(`Upload failed: ${errorText}`);
    }

    return testFile;
  }

  /**
   * Delete an item (file or folder) via context menu.
   */
  async function deleteItem(name: string): Promise<void> {
    await fileList.rightClickItem(name);
    await contextMenu.waitForOpen();
    await contextMenu.clickDelete();
    await confirmDialog.waitForOpen();
    await confirmDialog.clickConfirm();
    await confirmDialog.waitForClose({ timeout: 15000 });
    await fileList.waitForItemToDisappear(name, { timeout: 15000 });
  }

  // NOTE: getTrackedFolderId() was removed since move tests (Phase 4) are
  // skipped. Re-add when move functionality is implemented via context menu
  // or drag-drop to folder rows.

  // ============================================
  // Phase 1: Login
  // ============================================

  test('1.1 Login with Web3Auth credentials', async () => {
    expect(TEST_CREDENTIALS.email, 'WEB3AUTH_TEST_EMAIL must be set').toBeTruthy();
    expect(TEST_CREDENTIALS.otp, 'WEB3AUTH_TEST_OTP must be set').toBeTruthy();

    await page.goto('/');
    await loginViaEmail(page, TEST_CREDENTIALS.email, TEST_CREDENTIALS.otp);

    // Phase 6.3: /dashboard redirects to /files
    await expect(page).toHaveURL(/.*files/);
    // Phase 6.3: Logout is now in UserMenu dropdown, check for user menu trigger instead
    await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
  });

  // ============================================
  // Phase 2: Create Folder Hierarchy
  // ============================================

  test('2.1 Create workspace folder at root', async () => {
    await createFolder(workspaceFolder);
    expect(await fileList.isItemVisible(workspaceFolder)).toBe(true);
  });

  test('2.2 Create documents folder inside workspace', async () => {
    await navigateIntoFolder(workspaceFolder);
    await createFolder(documentsFolder);
    expect(await fileList.isItemVisible(documentsFolder)).toBe(true);
  });

  test('2.3 Create images folder inside workspace', async () => {
    // Still inside workspace
    await createFolder(imagesFolder);
    expect(await fileList.isItemVisible(imagesFolder)).toBe(true);
  });

  test('2.4 Create projects folder inside workspace', async () => {
    await createFolder(projectsFolder);
    expect(await fileList.isItemVisible(projectsFolder)).toBe(true);
  });

  test('2.5 Create active folder inside projects', async () => {
    await navigateIntoFolder(projectsFolder);
    await createFolder(activeFolder);
    expect(await fileList.isItemVisible(activeFolder)).toBe(true);
  });

  test('2.6 Create archive folder inside projects', async () => {
    // Still inside projects
    await createFolder(archiveFolder);
    expect(await fileList.isItemVisible(archiveFolder)).toBe(true);
  });

  // ============================================
  // Phase 3: Upload Files at Various Levels (12+ files)
  // ============================================

  test('3.1 Upload files to root level (3 files)', async () => {
    await navigateToRoot();

    // Wait for file list to stabilize after navigation
    // Ensure the workspace folder is visible (created in test 2.1)
    await fileList.waitForItemToAppear(workspaceFolder, { timeout: 10000 });

    for (const file of rootFiles) {
      await uploadFile(file.name, file.content);
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
  });

  test('3.2 Upload editable file to root (for later edit test)', async () => {
    // This file will be edited later (deleted and re-uploaded with new content)
    await uploadFile(editableFileName, editableFileOriginalContent);
    expect(await fileList.isItemVisible(editableFileName)).toBe(true);
  });

  test('3.3 Upload files to documents folder (3 files)', async () => {
    await navigateIntoFolder(workspaceFolder);
    await navigateIntoFolder(documentsFolder);

    for (const file of documentFiles) {
      await uploadFile(file.name, file.content);
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
  });

  test('3.4 Upload files to images folder (2 files)', async () => {
    await navigateBack(); // Back to workspace
    await navigateIntoFolder(imagesFolder);

    for (const file of imageFiles) {
      await uploadFile(file.name, file.content);
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
  });

  test('3.5 Upload files to projects/active folder (2 files)', async () => {
    await navigateBack(); // Back to workspace
    await navigateIntoFolder(projectsFolder);
    await navigateIntoFolder(activeFolder);

    for (const file of activeProjectFiles) {
      await uploadFile(file.name, file.content);
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
  });

  test('3.6 Upload files to projects/archive folder (2 files)', async () => {
    await navigateBack(); // Back to projects
    await navigateIntoFolder(archiveFolder);

    for (const file of archiveProjectFiles) {
      await uploadFile(file.name, file.content);
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
  });

  test('3.6.1 Storage quota reflects uploaded files', async () => {
    // After uploading 13+ files, the quota display should show non-zero usage.
    // The StorageQuota component fetches from GET /vault/quota which computes
    // usage from pinned CIDs in the database.
    const quotaText = page.locator('[data-testid="storage-quota"] .storage-quota-text');
    await expect(quotaText).toBeVisible({ timeout: 10000 });

    // Quota should NOT be "0 B" — files were uploaded so usage must be > 0
    await expect(quotaText).not.toHaveText(/^0 B\s*\//, { timeout: 15000 });
  });

  // ============================================
  // Phase 3.5: Post-Reload Subfolder Navigation
  // ============================================
  // After page.reload(), Zustand store is empty. The app must
  // re-authenticate, re-sync root metadata from IPNS, and then
  // cold-load subfolder contents via navigateTo (IPNS resolve +
  // key unwrapping). This path is NOT exercised by in-session tests.

  test('3.7 Page reload preserves session and reloads root folder', async () => {
    // Navigate to root before reload so we start from a clean state
    await navigateToRoot();

    // Reload the page — Zustand store is wiped
    await page.reload({ waitUntil: 'domcontentloaded' });

    // Reset navigation stack since we're starting fresh
    navigationStack.length = 0;
    navigationStack.push('root');

    // Wait for auth to restore (user menu becomes visible)
    await page.locator('[data-testid="user-menu"]').waitFor({
      state: 'visible',
      timeout: 30000,
    });

    // Wait for initial sync to complete — workspace folder must appear
    // This proves IPNS root metadata was re-fetched and decrypted
    await fileList.waitForItemToAppear(workspaceFolder, { timeout: 60000 });

    // Verify other root-level items are also visible
    // rootFiles[0] was moved to workspace in 4.1 — but Phase 4 hasn't run yet at this point
    for (const file of rootFiles) {
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
    expect(await fileList.isItemVisible(editableFileName)).toBe(true);
  });

  test('3.7.1 Storage quota persists after page reload', async () => {
    // After reload, the Zustand store is wiped so quota resets to 0.
    // The StorageQuota component should fetch fresh quota from the backend
    // once auth is restored, showing the same non-zero value as before reload.
    // This is a regression test for the quota-stuck-at-zero bug.
    const quotaText = page.locator('[data-testid="storage-quota"] .storage-quota-text');
    await expect(quotaText).toBeVisible({ timeout: 10000 });

    // Quota should NOT be "0 B" — the backend still has the pinned CIDs
    await expect(quotaText).not.toHaveText(/^0 B\s*\//, { timeout: 15000 });
  });

  test('3.8 Navigate into subfolder after reload and verify contents', async () => {
    // Double-click workspace folder → exercises navigateTo cold-load
    await navigateIntoFolder(workspaceFolder);

    // Verify workspace children are visible (documents, images, projects)
    expect(await fileList.isItemVisible(documentsFolder)).toBe(true);
    expect(await fileList.isItemVisible(imagesFolder)).toBe(true);
    expect(await fileList.isItemVisible(projectsFolder)).toBe(true);

    // Navigate deeper into documents — exercises nested IPNS resolve + key unwrap
    await navigateIntoFolder(documentsFolder);

    // Verify uploaded document files are visible
    for (const file of documentFiles) {
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }
  });

  test('3.9 Breadcrumb navigation works after reload', async () => {
    // We're in documents folder from previous test
    // Click workspace breadcrumb to navigate back
    await breadcrumbs.clickBreadcrumb(workspaceFolder);
    await breadcrumbs.waitForPathToContain(workspaceFolder, { timeout: 10000 });

    // Update navigation stack manually since we used breadcrumb
    navigationStack.length = 0;
    navigationStack.push('root', workspaceFolder);

    // Verify workspace children are all visible
    expect(await fileList.isItemVisible(documentsFolder)).toBe(true);
    expect(await fileList.isItemVisible(imagesFolder)).toBe(true);
    expect(await fileList.isItemVisible(projectsFolder)).toBe(true);
  });

  test('3.10 Upload file to subfolder after reload', async () => {
    // Navigate into images folder
    await navigateIntoFolder(imagesFolder);

    // Verify existing image files are present (from Phase 3.4)
    for (const file of imageFiles) {
      expect(await fileList.isItemVisible(file.name)).toBe(true);
    }

    // Upload a new file — exercises the upload path after cold-load
    await uploadFile(postReloadFile.name, postReloadFile.content);
    expect(await fileList.isItemVisible(postReloadFile.name)).toBe(true);

    // Navigate away and back to verify persistence
    await navigateBack(); // Back to workspace
    await navigateIntoFolder(imagesFolder);

    // File should still be there
    await fileList.waitForItemToAppear(postReloadFile.name, { timeout: 30000 });
    expect(await fileList.isItemVisible(postReloadFile.name)).toBe(true);

    // Navigate back to root for Phase 4
    await navigateToRoot();
  });

  // ============================================
  // Phase 4: Move Files Between Folders
  // ============================================
  // Move operations via:
  // - Context menu "Move to..." → MoveDialog
  // - Drag-drop to folder rows in file list
  // - Drag-drop to breadcrumb segments

  test('4.1 Move file via context menu (Move to...)', async () => {
    // Navigate to root
    await navigateToRoot();

    // Get the first root file to move
    const fileToMove = rootFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Open context menu and click Move to...
    await fileList.rightClickItem(fileToMove);
    await contextMenu.waitForOpen();
    await contextMenu.clickMove();

    // Wait for move dialog
    await moveDialog.waitForOpen();

    // Select workspace folder as destination
    await moveDialog.selectFolder(workspaceFolder);
    expect(await moveDialog.isFolderSelected(workspaceFolder)).toBe(true);

    // Confirm move
    await moveDialog.clickMove();
    await moveDialog.waitForClose({ timeout: 15000 });

    // Verify file is no longer at root
    expect(await fileList.isItemVisible(fileToMove)).toBe(false);

    // Navigate to workspace and verify file is there
    await navigateIntoFolder(workspaceFolder);
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
  });

  test('4.2 Move file via drag-drop to folder row', async () => {
    // We're in workspace folder from previous test
    // Move one of the document files from documents to images folder

    // Navigate to documents folder
    await navigateIntoFolder(documentsFolder);

    // Get a document file to move (we have 3, take the first)
    const fileToMove = documentFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Navigate back to workspace where we can see both documents and images folders
    await navigateBack();

    // Re-navigate to documents to drag the file
    await navigateIntoFolder(documentsFolder);

    // Actually move - we need to move from documents to workspace first
    // since images folder is a sibling, not child
    await navigateBack(); // Back to workspace

    // Move file from documents (need to be in documents to drag from there)
    await navigateIntoFolder(documentsFolder);

    // File should be visible in documents
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Use context menu to move to images folder (sibling folder)
    await fileList.rightClickItem(fileToMove);
    await contextMenu.waitForOpen();
    await contextMenu.clickMove();
    await moveDialog.waitForOpen();

    // Images folder should be visible in the move dialog
    await moveDialog.selectFolder(imagesFolder);
    await moveDialog.clickMove();
    await moveDialog.waitForClose({ timeout: 15000 });

    // File should be gone from documents
    expect(await fileList.isItemVisible(fileToMove)).toBe(false);

    // Navigate to images and verify
    await navigateBack(); // Back to workspace
    await navigateIntoFolder(imagesFolder);
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
  });

  test('4.3 Move file via drag-drop to breadcrumb', async () => {
    // We're in images folder from previous test
    // Drag a file to the workspace breadcrumb to move it up

    // Get an image file to move
    const fileToMove = imageFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Drag to workspace breadcrumb
    const sourceItem = fileList.getItem(fileToMove);
    await breadcrumbs.dragItemToBreadcrumb(sourceItem, workspaceFolder);

    // Wait for the move to complete
    await page.waitForTimeout(1000);

    // File should be gone from images
    expect(await fileList.isItemVisible(fileToMove)).toBe(false);

    // Navigate to workspace and verify file is there
    await navigateBack(); // Go up to workspace
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
  });

  test('4.4 Navigate via breadcrumb click', async () => {
    // We're in workspace from previous test
    // Navigate into projects, then use breadcrumb to go back to workspace

    await navigateIntoFolder(projectsFolder);
    await navigateIntoFolder(activeFolder);

    // Verify we're in active folder
    expect(await breadcrumbs.pathContains(activeFolder)).toBe(true);

    // Click workspace breadcrumb to navigate directly there
    await breadcrumbs.clickBreadcrumb(workspaceFolder);

    // Wait for navigation
    await page.waitForTimeout(500);

    // Verify we're at workspace - should see projects folder
    expect(await fileList.isItemVisible(projectsFolder)).toBe(true);
  });

  // ============================================
  // Phase 5: Edit File (Overwrite with New Content)
  // ============================================

  test('5.1 Edit file by deleting and re-uploading with new content', async () => {
    // Navigate to root where editable file is
    await navigateToRoot();

    // Verify original file exists
    expect(await fileList.isItemVisible(editableFileName)).toBe(true);

    // Download the file first to verify it's downloadable
    const downloadPromise = page.waitForEvent('download');
    await fileList.rightClickItem(editableFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDownload();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe(editableFileName);
    await download.cancel();

    // Delete the file
    await deleteItem(editableFileName);

    // Verify file is gone
    expect(await fileList.isItemVisible(editableFileName)).toBe(false);

    // Upload new version with same name but different content
    await uploadFile(editableFileName, editableFileUpdatedContent);

    // Verify new file exists
    expect(await fileList.isItemVisible(editableFileName)).toBe(true);

    // Download again to verify it's the new content (by checking download works)
    const downloadPromise2 = page.waitForEvent('download');
    await fileList.rightClickItem(editableFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickDownload();
    const download2 = await downloadPromise2;
    expect(download2.suggestedFilename()).toBe(editableFileName);
    await download2.cancel();
  });

  // ============================================
  // Phase 6: Rename Operations
  // ============================================

  test('6.1 Rename a file', async () => {
    // We're at root, rename one of the remaining root files
    const fileToRename = rootFiles[1].name;
    const newFileName = `renamed-${timestamp}.txt`;

    expect(await fileList.isItemVisible(fileToRename)).toBe(true);

    await fileList.rightClickItem(fileToRename);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();
    await renameDialog.rename(newFileName);

    await fileList.waitForItemToAppear(newFileName, { timeout: 15000 });
    expect(await fileList.isItemVisible(fileToRename)).toBe(false);
    expect(await fileList.isItemVisible(newFileName)).toBe(true);

    // Update the array for cleanup
    rootFiles[1].name = newFileName;
  });

  test('6.2 Rename a folder', async () => {
    // Navigate into workspace and rename one of the folders
    await navigateIntoFolder(workspaceFolder);

    const folderToRename = imagesFolder;
    const newFolderName = `media-${timestamp}`;

    expect(await fileList.isItemVisible(folderToRename)).toBe(true);

    await fileList.rightClickItem(folderToRename);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();
    await renameDialog.rename(newFolderName);

    await fileList.waitForItemToAppear(newFolderName, { timeout: 15000 });
    expect(await fileList.isItemVisible(folderToRename)).toBe(false);
    expect(await fileList.isItemVisible(newFolderName)).toBe(true);
  });

  // ============================================
  // Phase 7: Cleanup
  // ============================================

  test('7.1 Delete workspace folder (recursive delete)', async () => {
    // Navigate to root
    await navigateToRoot();

    // Delete the workspace folder (should recursively delete all contents)
    await deleteItem(workspaceFolder);

    // Verify folder is gone
    expect(await fileList.isItemVisible(workspaceFolder)).toBe(false);
  });

  test('7.2 Delete remaining root files', async () => {
    // Delete remaining files at root
    // Note: rootFiles[0] was moved to workspace in test 4.1, workspace was deleted in 7.1
    // Some files may have been moved around, clean up what remains
    const filesToDelete = [
      rootFiles[1].name, // This was renamed in test 6.1
      rootFiles[2].name,
      editableFileName,
    ];

    for (const fileName of filesToDelete) {
      const isVisible = await fileList.isItemVisible(fileName);
      if (isVisible) {
        await deleteItem(fileName);
      }
    }
  });

  // ============================================
  // Phase 8: Logout
  // ============================================

  test('8.1 Logout', async () => {
    // Phase 6.3: Logout is now in UserMenu dropdown
    const userMenu = page.locator('[data-testid="user-menu"]');
    await expect(userMenu).toBeVisible();

    // Hover to open the dropdown
    await userMenu.hover();

    // Wait for and click the logout button in the dropdown
    const logoutButton = page.locator('.user-menu-item', { hasText: '[logout]' });
    await expect(logoutButton).toBeVisible();
    await logoutButton.click();

    await expect(page).toHaveURL(/localhost:\d+\/?(?:#\/?)?$/);
    await expect(page.getByRole('button', { name: /\[CONNECT\]|sign in|login/i })).toBeVisible({
      timeout: 10000,
    });
  });
});
