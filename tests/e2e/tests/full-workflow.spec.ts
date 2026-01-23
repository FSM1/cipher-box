import { test, expect, Page, Browser, BrowserContext } from '@playwright/test';
import { loginViaEmail, TEST_CREDENTIALS } from '../utils/web3auth-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { FolderTreePage } from '../page-objects/file-browser/folder-tree.page';
import { RenameDialogPage } from '../page-objects/dialogs/rename-dialog.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';

/**
 * Full Workflow E2E Test Suite
 *
 * Comprehensive test session that:
 * 1. Logs in once via Web3Auth
 * 2. Creates a realistic folder hierarchy
 * 3. Uploads multiple files at various folder levels (12+ files)
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
  let folderTree: FolderTreePage;
  let renameDialog: RenameDialogPage;
  let confirmDialog: ConfirmDialogPage;
  let createFolderDialog: CreateFolderDialogPage;

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

  // Track current folder name for parentId lookup using a navigation stack
  const navigationStack: string[] = ['root'];
  const getCurrentFolderName = () => navigationStack[navigationStack.length - 1];

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
    folderTree = new FolderTreePage(page);
    renameDialog = new RenameDialogPage(page);
    confirmDialog = new ConfirmDialogPage(page);
    createFolderDialog = new CreateFolderDialogPage(page);
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
   */
  async function navigateIntoFolder(name: string): Promise<void> {
    await fileList.doubleClickFolder(name);
    await expect(page.locator('.breadcrumbs-current', { hasText: name })).toBeVisible({
      timeout: 10000,
    });
    navigationStack.push(name);
  }

  /**
   * Navigate back to parent folder.
   */
  async function navigateBack(): Promise<void> {
    await page.locator('.breadcrumbs-back').click();
    await page.waitForTimeout(500); // Wait for navigation
    if (navigationStack.length > 1) {
      navigationStack.pop();
    }
  }

  /**
   * Navigate to root folder.
   */
  async function navigateToRoot(): Promise<void> {
    // Click My Vault in the folder tree
    await folderTree.clickFolder('My Vault');
    await expect(page.locator('.breadcrumbs-current', { hasText: 'My Vault' })).toBeVisible({
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

  /**
   * Get the current folder ID from our tracked folder IDs.
   * Returns 'root' for the root folder.
   */
  function getTrackedFolderId(): string {
    const folderName = getCurrentFolderName();
    if (folderName === 'root') {
      return 'root';
    }
    const folderId = folderIds[folderName];
    if (!folderId) {
      throw new Error(
        `Folder ID not tracked for "${folderName}". Tracked folders: ${Object.keys(folderIds).join(', ')}`
      );
    }
    return folderId;
  }

  // ============================================
  // Phase 1: Login
  // ============================================

  test('1.1 Login with Web3Auth credentials', async () => {
    expect(TEST_CREDENTIALS.email, 'WEB3AUTH_TEST_EMAIL must be set').toBeTruthy();
    expect(TEST_CREDENTIALS.otp, 'WEB3AUTH_TEST_OTP must be set').toBeTruthy();

    await page.goto('/');
    await loginViaEmail(page, TEST_CREDENTIALS.email, TEST_CREDENTIALS.otp);

    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.getByRole('button', { name: /logout|sign out/i })).toBeVisible();
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

  // ============================================
  // Phase 4: Move Files Between Folders
  // ============================================

  test('4.1 Move file from root to documents folder', async () => {
    // Navigate to root
    await navigateToRoot();

    // Verify file exists
    const fileToMove = rootFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Expand the workspace folder in the tree to see documents
    await folderTree.expandFolder(workspaceFolder);

    // Get the actual item ID and type for the drag data
    const itemId = await fileList.getItemId(fileToMove);
    const itemType = await fileList.getItemType(fileToMove);

    // Drag and drop file to documents folder in the tree
    await folderTree.dropOnFolder(documentsFolder, {
      id: itemId,
      type: itemType,
      parentId: 'root',
    });

    // Wait for move to complete - file should disappear from current folder
    await fileList.waitForItemToDisappear(fileToMove, { timeout: 15000 });

    // Verify file is now in documents
    await navigateIntoFolder(workspaceFolder);
    await navigateIntoFolder(documentsFolder);
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
  });

  test('4.2 Move file from documents to images folder', async () => {
    // We're in documents folder from previous test
    const fileToMove = documentFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Get the actual item ID, type, and parent folder ID for the drag data
    const itemId = await fileList.getItemId(fileToMove);
    const itemType = await fileList.getItemType(fileToMove);
    const parentId = getTrackedFolderId();

    // Move to images (sibling folder)
    await folderTree.dropOnFolder(imagesFolder, {
      id: itemId,
      type: itemType,
      parentId,
    });

    await fileList.waitForItemToDisappear(fileToMove, { timeout: 15000 });

    // Verify file is in images
    await navigateBack(); // Back to workspace
    await navigateIntoFolder(imagesFolder);
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
  });

  test('4.3 Move file from images to projects/active folder', async () => {
    // We're in images folder
    const fileToMove = imageFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Expand projects to see active
    await folderTree.expandFolder(projectsFolder);

    // Get the actual item ID, type, and parent folder ID for the drag data
    const itemId = await fileList.getItemId(fileToMove);
    const itemType = await fileList.getItemType(fileToMove);
    const parentId = getTrackedFolderId();

    // Move to projects/active (nested folder)
    await folderTree.dropOnFolder(activeFolder, {
      id: itemId,
      type: itemType,
      parentId,
    });

    await fileList.waitForItemToDisappear(fileToMove, { timeout: 15000 });

    // Verify file is in projects/active
    await navigateBack(); // Back to workspace
    await navigateIntoFolder(projectsFolder);
    await navigateIntoFolder(activeFolder);
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
  });

  test('4.4 Move file between archive and active projects', async () => {
    // Navigate to archive
    await navigateBack(); // Back to projects
    await navigateIntoFolder(archiveFolder);

    const fileToMove = archiveProjectFiles[0].name;
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);

    // Get the actual item ID, type, and parent folder ID for the drag data
    const itemId = await fileList.getItemId(fileToMove);
    const itemType = await fileList.getItemType(fileToMove);
    const parentId = getTrackedFolderId();

    // Move to active folder
    await folderTree.dropOnFolder(activeFolder, {
      id: itemId,
      type: itemType,
      parentId,
    });

    await fileList.waitForItemToDisappear(fileToMove, { timeout: 15000 });

    // Verify file is in active
    await navigateBack(); // Back to projects
    await navigateIntoFolder(activeFolder);
    expect(await fileList.isItemVisible(fileToMove)).toBe(true);
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
    const filesToDelete = [
      rootFiles[1].name, // This was renamed
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
    const logoutButton = page.getByRole('button', { name: /logout|sign out/i });
    await expect(logoutButton).toBeVisible();
    await logoutButton.click();

    await expect(page).toHaveURL(/localhost:\d+\/?$/);
    await expect(
      page.getByRole('button', { name: /sign in|login|continue with google/i })
    ).toBeVisible({ timeout: 10000 });
  });
});
