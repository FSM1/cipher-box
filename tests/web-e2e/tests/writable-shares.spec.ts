import { test, expect, Browser } from '@playwright/test';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  navigateToFiles,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Writable Shares E2E Test Suite
 *
 * Tests write-permission sharing flows: permission toggle, recipient write
 * operations (upload, mkdir, rename, delete), permission upgrade/downgrade,
 * owner edits of recipient-uploaded files, and post-downgrade read access.
 *
 * Accounts:
 * - Alice: folder owner (creates content and shares with write permission)
 * - Bob: write-share recipient (performs write operations in shared folder)
 */
test.describe.serial('Writable Shares', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let bob: WalletTestAccount;

  // Page objects
  let aliceFileList: FileListPage;
  let aliceUploadZone: UploadZonePage;
  let aliceContextMenu: ContextMenuPage;
  let aliceCreateFolderDialog: CreateFolderDialogPage;
  let aliceShareDialog: ShareDialogPage;

  let bobSharedBrowser: SharedFileBrowserPage;
  let bobContextMenu: ContextMenuPage;

  // Test data - unique per run
  const runId = Date.now().toString();
  const folderName = `write-share-${runId}`;
  const ownerFileName = `owner-file-${runId}.txt`;
  const ownerFileContent = 'Original content by Alice';
  const recipientFileName = `recipient-file-${runId}.txt`;
  const recipientSubfolderName = `bob-subfolder-${runId}`;

  function truncateKey(key: string): string {
    const hex = key.startsWith('0x') ? key.slice(2) : key;
    return `0x${hex.slice(0, 4)}...${hex.slice(-4)}`;
  }

  // ============================================
  // Alice helpers
  // ============================================

  async function aliceCreateFolder(name: string): Promise<void> {
    const newFolderButton = alice.page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await aliceCreateFolderDialog.waitForOpen();
    await aliceCreateFolderDialog.createFolder(name);
    await aliceFileList.waitForItemToAppear(name, { timeout: 30000 });
  }

  async function aliceUploadFile(fileName: string, content: string): Promise<void> {
    const testFile = createTestTextFile(fileName, content);
    await aliceUploadZone.uploadFile(testFile.path);
    await Promise.race([
      aliceFileList.waitForItemToAppear(fileName, { timeout: 30000 }),
      alice.page
        .locator('[role="alert"]')
        .waitFor({ state: 'visible', timeout: 30000 })
        .then(async () => {
          const alertText = await alice.page.locator('[role="alert"]').textContent();
          throw new Error(`Upload failed with alert: ${alertText}`);
        }),
    ]);
  }

  async function aliceNavigateIntoFolder(name: string): Promise<void> {
    await aliceFileList.doubleClickFolder(name);
    await alice.page.locator('.breadcrumb-item', { hasText: name.toLowerCase() }).waitFor({
      state: 'visible',
      timeout: 30000,
    });
  }

  async function aliceNavigateBack(): Promise<void> {
    await alice.page.locator('[data-testid="parent-dir-row"]').dblclick();
    await alice.page.waitForTimeout(500);
  }

  async function aliceOpenShareDialog(itemName: string): Promise<void> {
    await aliceFileList.rightClickItem(itemName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
    await aliceShareDialog.waitForRecipientsLoaded();
  }

  // ============================================
  // Setup and Teardown
  // ============================================

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (alice || bob) {
      await closeWalletTestAccounts([alice, bob].filter(Boolean));
    }
  });

  // ============================================
  // Phase 1: Account Setup & Content Creation
  // ============================================

  test('1.1 Create test accounts (Alice, Bob)', async () => {
    test.setTimeout(300_000);
    alice = await createWalletTestAccount(browser, 'alice');
    bob = await createWalletTestAccount(browser, 'bob');

    aliceFileList = new FileListPage(alice.page);
    aliceUploadZone = new UploadZonePage(alice.page);
    aliceContextMenu = new ContextMenuPage(alice.page);
    aliceCreateFolderDialog = new CreateFolderDialogPage(alice.page);
    aliceShareDialog = new ShareDialogPage(alice.page);

    bobSharedBrowser = new SharedFileBrowserPage(bob.page);
    bobContextMenu = new ContextMenuPage(bob.page);

    expect(alice.publicKey).not.toBe(bob.publicKey);
  });

  test('1.2 Alice creates a folder with a text file', async () => {
    await aliceCreateFolder(folderName);
    await aliceNavigateIntoFolder(folderName);
    await aliceUploadFile(ownerFileName, ownerFileContent);
    await aliceNavigateBack();
  });

  // ============================================
  // Phase 2: Write Share Creation
  // ============================================

  test('2.1 Alice shares folder with Bob using WRITE permission', async () => {
    await aliceOpenShareDialog(folderName);

    // Select write permission
    const writeBtn = alice.page.locator('.share-perm-btn', { hasText: '[ READ-WRITE ]' });
    await writeBtn.click();
    await expect(writeBtn).toHaveClass(/share-perm-btn--active/);

    // Share with Bob
    await aliceShareDialog.shareWithKey(bob.publicKey);
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 60000 });
    expect(successText).toContain(truncateKey(bob.publicKey));
    expect(successText).toContain('read-write');

    // Verify recipient shows [write] label
    const recipientRow = aliceShareDialog.recipientRow(truncateKey(bob.publicKey));
    await expect(recipientRow).toBeVisible();
    const permLabel = recipientRow.locator('.recipient-perm-write');
    await expect(permLabel).toContainText('[write]');

    await aliceShareDialog.close();
  });

  test('2.2 Bob sees the shared folder with [RW] badge', async () => {
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.waitForSharedItem(folderName, { timeout: 15000 });

    // Verify [RW] badge (not [RO])
    const rwBadge = bobSharedBrowser.getSharedItem(folderName).locator('.shared-rw-badge');
    await expect(rwBadge).toBeVisible();
    await expect(rwBadge).toContainText('[RW]');
  });

  // ============================================
  // Phase 3: Recipient Write Operations
  // ============================================

  test('3.1 Bob navigates into write-shared folder and sees write toolbar', async () => {
    await bobSharedBrowser.navigateIntoFolder(folderName);

    // Verify existing file is visible
    const itemNames = await bobSharedBrowser.getFolderItemNames();
    expect(itemNames).toContain(ownerFileName);

    // Verify write toolbar buttons are visible
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    const mkdirBtn = bob.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await expect(uploadBtn).toBeVisible();
    await expect(mkdirBtn).toBeVisible();
  });

  test('3.2 Bob uploads a file to the shared folder', async () => {
    test.setTimeout(60000);

    // Create and upload a text file
    const testFile = createTestTextFile(recipientFileName, 'Content uploaded by Bob');
    const fileInput = bob.page.locator('input[type="file"]');
    await fileInput.setInputFiles(testFile.path);

    // Wait for the file to appear in the listing
    await bobSharedBrowser.getFolderItem(recipientFileName).waitFor({
      state: 'visible',
      timeout: 30000,
    });
  });

  test('3.3 Bob creates a subfolder in the shared folder', async () => {
    test.setTimeout(60000);

    const mkdirBtn = bob.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await mkdirBtn.click();

    // SharedFileBrowser uses an inline input (not a modal dialog)
    const folderInput = bob.page.locator('.shared-inline-input-field');
    await folderInput.waitFor({ state: 'visible', timeout: 5000 });
    await folderInput.fill(recipientSubfolderName);
    await folderInput.press('Enter');

    // Wait for subfolder to appear
    await bobSharedBrowser.getFolderItem(recipientSubfolderName).waitFor({
      state: 'visible',
      timeout: 30000,
    });
  });

  test('3.4 Bob can open and edit the file he uploaded', async () => {
    test.setTimeout(60000);

    // Right-click the file and open text editor
    await bobSharedBrowser.rightClickFolderItem(recipientFileName);
    await bobContextMenu.waitForOpen();

    // Click "Edit" or "View" in context menu
    const editOption = bob.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await editOption.click();

    // Wait for text editor dialog to open
    const textEditor = bob.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 15000 });

    // Wait for content to load (loading spinner gone)
    await bob.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    // Verify content loaded
    const textarea = bob.page.locator('.text-editor-textarea');
    await expect(textarea).toBeVisible();
    const content = await textarea.inputValue();
    expect(content).toBe('Content uploaded by Bob');

    // Edit the content
    await textarea.fill('Edited content by Bob');

    // Save via Ctrl+S
    await bob.page.keyboard.press('Control+s');

    // Wait for dialog to close (save completes)
    await textEditor.waitFor({ state: 'hidden', timeout: 30000 });
  });

  // ============================================
  // Phase 4: Owner Reads Recipient Uploads
  // ============================================

  test("4.1 Alice can see Bob's uploaded file in her folder", async () => {
    test.setTimeout(90000);

    // Navigate to Alice's files — reload to pick up IPNS propagation from Bob's writes
    await navigateToFiles(alice);
    await alice.page.reload({ waitUntil: 'networkidle' });
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 30000 });
    await aliceNavigateIntoFolder(folderName);

    // Wait for Bob's file to appear (IPNS propagation may take a few seconds)
    await aliceFileList.waitForItemToAppear(recipientFileName, { timeout: 60000 });
    expect(await aliceFileList.isItemVisible(recipientFileName)).toBe(true);

    // Also verify Bob's subfolder
    expect(await aliceFileList.isItemVisible(recipientSubfolderName)).toBe(true);
  });

  test("4.2 Alice can open and read Bob's uploaded file", async () => {
    test.setTimeout(60000);

    await aliceFileList.rightClickItem(recipientFileName);
    await aliceContextMenu.waitForOpen();

    const editOption = alice.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await editOption.click();

    const textEditor = alice.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 15000 });
    await alice.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    const textarea = alice.page.locator('.text-editor-textarea');
    const content = await textarea.inputValue();
    expect(content).toBe('Edited content by Bob');

    // Close without saving
    await alice.page.keyboard.press('Escape');
    await textEditor.waitFor({ state: 'hidden', timeout: 5000 });
  });

  test("4.3 Alice edits Bob's file and Bob can still read it", async () => {
    test.setTimeout(90000);

    // Alice edits the file
    await aliceFileList.rightClickItem(recipientFileName);
    await aliceContextMenu.waitForOpen();
    const editOption = alice.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await editOption.click();

    const textEditor = alice.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 15000 });
    await alice.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    const textarea = alice.page.locator('.text-editor-textarea');
    await textarea.fill('Re-edited by Alice');
    await alice.page.keyboard.press('Control+s');
    await textEditor.waitFor({ state: 'hidden', timeout: 30000 });

    // Navigate back to root
    await aliceNavigateBack();

    // Bob refreshes and reads the file
    // Navigate Bob back to shared root and re-enter the folder
    await bobSharedBrowser.navigateToRoot();
    await bobSharedBrowser.waitForLoaded({ timeout: 15000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);

    // Open the file Bob uploaded (now edited by Alice)
    await bobSharedBrowser.rightClickFolderItem(recipientFileName);
    await bobContextMenu.waitForOpen();
    const bobEditOption = bob.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await bobEditOption.click();

    const bobTextEditor = bob.page.locator('.text-editor-modal');
    await bobTextEditor.waitFor({ state: 'visible', timeout: 15000 });
    await bob.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    const bobTextarea = bob.page.locator('.text-editor-textarea');
    const bobContent = await bobTextarea.inputValue();
    expect(bobContent).toBe('Re-edited by Alice');

    await bob.page.keyboard.press('Escape');
    await bobTextEditor.waitFor({ state: 'hidden', timeout: 5000 });
  });

  // ============================================
  // Phase 5: Permission Downgrade
  // ============================================

  test('5.1 Alice downgrades Bob from write to read-only', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 15000 });
    await aliceOpenShareDialog(folderName);

    // Find Bob's recipient row and click downgrade
    const bobRow = aliceShareDialog.recipientRow(truncateKey(bob.publicKey));
    await expect(bobRow).toBeVisible();

    const downgradeBtn = bobRow.locator('.share-downgrade-btn');
    await downgradeBtn.click();

    // Confirm downgrade
    const confirmBtn = bobRow.locator('.share-revoke-confirm-btn--yes');
    await confirmBtn.click();

    // Wait for permission label to change to [read]
    const permLabel = bobRow.locator('.recipient-perm-read');
    await expect(permLabel).toContainText('[read]', { timeout: 10000 });

    // Verify upgrade button now appears
    const upgradeBtn = bobRow.locator('.share-upgrade-btn');
    await expect(upgradeBtn).toBeVisible();

    await aliceShareDialog.close();
  });

  test('5.2 Bob sees [RO] badge after downgrade', async () => {
    // Navigate Bob back to shared root
    await bobSharedBrowser.navigateToRoot();
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.waitForSharedItem(folderName, { timeout: 15000 });

    // Badge should now be [RO]
    const roBadge = bobSharedBrowser.getReadOnlyBadge(folderName);
    await expect(roBadge).toBeVisible({ timeout: 10000 });
  });

  test('5.3 Bob can still read files after downgrade', async () => {
    test.setTimeout(60000);

    await bobSharedBrowser.navigateIntoFolder(folderName);

    // Write toolbar should NOT be visible
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).not.toBeVisible();

    // Bob should still be able to read the file
    await bobSharedBrowser.rightClickFolderItem(recipientFileName);
    await bobContextMenu.waitForOpen();
    const viewOption = bob.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await viewOption.click();

    const textEditor = bob.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 15000 });
    await bob.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    // Content should be readable (Alice's last edit)
    const textarea = bob.page.locator('.text-editor-textarea');
    const content = await textarea.inputValue();
    expect(content).toBe('Re-edited by Alice');

    // Textarea should be read-only
    await expect(textarea).toHaveAttribute('readonly', '');

    await bob.page.keyboard.press('Escape');
    await textEditor.waitFor({ state: 'hidden', timeout: 5000 });
  });

  // ============================================
  // Phase 6: Permission Upgrade
  // ============================================

  test('6.1 Alice upgrades Bob back to write permission', async () => {
    test.setTimeout(60000);

    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 15000 });
    await aliceOpenShareDialog(folderName);

    const bobRow = aliceShareDialog.recipientRow(truncateKey(bob.publicKey));
    const upgradeBtn = bobRow.locator('.share-upgrade-btn');
    await upgradeBtn.click();

    // Wait for permission label to change back to [write]
    const permLabel = bobRow.locator('.recipient-perm-write');
    await expect(permLabel).toContainText('[write]', { timeout: 15000 });

    // Downgrade button should be visible again
    const downgradeBtn = bobRow.locator('.share-downgrade-btn');
    await expect(downgradeBtn).toBeVisible();

    await aliceShareDialog.close();
  });

  test('6.2 Bob sees [RW] badge after upgrade and can write again', async () => {
    test.setTimeout(60000);

    await bobSharedBrowser.navigateToRoot();
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.waitForSharedItem(folderName, { timeout: 15000 });

    // Badge should be [RW] again
    const rwBadge = bobSharedBrowser.getSharedItem(folderName).locator('.shared-rw-badge');
    await expect(rwBadge).toBeVisible({ timeout: 10000 });

    // Enter folder and verify write toolbar
    await bobSharedBrowser.navigateIntoFolder(folderName);
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).toBeVisible();
  });

  // ============================================
  // Phase 7: Rename and Delete by Recipient
  // ============================================

  test('7.1 Bob renames a file in the shared folder', async () => {
    test.setTimeout(60000);

    // Right-click the file Bob created
    await bobSharedBrowser.rightClickFolderItem(recipientFileName);
    await bobContextMenu.waitForOpen();

    const renameOption = bob.page.locator('.context-menu-item', { hasText: /rename/i });
    await renameOption.click();

    // SharedFileBrowser uses an inline rename field
    const renameInput = bob.page.locator('.shared-inline-rename-field');
    await renameInput.waitFor({ state: 'visible', timeout: 5000 });
    const renamedFileName = `renamed-${runId}.txt`;
    await renameInput.fill(renamedFileName);
    await renameInput.press('Enter');

    // Wait for renamed file to appear
    await bobSharedBrowser.getFolderItem(renamedFileName).waitFor({
      state: 'visible',
      timeout: 15000,
    });

    // Old name should be gone
    await expect(bobSharedBrowser.getFolderItem(recipientFileName)).not.toBeVisible();
  });

  test('7.2 Bob deletes the subfolder he created', async () => {
    test.setTimeout(60000);

    await bobSharedBrowser.rightClickFolderItem(recipientSubfolderName);
    await bobContextMenu.waitForOpen();

    const deleteOption = bob.page.locator('.context-menu-item', { hasText: /delete/i });
    await deleteOption.click();

    // Confirm deletion if there's a confirmation dialog
    const confirmBtn = bob.page.locator('.confirm-delete-btn, .modal-confirm-btn');
    if (await confirmBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await confirmBtn.click();
    }

    // Wait for subfolder to disappear
    await expect(bobSharedBrowser.getFolderItem(recipientSubfolderName)).not.toBeVisible({
      timeout: 15000,
    });
  });

  // ============================================
  // Phase 8: Security — Subfolder Access (C-02)
  // ============================================

  test('8.1 Owner can navigate into subfolder created by recipient', async () => {
    test.setTimeout(90000);

    // Bob creates a subfolder (re-create since 7.2 deleted the previous one)
    const securitySubfolder = `sec-subfolder-${runId}`;
    const mkdirBtn = bob.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await mkdirBtn.click();
    const folderInput = bob.page.locator('.shared-inline-input-field');
    await folderInput.waitFor({ state: 'visible', timeout: 5000 });
    await folderInput.fill(securitySubfolder);
    await folderInput.press('Enter');
    // A recipient mkdir is a full shared-write -> IPNS publish -> re-resolve
    // round-trip (the highest-latency path); under parallel-worker CI load it can
    // exceed 30s. Use the same 60s budget the owner-side shared waits use below.
    await bobSharedBrowser.getFolderItem(securitySubfolder).waitFor({
      state: 'visible',
      timeout: 60000,
    });

    // Alice navigates to her folder and enters the subfolder Bob created
    // C-02 fix: subfolder keys must be wrapped with owner's key so owner can access
    await navigateToFiles(alice);
    await alice.page.reload({ waitUntil: 'networkidle' });
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 30000 });
    await aliceNavigateIntoFolder(folderName);
    await aliceFileList.waitForItemToAppear(securitySubfolder, { timeout: 60000 });

    // Owner should be able to enter the subfolder without decryption errors
    await aliceNavigateIntoFolder(securitySubfolder);

    // Should see empty folder (no errors, breadcrumbs should show subfolder)
    const breadcrumbs = await alice.page.locator('.breadcrumb-item').allTextContents();
    const breadcrumbText = breadcrumbs.join('/').toLowerCase();
    expect(breadcrumbText).toContain(securitySubfolder.toLowerCase());

    // Navigate back to root via Files nav link
    await navigateToFiles(alice);
  });

  // ============================================
  // Phase 8b: Deep Subfolder Write Operations
  // ============================================

  const deepSubfolder = `deep-sub-${runId}`;
  const deepFileName = `deep-file-${runId}.txt`;
  const nestedSubfolder = `nested-sub-${runId}`;
  const nestedFileName = `nested-file-${runId}.txt`;

  test('8.2 Bob uploads a file inside the subfolder he created', async () => {
    test.setTimeout(90000);

    // Bob should be at the shared folder root — navigate there if needed
    await bobSharedBrowser.navigateToRoot();
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);

    // Create a new subfolder for deep-write testing (the previous one was deleted in 7.2)
    const mkdirBtn = bob.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await mkdirBtn.click();
    const folderInput = bob.page.locator('.shared-inline-input-field');
    await folderInput.waitFor({ state: 'visible', timeout: 5000 });
    await folderInput.fill(deepSubfolder);
    await folderInput.press('Enter');
    // Shared-write mkdir round-trip: use the 60s CI budget (see 8.1).
    await bobSharedBrowser.getFolderItem(deepSubfolder).waitFor({
      state: 'visible',
      timeout: 60000,
    });

    // Navigate into the subfolder (wait for breadcrumbs to confirm navigation completed)
    await bobSharedBrowser.navigateIntoSubfolder(deepSubfolder);

    // Write toolbar should be visible (subfolder write access via folder-ipns key)
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });

    // Upload a file inside the subfolder
    const testFile = createTestTextFile(deepFileName, 'Deep subfolder content by Bob');
    const fileInput = bob.page.locator('input[type="file"]');
    await fileInput.setInputFiles(testFile.path);
    await bobSharedBrowser.getFolderItem(deepFileName).waitFor({
      state: 'visible',
      timeout: 30000,
    });
  });

  test('8.3 Bob creates a nested subfolder (depth 2) and uploads a file', async () => {
    test.setTimeout(90000);

    // Still inside deepSubfolder from previous test — create a nested subfolder
    const mkdirBtn = bob.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await mkdirBtn.click();
    const folderInput = bob.page.locator('.shared-inline-input-field');
    await folderInput.waitFor({ state: 'visible', timeout: 5000 });
    await folderInput.fill(nestedSubfolder);
    await folderInput.press('Enter');
    await bobSharedBrowser.getFolderItem(nestedSubfolder).waitFor({
      state: 'visible',
      timeout: 30000,
    });

    // Navigate into the nested subfolder (now at depth 2)
    await bobSharedBrowser.navigateIntoSubfolder(nestedSubfolder);

    // Write toolbar should be visible at depth 2
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });

    // Upload a file at depth 2
    const testFile = createTestTextFile(nestedFileName, 'Nested subfolder content by Bob');
    const fileInput = bob.page.locator('input[type="file"]');
    await fileInput.setInputFiles(testFile.path);
    await bobSharedBrowser.getFolderItem(nestedFileName).waitFor({
      state: 'visible',
      timeout: 30000,
    });

    // Verify breadcrumbs show the full path
    const breadcrumbPath = await bobSharedBrowser.getBreadcrumbPath();
    expect(breadcrumbPath.toLowerCase()).toContain(deepSubfolder.toLowerCase());
    expect(breadcrumbPath.toLowerCase()).toContain(nestedSubfolder.toLowerCase());
  });

  test('8.4 Bob navigates back to root and re-enters subfolder with write access', async () => {
    test.setTimeout(90000);

    // Navigate all the way back to shared root
    await bobSharedBrowser.navigateToRoot();
    await bobSharedBrowser.waitForLoaded({ timeout: 15000 });

    // Re-enter the folder
    await bobSharedBrowser.navigateIntoFolder(folderName);

    // Root level should have write access
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });

    // Navigate into the subfolder — write access should be restored via folder-ipns key
    await bobSharedBrowser.navigateIntoSubfolder(deepSubfolder);
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });

    // Verify the file we uploaded earlier is still there
    await bobSharedBrowser.getFolderItem(deepFileName).waitFor({
      state: 'visible',
      timeout: 15000,
    });

    // Navigate into nested subfolder — write access at depth 2
    await bobSharedBrowser.navigateIntoSubfolder(nestedSubfolder);
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });

    // Verify the file at depth 2
    await bobSharedBrowser.getFolderItem(nestedFileName).waitFor({
      state: 'visible',
      timeout: 15000,
    });

    // Navigate back to shared folder root for subsequent tests
    await bobSharedBrowser.navigateToRoot();
    await bobSharedBrowser.waitForLoaded({ timeout: 15000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);
  });

  // SC1 (73-RESEARCH.md): navigateUp/navigateToBreadcrumb previously only
  // re-derived a writeKey when restoring the SHARE ROOT (the old
  // `isRootDepth` branch in useSharedNavigationActions.ts) -- any non-root
  // restore depth seeded a zero-buffer writeKey (`new Uint8Array(32)`
  // fallback in shared-folder-projection.ts's `seedSharedFolder`), so a
  // write performed right after an UP-ONE-LEVEL restore (not a full
  // round-trip back to root) silently failed its GCM auth tag check. Test
  // 8.4 above only covers DESCEND-then-write (full return to root, then
  // back down) -- it never navigates UP from depth 2 to depth 1 and writes
  // from THAT restored level. This was the exact gap flagged against 8.4.
  //
  // Plan 73-07 closed the gap: useSharedNavigationActions.ts's consolidated
  // restore helper (SC6) now caches each depth's writeKey in NavStackEntry
  // and transfers it on restore instead of the old isRootDepth branch (see
  // 73-RESEARCH.md SC1).
  test('8.4b Bob navigates up one level then writes from the restored subfolder (SC1)', async () => {
    test.setTimeout(90000);

    // Reuse 8.3's depth-2 descent: folderName -> deepSubfolder -> nestedSubfolder.
    await bobSharedBrowser.navigateToRoot();
    await bobSharedBrowser.waitForLoaded({ timeout: 15000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);
    await bobSharedBrowser.navigateIntoSubfolder(deepSubfolder);
    await bobSharedBrowser.navigateIntoSubfolder(nestedSubfolder);

    // Navigate UP exactly ONE level -- back to deepSubfolder (depth 1),
    // NOT all the way to root. This is the restore path that currently
    // seeds a zero-buffer writeKey for any non-root depth.
    await bobSharedBrowser.navigateUp();
    await expect(bobSharedBrowser.breadcrumbs().locator('.breadcrumb-item--current')).toHaveText(
      deepSubfolder,
      { ignoreCase: true, timeout: 30000 }
    );

    // Write from the restored depth-1 folder MUST SUCCEED -- no GCM-auth /
    // write-key error toast. Upload a new file (mirrors 8.3's pattern).
    const restoredWriteFileName = `restored-depth1-write-${runId}.txt`;
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });
    const testFile = createTestTextFile(
      restoredWriteFileName,
      'Written after up-one-level restore (SC1)'
    );
    const fileInput = bob.page.locator('input[type="file"]');
    await fileInput.setInputFiles(testFile.path);

    // Assert SUCCESS: the file appears, and no write-key/GCM-auth error
    // toast is surfaced.
    await bobSharedBrowser.getFolderItem(restoredWriteFileName).waitFor({
      state: 'visible',
      timeout: 30000,
    });
    await expect(bob.page.locator('[role="alert"]')).toHaveCount(0);

    // Restore navigation state for subsequent tests.
    await bobSharedBrowser.navigateToRoot();
    await bobSharedBrowser.waitForLoaded({ timeout: 15000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);
  });

  test('8.5 Alice can read files at all depths created by Bob', async () => {
    test.setTimeout(90000);

    // Navigate Alice into the shared folder
    await navigateToFiles(alice);
    await alice.page.reload({ waitUntil: 'networkidle' });
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 30000 });
    await aliceNavigateIntoFolder(folderName);

    // Alice should see the deepSubfolder
    await aliceFileList.waitForItemToAppear(deepSubfolder, { timeout: 60000 });
    await aliceNavigateIntoFolder(deepSubfolder);

    // Alice should see Bob's file and the nested subfolder
    await aliceFileList.waitForItemToAppear(deepFileName, { timeout: 30000 });
    await aliceFileList.waitForItemToAppear(nestedSubfolder, { timeout: 15000 });

    // Navigate into nested subfolder
    await aliceNavigateIntoFolder(nestedSubfolder);
    await aliceFileList.waitForItemToAppear(nestedFileName, { timeout: 30000 });

    // Navigate back to root
    await navigateToFiles(alice);
  });

  // ============================================
  // Phase 9: Security — Post-Downgrade Behavior (H-03)
  // ============================================

  test('9.1 After downgrade, recipient write toolbar is hidden', async () => {
    // Downgrade Bob again
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 15000 });
    await aliceOpenShareDialog(folderName);

    const bobRow = aliceShareDialog.recipientRow(truncateKey(bob.publicKey));
    const downgradeBtn = bobRow.locator('.share-downgrade-btn');
    await downgradeBtn.click();
    const confirmBtn = bobRow.locator('.share-revoke-confirm-btn--yes');
    await confirmBtn.click();
    const permLabel = bobRow.locator('.recipient-perm-read');
    await expect(permLabel).toContainText('[read]', { timeout: 10000 });
    await aliceShareDialog.close();

    // Bob re-enters the shared folder
    await bobSharedBrowser.navigateToRoot();
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);

    // Write toolbar should be hidden (H-03: downgrade removes write capability)
    const uploadBtn = bob.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).not.toBeVisible();

    // Context menu should not show rename/delete
    const renamedFile = `renamed-${runId}.txt`;
    const targetFile = (await bobSharedBrowser.getFolderItem(renamedFile).isVisible())
      ? renamedFile
      : ownerFileName;

    await bobSharedBrowser.rightClickFolderItem(targetFile);
    await bobContextMenu.waitForOpen();
    const renameOption = bob.page.locator('.context-menu-item', { hasText: /rename/i });
    await expect(renameOption).not.toBeVisible();
    // Close context menu
    await bob.page.keyboard.press('Escape');
  });

  test('9.2 Downgraded recipient can still read files', async () => {
    test.setTimeout(60000);

    const renamedFile = `renamed-${runId}.txt`;
    const targetFile = (await bobSharedBrowser.getFolderItem(renamedFile).isVisible())
      ? renamedFile
      : ownerFileName;

    await bobSharedBrowser.rightClickFolderItem(targetFile);
    await bobContextMenu.waitForOpen();
    const viewOption = bob.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await viewOption.click();

    const textEditor = bob.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 15000 });
    await bob.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    // Should load without decryption errors
    const textarea = bob.page.locator('.text-editor-textarea');
    await expect(textarea).toBeVisible();
    const content = await textarea.inputValue();
    expect(content.length).toBeGreaterThan(0);

    // Should be read-only
    await expect(textarea).toHaveAttribute('readonly', '');

    await bob.page.keyboard.press('Escape');
    await textEditor.waitFor({ state: 'hidden', timeout: 5000 });
  });

  // ============================================
  // Phase 10: Writable File Shares
  // ============================================

  const fileShareName = `file-share-${runId}.txt`;
  const fileShareContent = 'Original file content by Alice';

  test('10.1 Alice creates a text file and shares it with Bob with WRITE permission', async () => {
    test.setTimeout(120000);

    // Navigate to Alice's root and create a file
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 15000 });

    // Upload a text file at root level
    const testFile = createTestTextFile(fileShareName, fileShareContent);
    await aliceUploadZone.uploadFile(testFile.path);
    await aliceFileList.waitForItemToAppear(fileShareName, { timeout: 30000 });

    // Share it with Bob with write permission
    await aliceFileList.rightClickItem(fileShareName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
    await aliceShareDialog.waitForRecipientsLoaded();

    // Select write permission
    const writeBtn = alice.page.locator('.share-perm-btn', { hasText: '[ READ-WRITE ]' });
    await writeBtn.click();
    await expect(writeBtn).toHaveClass(/share-perm-btn--active/);

    // Share with Bob
    await aliceShareDialog.shareWithKey(bob.publicKey);
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 60000 });
    expect(successText).toContain(truncateKey(bob.publicKey));
    expect(successText).toContain('read-write');

    await aliceShareDialog.close();
  });

  test('10.2 Bob sees the write-shared file with [RW] badge', async () => {
    test.setTimeout(60000);

    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.waitForSharedItem(fileShareName, { timeout: 15000 });

    // Verify [RW] badge
    const rwBadge = bobSharedBrowser.getSharedItem(fileShareName).locator('.shared-rw-badge');
    await expect(rwBadge).toBeVisible();
    await expect(rwBadge).toContainText('[RW]');
  });

  test('10.3 Bob opens the write-shared file and can edit it', async () => {
    test.setTimeout(90000);

    // Double-click to open the file (should auto-open text editor for text files)
    await bobSharedBrowser.doubleClickSharedItem(fileShareName);

    // Wait for text editor to open
    const textEditor = bob.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 30000 });
    await bob.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    // Should be editable (NOT read-only)
    const textarea = bob.page.locator('.text-editor-textarea');
    await expect(textarea).toBeVisible();
    const content = await textarea.inputValue();
    expect(content).toBe(fileShareContent);
    await expect(textarea).not.toHaveAttribute('readonly');

    // Edit the content
    await textarea.fill('Edited file content by Bob');

    // Wait for React to process the state change (isDirty must be true
    // before Ctrl+S fires, otherwise the stale closure skips the save)
    await bob.page
      .locator('.text-editor-status--modified')
      .waitFor({ state: 'visible', timeout: 5000 });

    // Save via Ctrl+S
    await bob.page.keyboard.press('Control+s');
    await textEditor.waitFor({ state: 'hidden', timeout: 30000 });
  });

  test('10.4 Alice can read the file edited by Bob', async () => {
    test.setTimeout(90000);

    await navigateToFiles(alice);
    await alice.page.reload({ waitUntil: 'networkidle' });
    await aliceFileList.waitForItemToAppear(fileShareName, { timeout: 30000 });

    // Open the file
    await aliceFileList.rightClickItem(fileShareName);
    await aliceContextMenu.waitForOpen();
    const editOption = alice.page.locator('.context-menu-item', { hasText: /edit|view/i });
    await editOption.click();

    const textEditor = alice.page.locator('.text-editor-modal');
    await textEditor.waitFor({ state: 'visible', timeout: 15000 });
    await alice.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 15000 });

    const textarea = alice.page.locator('.text-editor-textarea');
    const content = await textarea.inputValue();
    expect(content).toBe('Edited file content by Bob');

    await alice.page.keyboard.press('Escape');
    await textEditor.waitFor({ state: 'hidden', timeout: 5000 });
  });
});
