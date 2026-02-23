import { test, expect, Browser } from '@playwright/test';
import {
  createTestAccount,
  closeTestAccounts,
  navigateToShared,
  navigateToFiles,
  type TestAccount,
} from '../utils/multi-account';
import { createTestTextFile, createTestImageFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Sharing Workflow E2E Test Suite
 *
 * Tests user-to-user sharing with multiple authenticated accounts.
 * Each test account gets its own browser context (isolated cookies/storage).
 *
 * Accounts:
 * - Alice: primary sharer (creates content and shares it)
 * - Bob: primary recipient (receives and browses shared content)
 * - Charlie: secondary recipient (for multi-recipient tests)
 *
 * Test flow:
 * 1. Setup: Create 3 accounts, Alice creates test content
 * 2. Basic sharing: Alice shares file with Bob, Bob receives it
 * 3. Folder sharing: Alice shares folder tree, Bob navigates it
 * 4. Multi-recipient: Alice adds Charlie to existing share
 * 5. Revocation: Alice revokes Bob's access
 * 6. Post-share mutations: Alice adds files to shared folder
 * 7. Error cases: Invalid key, self-share, user not found
 * 8. Hide share: Bob hides a shared item
 */
test.describe.serial('Sharing Workflow', () => {
  let browser: Browser;
  let alice: TestAccount;
  let bob: TestAccount;
  let charlie: TestAccount;

  // Page objects per account
  let aliceFileList: FileListPage;
  let aliceUploadZone: UploadZonePage;
  let aliceContextMenu: ContextMenuPage;
  let aliceCreateFolderDialog: CreateFolderDialogPage;
  let aliceShareDialog: ShareDialogPage;

  let bobSharedBrowser: SharedFileBrowserPage;
  let bobContextMenu: ContextMenuPage;

  let charlieSharedBrowser: SharedFileBrowserPage;

  // Test data - unique per run
  const runId = Date.now().toString();

  // Shared file
  const sharedFileName = `shared-file-${runId}.txt`;
  const sharedFileContent = 'This file is shared with Bob';

  // Shared folder structure
  const sharedFolderName = `shared-folder-${runId}`;
  const subFolderName = `subfolder-${runId}`;
  const folderFile1Name = `folder-file1-${runId}.txt`;
  const folderFile2Name = `subfolder-file-${runId}.txt`;

  // Post-share file (added after share is created)
  const postShareFileName = `added-after-share-${runId}.txt`;
  const postShareFileContent = 'This file was added after the share was created';

  // Preview test files (image in shared folder)
  const sharedImageName = `test-image-${runId}.png`;

  // Helper to truncate a public key for matching in the UI
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

    // Wait for upload: check for either the file appearing or an error alert
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
    // Wait for breadcrumbs to show the folder name
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
    if (alice || bob || charlie) {
      await closeTestAccounts([alice, bob, charlie].filter(Boolean));
    }
  });

  // ============================================
  // Phase 1: Account Setup
  // ============================================

  test('1.1 Create test accounts (Alice, Bob, Charlie)', async () => {
    // Create accounts sequentially (each needs its own context + vault init)
    alice = await createTestAccount(browser, 'alice', runId);
    bob = await createTestAccount(browser, 'bob', runId);
    charlie = await createTestAccount(browser, 'charlie', runId);

    // Initialize page objects for Alice
    aliceFileList = new FileListPage(alice.page);
    aliceUploadZone = new UploadZonePage(alice.page);
    aliceContextMenu = new ContextMenuPage(alice.page);
    aliceCreateFolderDialog = new CreateFolderDialogPage(alice.page);
    aliceShareDialog = new ShareDialogPage(alice.page);

    // Initialize page objects for Bob
    bobSharedBrowser = new SharedFileBrowserPage(bob.page);
    bobContextMenu = new ContextMenuPage(bob.page);

    // Initialize page objects for Charlie
    charlieSharedBrowser = new SharedFileBrowserPage(charlie.page);

    // Verify all three accounts have different public keys
    expect(alice.publicKey).not.toBe(bob.publicKey);
    expect(alice.publicKey).not.toBe(charlie.publicKey);
    expect(bob.publicKey).not.toBe(charlie.publicKey);
  });

  // ============================================
  // Phase 2: Alice Creates Content
  // ============================================

  test('2.1 Alice creates a test file at root', async () => {
    await aliceUploadFile(sharedFileName, sharedFileContent);
    expect(await aliceFileList.isItemVisible(sharedFileName)).toBe(true);
  });

  test('2.2 Alice creates a folder with nested content', async () => {
    // Create top-level folder
    await aliceCreateFolder(sharedFolderName);
    expect(await aliceFileList.isItemVisible(sharedFolderName)).toBe(true);

    // Navigate into it and add a file + an image
    await aliceNavigateIntoFolder(sharedFolderName);
    await aliceUploadFile(folderFile1Name, 'File inside shared folder');

    // Upload a PNG image (needed for shared preview test in Phase 11)
    const testImage = createTestImageFile(sharedImageName);
    await aliceUploadZone.uploadFile(testImage.path);
    await aliceFileList.waitForItemToAppear(sharedImageName, { timeout: 30000 });

    // Create subfolder
    await aliceCreateFolder(subFolderName);

    // Navigate into subfolder and add a file
    await aliceNavigateIntoFolder(subFolderName);
    await aliceUploadFile(folderFile2Name, 'File inside subfolder');

    // Navigate back to root
    await aliceNavigateBack(); // back to shared folder
    await aliceNavigateBack(); // back to root
  });

  // ============================================
  // Phase 3: Basic File Sharing
  // ============================================

  test('3.1 Alice shares a file with Bob', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Should start with no recipients
    expect(await aliceShareDialog.getRecipientCount()).toBe(0);

    // Share with Bob
    await aliceShareDialog.shareWithKey(bob.publicKey);
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 30000 });
    expect(successText).toContain(truncateKey(bob.publicKey));

    // Verify recipient appears in the list
    expect(await aliceShareDialog.getRecipientCount()).toBe(1);
    const recipientKeys = await aliceShareDialog.getRecipientKeys();
    expect(recipientKeys[0]).toBe(truncateKey(bob.publicKey));

    await aliceShareDialog.close();
  });

  test('3.2 Bob sees the shared file in ~/shared', async () => {
    await navigateToShared(bob);

    // Wait for the shared items to load
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });

    // Bob should see Alice's shared file
    await bobSharedBrowser.waitForSharedItem(sharedFileName, { timeout: 15000 });
    expect(await bobSharedBrowser.getSharedItemCount()).toBeGreaterThanOrEqual(1);

    // Verify [RO] badge
    const roBadge = bobSharedBrowser.getReadOnlyBadge(sharedFileName);
    expect(await roBadge.isVisible()).toBe(true);

    // Verify "SHARED BY" shows Alice's truncated key
    const sharedBy = await bobSharedBrowser.getSharedBy(sharedFileName);
    expect(sharedBy).toContain(truncateKey(alice.publicKey));
  });

  // ============================================
  // Phase 4: Folder Sharing with Descendants
  // ============================================

  test('4.1 Alice shares a folder with Bob', async () => {
    // Make sure Alice is on files page
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFolderName);

    // Share with Bob - folder sharing re-wraps descendant keys
    await aliceShareDialog.shareWithKey(bob.publicKey);

    // Wait for progress (folder sharing re-wraps keys for each child)
    // The progress may be very fast for small folders, so we just wait for success
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 60000 });
    expect(successText).toContain(truncateKey(bob.publicKey));

    await aliceShareDialog.close();
  });

  test('4.2 Bob navigates the shared folder tree', async () => {
    // Navigate to Bob's shared view
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });

    // Find and open the shared folder
    await bobSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });

    // Click the shared item and wait — IPNS resolution can be slow on first access
    await bobSharedBrowser.openSharedItem(sharedFolderName);
    await bob.page.waitForTimeout(3000);

    // If IPNS resolution failed on first try, retry once
    const parentDirVisible = await bobSharedBrowser.parentDirRow().isVisible();
    if (!parentDirVisible) {
      await navigateToShared(bob);
      await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
      await bobSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
      await bobSharedBrowser.navigateIntoFolder(sharedFolderName);
    }

    // Should see folder contents: the file and subfolder
    const itemNames = await bobSharedBrowser.getFolderItemNames();
    expect(itemNames.some((n) => n.includes(folderFile1Name))).toBe(true);
    expect(itemNames.some((n) => n.includes(subFolderName))).toBe(true);

    // Navigate into subfolder
    await bobSharedBrowser.doubleClickFolderItem(subFolderName);
    // Wait for subfolder content to load
    await bob.page.waitForTimeout(2000);

    const subItems = await bobSharedBrowser.getFolderItemNames();
    expect(subItems.some((n) => n.includes(folderFile2Name))).toBe(true);

    // Navigate back to shared root
    await bobSharedBrowser.navigateToRoot();
    await bobSharedBrowser.waitForLoaded({ timeout: 15000 });
  });

  // ============================================
  // Phase 5: Multi-Recipient (Add Charlie)
  // ============================================

  test('5.1 Alice adds Charlie as a second recipient', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFolderName);

    // Bob should already be a recipient
    await aliceShareDialog.waitForRecipientsLoaded();
    expect(await aliceShareDialog.getRecipientCount()).toBe(1);

    // Add Charlie
    await aliceShareDialog.shareWithKey(charlie.publicKey);
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 60000 });
    expect(successText).toContain(truncateKey(charlie.publicKey));

    // Now should have 2 recipients
    expect(await aliceShareDialog.getRecipientCount()).toBe(2);

    await aliceShareDialog.close();
  });

  test('5.2 Charlie sees the shared folder', async () => {
    await navigateToShared(charlie);
    await charlieSharedBrowser.waitForLoaded({ timeout: 30000 });

    await charlieSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
    expect(await charlieSharedBrowser.getSharedItemCount()).toBeGreaterThanOrEqual(1);
  });

  // ============================================
  // Phase 6: Revoke Access
  // ============================================

  test("6.1 Alice revokes Bob's access to the shared folder", async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFolderName);
    await aliceShareDialog.waitForRecipientsLoaded();

    // Should have 2 recipients (Bob + Charlie)
    expect(await aliceShareDialog.getRecipientCount()).toBe(2);

    // Revoke Bob
    const bobTruncated = truncateKey(bob.publicKey);
    await aliceShareDialog.revokeRecipient(bobTruncated);

    // Should now have 1 recipient (Charlie only)
    expect(await aliceShareDialog.getRecipientCount()).toBe(1);

    await aliceShareDialog.close();
  });

  test('6.2 Bob no longer sees the shared folder', async () => {
    // Reload Bob's shared view to get fresh data
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });

    // The shared folder should no longer appear for Bob
    // (may still show the shared file from test 3.1)
    const itemNames = await bobSharedBrowser.getSharedItemNames();
    const hasFolderShare = itemNames.some((n) => n.includes(sharedFolderName));
    expect(hasFolderShare).toBe(false);
  });

  test('6.3 Charlie still has access', async () => {
    await navigateToShared(charlie);
    await charlieSharedBrowser.waitForLoaded({ timeout: 30000 });

    await charlieSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
    expect(await charlieSharedBrowser.getSharedItemCount()).toBeGreaterThanOrEqual(1);
  });

  // ============================================
  // Phase 7: Post-Share Mutations
  // ============================================

  test('7.1 Alice adds a file to the shared folder after sharing', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });

    // Navigate into the shared folder
    await aliceNavigateIntoFolder(sharedFolderName);

    // Upload a new file
    await aliceUploadFile(postShareFileName, postShareFileContent);
    expect(await aliceFileList.isItemVisible(postShareFileName)).toBe(true);

    // Navigate back
    await aliceNavigateBack();
  });

  test('7.2 Charlie sees the newly added file', async () => {
    // Wait briefly for any background operations from 7.1 to settle
    await charlie.page.waitForTimeout(2000);

    // Navigate Charlie into the shared folder to check for the new file
    await navigateToShared(charlie);
    await charlieSharedBrowser.waitForLoaded({ timeout: 30000 });

    await charlieSharedBrowser.navigateIntoFolder(sharedFolderName);

    // Wait for folder contents - the new file should be visible
    const itemNames = await charlieSharedBrowser.getFolderItemNames();
    expect(itemNames.some((n) => n.includes(postShareFileName))).toBe(true);

    await charlieSharedBrowser.navigateToRoot();
  });

  test('7.3 Charlie can preview the post-share file (re-wrapping verification)', async () => {
    // This test verifies the re-wrapping fix: files uploaded AFTER sharing
    // must have their keys re-wrapped for recipients. Without the fix,
    // Charlie would see "No re-wrapped file key available" error.
    await navigateToShared(charlie);
    await charlieSharedBrowser.waitForLoaded({ timeout: 30000 });
    await charlieSharedBrowser.navigateIntoFolder(sharedFolderName);

    // Wait for the post-share file to be visible
    await charlieSharedBrowser
      .getFolderItem(postShareFileName)
      .waitFor({ state: 'visible', timeout: 15000 });

    // Right-click and preview the text file
    await charlieSharedBrowser.rightClickFolderItem(postShareFileName);
    const charlieContextMenu = new ContextMenuPage(charlie.page);
    await charlieContextMenu.waitForOpen();
    await charlieContextMenu.clickPreview();

    // The text editor dialog should open in read-only mode
    const editorDialog = charlie.page.locator('.text-editor-modal');
    await editorDialog.waitFor({ state: 'visible', timeout: 30000 });

    // Verify the content loaded (not an error message)
    const textarea = charlie.page.locator('.text-editor-textarea');
    await textarea.waitFor({ state: 'visible', timeout: 15000 });
    const content = await textarea.inputValue();
    expect(content).toContain('added after the share');

    // Close the dialog
    await charlie.page.locator('.text-editor-modal .modal-close').click();
    await editorDialog.waitFor({ state: 'hidden' });

    await charlieSharedBrowser.navigateToRoot();
  });

  // ============================================
  // Phase 8: Error Cases
  // ============================================

  test('8.1 Invalid public key format shows error', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFileName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFileName);

    // Try an invalid key
    await aliceShareDialog.shareWithKey('0x1234invalid');
    const errorText = await aliceShareDialog.waitForError();
    expect(errorText).toContain('invalid key format');

    await aliceShareDialog.close();
  });

  test('8.2 Self-sharing shows error', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Try sharing with own key
    await aliceShareDialog.shareWithKey(alice.publicKey);
    const errorText = await aliceShareDialog.waitForError();
    expect(errorText).toContain('cannot share with yourself');

    await aliceShareDialog.close();
  });

  test('8.3 Unregistered user shows error', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Use a valid-format key that doesn't belong to any user
    // 0x04 + 128 hex chars (65 bytes uncompressed secp256k1)
    const fakeKey =
      '0x04' +
      'aa'.repeat(32) + // x coordinate
      'bb'.repeat(32); // y coordinate

    await aliceShareDialog.shareWithKey(fakeKey);
    const errorText = await aliceShareDialog.waitForError({ timeout: 15000 });
    expect(errorText).toContain('user not found');

    await aliceShareDialog.close();
  });

  // ============================================
  // Phase 9: Hide Share
  // ============================================

  test('9.1 Bob hides the shared file', async () => {
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });

    // Bob should still see the shared file from test 3.1
    await bobSharedBrowser.waitForSharedItem(sharedFileName, { timeout: 15000 });

    // Right-click and hide
    await bobSharedBrowser.rightClickSharedItem(sharedFileName);
    await bobContextMenu.waitForOpen();
    await bobContextMenu.clickHide();

    // Wait for the item to disappear
    await bobSharedBrowser.waitForSharedItemGone(sharedFileName, { timeout: 10000 });
  });

  // ============================================
  // Phase 10: Re-share After Revoke
  // ============================================

  test('10.1 Alice re-shares the folder with Bob after previous revoke', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFolderName);

    // Charlie should be the only recipient (Bob was revoked in 6.1)
    await aliceShareDialog.waitForRecipientsLoaded();
    expect(await aliceShareDialog.getRecipientCount()).toBe(1);

    // Re-share with Bob
    await aliceShareDialog.shareWithKey(bob.publicKey);
    const successText = await aliceShareDialog.waitForSuccess({ timeout: 60000 });
    expect(successText).toContain(truncateKey(bob.publicKey));

    // Now should have 2 recipients again
    expect(await aliceShareDialog.getRecipientCount()).toBe(2);

    await aliceShareDialog.close();
  });

  test('10.2 Bob sees the re-shared folder', async () => {
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });

    await bobSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
    const itemNames = await bobSharedBrowser.getSharedItemNames();
    const hasFolderShare = itemNames.some((n) => n.includes(sharedFolderName));
    expect(hasFolderShare).toBe(true);
  });

  // ============================================
  // Phase 11: Shared File Previews
  // ============================================

  test('11.1 Bob can see the image in the shared folder', async () => {
    // The image was uploaded in test 2.2 before sharing, so share keys exist.
    // Bob should be able to see it in the shared folder view.
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });

    // Navigate into the shared folder
    await bobSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
    await bobSharedBrowser.openSharedItem(sharedFolderName);
    await bob.page.waitForTimeout(3000);

    // Check if we navigated successfully
    const parentVisible = await bobSharedBrowser.parentDirRow().isVisible();
    if (!parentVisible) {
      await bobSharedBrowser.openSharedItem(sharedFolderName);
      await bobSharedBrowser.parentDirRow().waitFor({ state: 'visible', timeout: 30000 });
    }

    // Verify the image file is visible
    await bobSharedBrowser.getFolderItem(sharedImageName).waitFor({
      state: 'visible',
      timeout: 15000,
    });
  });

  test('11.2 Bob previews a text file in the shared folder', async () => {
    // Bob is already inside the shared folder from test 11.1
    // Right-click the text file and open context menu
    await bobSharedBrowser.rightClickFolderItem(folderFile1Name);
    await bobContextMenu.waitForOpen();

    // Verify Preview option is available for text files
    const options = await bobContextMenu.getVisibleOptions();
    expect(options).toContain('Preview');

    // Click Preview to open text viewer
    await bobContextMenu.clickPreview();

    // Wait for the text editor modal to appear
    const modal = bob.page.locator('.text-editor-modal');
    await modal.waitFor({ state: 'visible', timeout: 30000 });

    // Verify it opened in read-only mode
    const title = await bob.page.locator('.modal-title').textContent();
    expect(title).toContain('View:');

    // Wait for decryption to complete (loading state to disappear)
    await bob.page.locator('.text-editor-loading').waitFor({ state: 'hidden', timeout: 30000 });

    // Verify textarea is read-only
    const textarea = bob.page.locator('.text-editor-textarea');
    await textarea.waitFor({ state: 'visible' });
    const isReadOnly = await textarea.getAttribute('readonly');
    expect(isReadOnly).not.toBeNull();

    // Verify the status bar shows read-only
    const statusText = await bob.page.locator('.text-editor-status').textContent();
    expect(statusText).toContain('read-only');

    // Verify the content was decrypted (textarea has some text)
    const content = await textarea.inputValue();
    expect(content.length).toBeGreaterThan(0);

    // Close the dialog
    await bob.page.locator('.dialog-button--primary', { hasText: 'close' }).click();
    await modal.waitFor({ state: 'hidden' });
  });

  test('11.3 Bob previews an image in the shared folder', async () => {
    // Bob is already inside the shared folder from test 11.1
    // The image was uploaded before sharing (test 2.2), so share keys exist.
    await bobSharedBrowser.getFolderItem(sharedImageName).waitFor({
      state: 'visible',
      timeout: 15000,
    });

    // Right-click the image file
    await bobSharedBrowser.rightClickFolderItem(sharedImageName);
    await bobContextMenu.waitForOpen();

    // Verify Preview option is available
    const options = await bobContextMenu.getVisibleOptions();
    expect(options).toContain('Preview');

    // Click Preview to open image preview
    await bobContextMenu.clickPreview();

    // Wait for the image preview modal to appear
    const modal = bob.page.locator('.image-preview-modal');
    await modal.waitFor({ state: 'visible', timeout: 30000 });

    // Wait for decryption to complete (loading or error state)
    await bob.page
      .locator('.image-preview-img, .image-preview-error')
      .first()
      .waitFor({ state: 'visible', timeout: 30000 });

    // Verify the image element is rendered (not an error)
    const img = bob.page.locator('.image-preview-img');
    expect(await img.isVisible()).toBe(true);

    // Verify the image has a valid src (blob URL)
    const src = await img.getAttribute('src');
    expect(src).toContain('blob:');

    // Close the dialog
    await bob.page.locator('.modal-close').click();
    await modal.waitFor({ state: 'hidden' });
  });

  test('11.4 Shared text file context menu shows View not Edit', async () => {
    // Bob should still be inside the shared folder
    await bobSharedBrowser.getFolderItem(folderFile1Name).waitFor({
      state: 'visible',
      timeout: 15000,
    });

    // Right-click the text file
    await bobSharedBrowser.rightClickFolderItem(folderFile1Name);
    await bobContextMenu.waitForOpen();

    // In read-only mode, Edit menu item should be present (opens read-only viewer)
    // but Rename and Delete should NOT be present
    const options = await bobContextMenu.getVisibleOptions();
    expect(options).toContain('Edit');
    expect(options).toContain('Preview');
    expect(options).toContain('Download');
    expect(options).not.toContain('Rename');
    expect(options).not.toContain('Delete');

    // Click Edit to open the read-only text viewer
    await bobContextMenu.clickEdit();

    const modal = bob.page.locator('.text-editor-modal');
    await modal.waitFor({ state: 'visible', timeout: 30000 });

    // Verify read-only title
    const title = await bob.page.locator('.modal-title').textContent();
    expect(title).toContain('View:');

    // Close
    await bob.page.locator('.dialog-button--primary', { hasText: 'close' }).click();
    await modal.waitFor({ state: 'hidden' });
  });
});
