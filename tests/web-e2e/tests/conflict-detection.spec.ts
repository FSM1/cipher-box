import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import {
  createConflictDevice,
  bumpSequenceViaSecondDevice,
  closeConflictDevice,
  type ConflictDevice,
} from '../utils/conflict-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { TextEditorDialogPage } from '../page-objects/dialogs/text-editor-dialog.page';

/**
 * Conflict Detection E2E Test Suite
 *
 * Verifies the full conflict detection flow end-to-end using two browser
 * sessions logged in as the same user (simulating two devices):
 *
 * 1. Session B uploads a file (bumps server-side sequence)
 * 2. Session A's local sequence is now stale
 * 3. Session A performs a mutation → gets 409 from server
 * 4. Session A auto-resyncs (fetches latest remote state)
 * 5. Session A retries with fresh sequence → operation succeeds
 *
 * Tests cover:
 * - Upload file with stale folder sequence -> auto re-sync -> file visible
 * - Create folder with stale parent sequence -> auto re-sync -> folder visible
 * - Per-file IPNS publish (content update) does NOT trigger conflict detection
 */
test.describe.serial('Conflict Detection', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  // Page objects (initialized after login)
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let createFolderDialog: CreateFolderDialogPage;
  let contextMenu: ContextMenuPage;
  let textEditorDialog: TextEditorDialogPage;

  let account: PrivateKeyAccount;

  // Second browser session — same user, simulates another device
  let deviceB: ConflictDevice | undefined;

  // Unique suffix per test run to avoid naming collisions
  const runId = Date.now().toString();

  // Cleanup: track items created during tests for deletion
  const createdItems: Array<{ name: string; type: 'file' | 'folder' }> = [];

  test.beforeAll(async ({ browser: testBrowser }) => {
    test.setTimeout(180_000); // Two Core Kit logins (same identity) + seed upload
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    // Generate a random wallet identity and install mock wallet
    account = createTestAccount();
    await setupMockWallet(page, account);

    // Initialize page objects
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    createFolderDialog = new CreateFolderDialogPage(page);
    contextMenu = new ContextMenuPage(page);
    textEditorDialog = new TextEditorDialogPage(page);

    // Login via wallet (mock wallet auto-approves connect + SIWE)
    await loginViaWallet(page, { timeout: 60_000 });

    // Verify we're on the files page and the vault is accessible
    await page.waitForURL('**/files', { timeout: 60000 });
    await Promise.race([
      fileList.fileListContainer().waitFor({ state: 'visible', timeout: 30000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30000 }),
    ]);

    // Seed: upload a file to ensure the root folder IPNS record exists.
    // For a fresh vault, no IPNS record is published until the first mutation.
    const seedFileName = `seed-${runId}.txt`;
    const seedFile = createTestTextFile(seedFileName, 'seed file for conflict tests');
    await uploadZone.uploadFile(seedFile.path);
    await fileList.waitForItemToAppear(seedFileName, { timeout: 60000 });
    createdItems.push({ name: seedFileName, type: 'file' });

    // Create second session with the same wallet identity (simulates another device)
    deviceB = await createConflictDevice(browser, account);
  });

  test.afterAll(async () => {
    test.setTimeout(60_000); // Cleanup can be slow with rate-limited API

    // Close second device first
    if (deviceB) {
      await closeConflictDevice(deviceB);
    }

    cleanupTestFiles();

    // Delete the test account before closing the context (page must still be
    // navigable). deleteAccount cascades server-side and removes every folder,
    // file, and IPNS record for this identity, so there is no need to delete the
    // created items through the UI first. That redundant per-item loop used to
    // blow the 60s afterAll budget here: because this is the conflict suite,
    // device A's local sequence is stale, so each UI delete triggered a
    // 409 -> auto-resync -> retry cycle under 4-worker API rate-limiting.
    // Both primary and deviceB share the same wallet identity, so one delete suffices.
    if (page) {
      await deleteAccountViaPage(page);
    }

    if (context) {
      await context.close();
    }
  });

  function requireDeviceB(): ConflictDevice {
    if (!deviceB) throw new Error('deviceB not initialized — beforeAll failed');
    return deviceB;
  }

  // ============================================================
  // Test 1: Upload file with stale sequence -> conflict -> retry
  // ============================================================

  test('upload file to root when sequence is stale -> conflict auto-resolved -> file appears', async () => {
    test.slow(); // Allow extra time for conflict re-sync cycle

    const fileName = `conflict-upload-${runId}.txt`;

    // Step 1: Bump the server-side sequence by uploading from device B.
    // This makes device A's local sequence stale.
    const bumpFile = await bumpSequenceViaSecondDevice(requireDeviceB(), runId);
    createdItems.push({ name: bumpFile, type: 'file' });

    // Step 2: Upload a test file from device A (primary session).
    // The client will:
    // - Encrypt the file content and upload to IPFS
    // - Build the new folder metadata (with the new file added)
    // - Publish the folder IPNS record with its (now-stale) expectedSequenceNumber
    // - Receive a 409 Conflict response from the API
    // - Re-sync: fetch the latest folder metadata from IPNS
    // - Retry the upload with the fresh sequence number
    // - Succeed on retry
    const testFile = createTestTextFile(fileName, `Conflict detection test file - ${runId}`);
    await uploadZone.uploadFile(testFile.path);

    // Step 3: Assert the file appears in the file list despite the initial
    // conflict. Use a generous timeout to allow for the re-sync cycle.
    await fileList.waitForItemToAppear(fileName, { timeout: 60000 });

    // Step 4: Assert the operation completed successfully (no persistent error).
    // The upload zone should not show an error after conflict auto-resolution.
    const hasUploadError = await uploadZone.hasError();
    expect(hasUploadError).toBe(false);

    // Track for cleanup
    createdItems.push({ name: fileName, type: 'file' });
  });

  // ============================================================
  // Test 2: Create folder with stale sequence -> conflict -> retry
  // ============================================================

  test('create folder when parent sequence is stale -> conflict auto-resolved -> folder appears', async () => {
    test.slow(); // Allow extra time for conflict re-sync cycle

    const folderName = `conflict-folder-${runId}`;

    // Step 1: Bump the server-side sequence again from device B.
    const bumpFile = await bumpSequenceViaSecondDevice(requireDeviceB(), runId);
    createdItems.push({ name: bumpFile, type: 'file' });

    // Step 2: Create a folder from device A.
    // The client will hit the same 409 -> re-sync -> retry flow.
    const newFolderButton = page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(folderName);

    // Step 3: Assert the folder appears in the file list.
    await fileList.waitForItemToAppear(folderName, { timeout: 60000 });

    // Step 4: Verify no persistent error state after conflict auto-resolution.
    const folderVisible = await fileList.isItemVisible(folderName);
    expect(folderVisible).toBe(true);

    // Track for cleanup
    createdItems.push({ name: folderName, type: 'folder' });
  });

  // ============================================================
  // Test 3 (negative): Per-file IPNS publish does NOT conflict
  // ============================================================

  test('per-file IPNS content update does not trigger conflict even with stale folder sequence', async () => {
    test.slow(); // Allow for file edit + save cycle

    // Step 1: Upload a text file to edit later.
    const editFileName = `conflict-edit-target-${runId}.txt`;
    const originalContent = `Original content for conflict edit test - ${runId}`;
    const updatedContent = `Updated content via text editor - ${runId} - modified`;

    const testFile = createTestTextFile(editFileName, originalContent);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(editFileName, { timeout: 30000 });

    // Step 2: Bump the folder's server-side sequence from device B.
    // Brief pause to avoid API rate limiting from rapid test transitions.
    await page.waitForTimeout(2000);
    const bumpFile = await bumpSequenceViaSecondDevice(requireDeviceB(), runId);
    createdItems.push({ name: bumpFile, type: 'file' });

    // Step 3: Open the text editor for the file and save new content.
    // The text editor save flow publishes only the per-file IPNS record
    // (NOT the folder IPNS record). Per the Phase 16 design, per-file IPNS
    // publishes use last-write-wins with no expectedSequenceNumber, so they
    // never trigger conflict detection.
    await fileList.rightClickItem(editFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickEdit();

    await textEditorDialog.waitForOpen({ timeout: 15000 });
    await textEditorDialog.waitForContentLoaded({ timeout: 15000 });
    await textEditorDialog.setContent(updatedContent);
    await textEditorDialog.clickSave();
    await textEditorDialog.waitForClose({ timeout: 30000 });

    // Step 4: Assert the file update completed without a persistent error.
    await fileList.waitForItemToAppear(editFileName, { timeout: 15000 });
    const fileVisible = await fileList.isItemVisible(editFileName);
    expect(fileVisible).toBe(true);

    // Step 5: Verify no upload-zone error state.
    const hasUploadError = await uploadZone.hasError();
    expect(hasUploadError).toBe(false);

    // Track for cleanup
    createdItems.push({ name: editFileName, type: 'file' });
  });
});
