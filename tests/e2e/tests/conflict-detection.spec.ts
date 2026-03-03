import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import {
  loginViaEmail,
  loginViaTestEndpoint,
  TEST_CREDENTIALS,
  type TestAuthState,
} from '../utils/web3auth-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { bumpServerSequence } from '../utils/conflict-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { TextEditorDialogPage } from '../page-objects/dialogs/text-editor-dialog.page';

/**
 * Conflict Detection E2E Test Suite
 *
 * Verifies the full conflict detection flow end-to-end:
 * 1. Server-side sequence is bumped (simulating another device publishing)
 * 2. Web client detects 409 on its next folder publish
 * 3. Client re-syncs (fetches latest remote state)
 * 4. Client retries the operation with the fresh sequence
 * 5. User's operation succeeds and the item appears in the file list
 *
 * Tests cover:
 * - Upload file with stale folder sequence -> auto re-sync -> file visible
 * - Create folder with stale parent sequence -> auto re-sync -> folder visible
 * - Per-file IPNS publish (content update) does NOT trigger conflict detection
 *
 * Depends on:
 * - Plan 16-01: API accepts expectedSequenceNumber, returns 409 on mismatch
 * - Plan 16-02: Web client sends expectedSequenceNumber and handles 409 with re-sync + retry
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
  let confirmDialog: ConfirmDialogPage;
  let textEditorDialog: TextEditorDialogPage;

  // Auth state -- used for direct API calls in bumpServerSequence
  let authState: TestAuthState | null = null;

  const apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:3000';

  // Unique suffix per test run to avoid naming collisions
  const runId = Date.now().toString();

  // Cleanup: track items created during tests for deletion
  const createdItems: Array<{ name: string; type: 'file' | 'folder' }> = [];

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    // Initialize page objects
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    createFolderDialog = new CreateFolderDialogPage(page);
    contextMenu = new ContextMenuPage(page);
    confirmDialog = new ConfirmDialogPage(page);
    textEditorDialog = new TextEditorDialogPage(page);

    // Login using test-login endpoint (bypasses Core Kit, decouples from Web3Auth)
    if (process.env.TEST_LOGIN_SECRET) {
      authState = await loginViaTestEndpoint(page, TEST_CREDENTIALS.email);
    } else {
      await loginViaEmail(page, TEST_CREDENTIALS.email);
      // When using real Core Kit login, extract auth state from Zustand stores
      // for use in bumpServerSequence API calls
      authState = await page.evaluate(() => {
        const stores = (window as unknown as Record<string, unknown>).__ZUSTAND_STORES as
          | {
              auth: { getState: () => { accessToken: string } };
              vault: { getState: () => { rootIpnsName: string } };
            }
          | undefined;

        if (!stores) return null;

        const authStoreState = stores.auth.getState();
        const vaultStoreState = stores.vault.getState();

        return {
          accessToken: authStoreState.accessToken,
          rootIpnsName: vaultStoreState.rootIpnsName,
          // Non-sensitive fields only -- private keys stay in browser memory
          email: '',
          publicKeyHex: '',
          publicKeyArr: [],
          privateKeyArr: [],
          rootFolderKeyArr: [],
          rootIpnsPublicKeyArr: [],
          rootIpnsPrivateKeyArr: [],
          vaultId: '',
        } as TestAuthState;
      });
    }

    // Verify we're on the files page and the vault is accessible
    await page.waitForURL('**/files', { timeout: 60000 });
    await fileList.fileListContainer().waitFor({ state: 'visible', timeout: 30000 });
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (context) {
      await context.close();
    }
  });

  // ============================================================
  // Helper: Get current access token from Zustand auth store
  // ============================================================

  /**
   * Get a fresh access token from the browser's Zustand auth store.
   * The token may be refreshed between tests.
   */
  async function getAccessToken(): Promise<string> {
    if (authState?.accessToken) {
      return authState.accessToken;
    }
    // Fallback: read from store if authState not available
    return await page.evaluate(() => {
      const stores = (window as unknown as Record<string, unknown>).__ZUSTAND_STORES as {
        auth: { getState: () => { accessToken: string } };
      };
      return stores?.auth?.getState()?.accessToken ?? '';
    });
  }

  /**
   * Get the root IPNS name from the browser's Zustand vault store.
   */
  async function getRootIpnsName(): Promise<string> {
    if (authState?.rootIpnsName) {
      return authState.rootIpnsName;
    }
    return await page.evaluate(() => {
      const stores = (window as unknown as Record<string, unknown>).__ZUSTAND_STORES as {
        vault: { getState: () => { rootIpnsName: string } };
      };
      return stores?.vault?.getState()?.rootIpnsName ?? '';
    });
  }

  // ============================================================
  // Test 1: Upload file with stale sequence -> conflict -> retry
  // ============================================================

  test('upload file to root when sequence is stale -> conflict auto-resolved -> file appears', async () => {
    test.slow(); // Allow extra time for conflict re-sync cycle

    const fileName = `conflict-upload-${runId}.txt`;

    // Step 1: Bump the server-side sequence number so the client's local
    // sequence becomes stale. This simulates another device publishing.
    const accessToken = await getAccessToken();
    const rootIpnsName = await getRootIpnsName();

    expect(accessToken).toBeTruthy();
    expect(rootIpnsName).toBeTruthy();

    await bumpServerSequence({ page, apiBaseUrl, accessToken, rootIpnsName });

    // Step 2: Upload a test file via the upload zone.
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

    // Step 1: Bump the server-side sequence number again.
    const accessToken = await getAccessToken();
    const rootIpnsName = await getRootIpnsName();

    await bumpServerSequence({ page, apiBaseUrl, accessToken, rootIpnsName });

    // Step 2: Create a folder via the new-folder button.
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
    // This resets/syncs the root folder sequence as a side effect of the
    // successful publish from Test 2.
    const editFileName = `conflict-edit-target-${runId}.txt`;
    const originalContent = `Original content for conflict edit test - ${runId}`;
    const updatedContent = `Updated content via text editor - ${runId} - modified`;

    const testFile = createTestTextFile(editFileName, originalContent);
    await uploadZone.uploadFile(testFile.path);
    await fileList.waitForItemToAppear(editFileName, { timeout: 30000 });

    // Step 2: Bump the folder's server-side sequence number.
    // This makes the client's local folder sequence stale.
    const accessToken = await getAccessToken();
    const rootIpnsName = await getRootIpnsName();

    await bumpServerSequence({ page, apiBaseUrl, accessToken, rootIpnsName });

    // Step 3: Open the text editor for the file and save new content.
    // The text editor save flow calls handleUpdateFile, which publishes only
    // the per-file IPNS record (NOT the folder IPNS record). Per the Phase 16
    // design, per-file IPNS publishes use last-write-wins with no
    // expectedSequenceNumber, so they never trigger conflict detection.
    await fileList.rightClickItem(editFileName);
    await contextMenu.waitForOpen();
    await contextMenu.clickEdit();

    await textEditorDialog.waitForOpen({ timeout: 15000 });
    await textEditorDialog.waitForContentLoaded({ timeout: 15000 });
    await textEditorDialog.setContent(updatedContent);
    await textEditorDialog.clickSave();
    await textEditorDialog.waitForClose({ timeout: 30000 });

    // Step 4: Assert the file update completed without a persistent error.
    // The file should still be visible in the list (not removed by an error).
    await fileList.waitForItemToAppear(editFileName, { timeout: 15000 });
    const fileVisible = await fileList.isItemVisible(editFileName);
    expect(fileVisible).toBe(true);

    // Step 5: Verify no upload-zone error state.
    const hasUploadError = await uploadZone.hasError();
    expect(hasUploadError).toBe(false);

    // Track for cleanup
    createdItems.push({ name: editFileName, type: 'file' });
  });

  // ============================================================
  // Cleanup: Remove all items created during conflict tests
  // ============================================================

  test('cleanup: delete conflict test items', async () => {
    // Delete items in reverse creation order (files first, then folders)
    const itemsToDelete = [...createdItems].reverse();

    for (const item of itemsToDelete) {
      const isVisible = await fileList.isItemVisible(item.name).catch(() => false);
      if (!isVisible) continue;

      await fileList.rightClickItem(item.name);
      await contextMenu.waitForOpen();
      await contextMenu.clickDelete();
      await confirmDialog.waitForOpen();
      await confirmDialog.clickConfirm();
      await fileList.waitForItemToDisappear(item.name, { timeout: 30000 });
    }
  });
});
