import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { SelectionActionBarPage } from '../page-objects/file-browser/selection-action-bar.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';

/**
 * Batch Download E2E Test Suite
 *
 * Tests the multi-file selection and batch download feature via the
 * selection action bar. IMPORTANT: Batch download does NOT create a zip
 * file -- it downloads each selected file individually in sequence via
 * `downloadFromIpns`. Only files are downloaded, not folders.
 *
 * Suite flow:
 * 1. Login with fresh wallet account
 * 2. Upload 3 text files for batch operations
 * 3. Verify multi-select shows selection action bar with correct count
 * 4. Verify batch download via selection bar triggers file download event
 * 5. Verify 3-file selection shows correct count
 * 6. Verify batch context menu shows download option
 * 7. Cleanup: delete account
 */
test.describe.serial('Batch Download', () => {
  test.setTimeout(120_000); // 2 min -- uploads + downloads may be slow

  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let selectionBar: SelectionActionBarPage;
  let contextMenu: ContextMenuPage;
  const timestamp = Date.now();

  // Create 3 uniquely named test files
  const file1Name = `batch-dl-1-${timestamp}.txt`;
  const file2Name = `batch-dl-2-${timestamp}.txt`;
  const file3Name = `batch-dl-3-${timestamp}.txt`;

  test.beforeAll(async ({ browser: b }) => {
    browser = b;
    const account = createTestAccount();

    // Retry login once — the first test suite in the CI run can hit cold-start
    // issues where the page crashes before the auth flow completes.
    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        context = await browser.newContext();
        page = await context.newPage();
        await setupMockWallet(page, account);
        const result = await loginViaWallet(page, { timeout: 90_000 });
        expect(result.outcome).toBe('success');
        lastError = undefined;
        break;
      } catch (err) {
        lastError = err;
        await context?.close().catch(() => {});
      }
    }
    if (lastError) throw lastError;

    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    selectionBar = new SelectionActionBarPage(page);
    contextMenu = new ContextMenuPage(page);
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (page) await deleteAccountViaPage(page);
    if (context) await context.close();
  });

  test('upload test files for batch operations', async () => {
    // Create and upload 3 text files
    const file1 = createTestTextFile(file1Name, 'Batch download test file 1');
    const file2 = createTestTextFile(file2Name, 'Batch download test file 2');
    const file3 = createTestTextFile(file3Name, 'Batch download test file 3');

    for (const file of [file1, file2, file3]) {
      await uploadZone.uploadFile(file.path);
      await uploadZone.waitForUploadComplete({ timeout: 30_000 });
      await fileList.waitForItemToAppear(file.name, { timeout: 30_000 });
    }

    // Assert all 3 files visible
    expect(await fileList.isItemVisible(file1Name)).toBe(true);
    expect(await fileList.isItemVisible(file2Name)).toBe(true);
    expect(await fileList.isItemVisible(file3Name)).toBe(true);
  });

  test('multi-select files shows selection action bar', async () => {
    // Select first file
    await fileList.selectItem(file1Name);

    // Ctrl+click second file to add to selection
    await fileList.ctrlClickItem(file2Name);

    // Wait for selection bar to appear
    await selectionBar.waitForVisible({ timeout: 5_000 });

    // Assert count text contains "2"
    expect(await selectionBar.getCountText()).toContain('2');

    // Assert download button is visible
    expect(await selectionBar.isDownloadVisible()).toBe(true);

    // Clear selection for next test
    await selectionBar.clickClear();
    await selectionBar.waitForHidden();
  });

  test('batch download via selection bar triggers file download', async () => {
    // Select file1 and file2
    await fileList.selectItem(file1Name);
    await fileList.ctrlClickItem(file2Name);
    await selectionBar.waitForVisible();

    // Set up download listener BEFORE clicking download
    const downloadPromise = page.waitForEvent('download', { timeout: 30_000 });

    // Click download button in selection bar
    await selectionBar.clickDownload();

    // Await at least one download event
    // Note: Batch download fires multiple events sequentially (one per file)
    // but we only need to verify at least one succeeds
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBeTruthy();

    // Deselect all and wait for selection bar to disappear
    await page.keyboard.press('Escape');
    await selectionBar.waitForHidden();
  });

  test('select three files shows correct count', async () => {
    // Select all 3 files
    await fileList.selectItem(file1Name);
    await fileList.ctrlClickItem(file2Name);
    await fileList.ctrlClickItem(file3Name);

    // Assert selection count is 3
    expect(await fileList.getSelectedCount()).toBe(3);

    // Assert selection bar count text contains "3"
    await selectionBar.waitForVisible();
    expect(await selectionBar.getCountText()).toContain('3');

    // Keep selection for next test (batch context menu)
  });

  test('batch context menu shows download option', async () => {
    // With 3 files still selected from previous test, right-click one
    await fileList.rightClickItem(file2Name);
    await contextMenu.waitForOpen();

    // Assert batch menu (has header)
    expect(await contextMenu.isBatchMenu()).toBe(true);

    // Assert header contains "selected"
    const headerText = await contextMenu.getHeaderText();
    expect(headerText.toLowerCase()).toContain('selected');

    // Assert download option is present in the batch menu
    await expect(page.locator('[role="menuitem"]', { hasText: /download/i })).toBeVisible();

    // Close menu
    await contextMenu.closeWithEscape();

    // Deselect all and wait for selection bar to disappear
    await page.keyboard.press('Escape');
    await selectionBar.waitForHidden();
  });
});
