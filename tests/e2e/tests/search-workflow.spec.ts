import { test, expect, Page, Browser, BrowserContext } from '@playwright/test';
import { loginViaEmail, TEST_CREDENTIALS } from '../utils/web3auth-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { SearchPalettePage } from '../page-objects/dialogs/search-palette.page';

/**
 * Search Workflow E2E Test Suite
 *
 * Tests the client-side search feature end-to-end:
 * 1. Open search palette via Cmd/Ctrl+K keyboard shortcut
 * 2. Open search palette via header button click
 * 3. Type query and verify fuzzy-matched results appear
 * 4. No-results state for nonsense queries
 * 5. Select result and verify navigation to correct folder
 * 6. Keyboard navigation with Enter to select
 * 7. Escape closes palette
 * 8. Click outside closes palette
 *
 * Uses a single login session with serial test execution.
 * Uploads a uniquely named file for deterministic search results.
 */
test.describe.serial('Search Workflow', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  // Page objects
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let searchPalette: SearchPalettePage;

  // Test data
  const runId = Date.now();
  const testFileName = `search-test-${runId}.txt`;

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    // Initialize page objects
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    searchPalette = new SearchPalettePage(page);
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (context) {
      await context.close();
    }
  });

  // ============================================
  // Setup
  // ============================================

  test('0.1 Login and create test content', async () => {
    // Login
    await loginViaEmail(page, TEST_CREDENTIALS.email);
    await page.waitForURL('**/files', { timeout: 60000 });

    // Create and upload a uniquely named text file
    const testFile = createTestTextFile(testFileName, `Search test content ${runId}`);
    await uploadZone.uploadFile(testFile.path);

    // Wait for the file to appear in the file list
    await fileList.waitForItemToAppear(testFileName, { timeout: 30000 });
  });

  // ============================================
  // 1. Open / Close via shortcuts
  // ============================================

  test('1.1 Open search palette via Cmd+K', async () => {
    // Press Meta+K to open search palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Verify input is focused
    await expect(searchPalette.input()).toBeFocused();

    // Close via Escape
    await page.keyboard.press('Escape');
    await searchPalette.waitForClosed({ timeout: 5000 });
  });

  test('1.2 Open search palette via header button', async () => {
    // Click the header search button
    await searchPalette.headerSearchButton().click();
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Verify input is focused
    await expect(searchPalette.input()).toBeFocused();

    // Close via Escape for cleanup
    await page.keyboard.press('Escape');
    await searchPalette.waitForClosed({ timeout: 5000 });
  });

  // ============================================
  // 2. Search queries and results
  // ============================================

  test('2.1 Type query and verify results appear', async () => {
    // Open palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Type the first part of the test file name (enough for a match)
    const queryText = `search-test-${runId}`;
    await searchPalette.typeQuery(queryText.slice(0, 12));

    // Wait for results (index build + debounce may take time on first open)
    await searchPalette.waitForResults({ timeout: 15000 });

    // Verify at least one result appears
    const resultCount = await searchPalette.getResultCount();
    expect(resultCount).toBeGreaterThan(0);

    // Verify the test file is in the results
    const names = await searchPalette.getResultNames();
    expect(names.some((n) => n.includes(testFileName))).toBe(true);

    // Verify footer count is visible and shows a number
    const countText = await searchPalette.getFooterCountText();
    expect(countText).toMatch(/\d+ result/);

    // Close
    await page.keyboard.press('Escape');
    await searchPalette.waitForClosed({ timeout: 5000 });
  });

  test('2.2 No results for nonsense query', async () => {
    // Open palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Type nonsense query
    await searchPalette.typeQuery('zzzzxqwnofile999');

    // Wait for debounce (150ms) + rendering
    await page.waitForTimeout(500);

    // Verify no results
    const resultCount = await searchPalette.getResultCount();
    expect(resultCount).toBe(0);

    // Verify "no results" message is visible
    await expect(searchPalette.noResults()).toBeVisible();

    // Close
    await page.keyboard.press('Escape');
    await searchPalette.waitForClosed({ timeout: 5000 });
  });

  // ============================================
  // 3. Navigation from search results
  // ============================================

  test('3.1 Select result and verify navigation', async () => {
    // Open palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Type query matching the test file
    await searchPalette.typeQuery(`search-test-${runId}`);
    await searchPalette.waitForResults({ timeout: 15000 });

    // Click the first result
    await searchPalette.clickResult(0);

    // Verify palette closes
    await searchPalette.waitForClosed({ timeout: 5000 });

    // Verify URL is on /files (root folder, since file was uploaded to root)
    await page.waitForURL('**/files**', { timeout: 10000 });

    // Verify the file is visible in the file list (navigation landed correctly)
    await expect(fileList.getItem(testFileName)).toBeVisible({ timeout: 10000 });
  });

  test('3.2 Keyboard navigation with Enter selects result', async () => {
    // Open palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Type query matching the test file
    await searchPalette.typeQuery(`search-test-${runId}`);
    await searchPalette.waitForResults({ timeout: 15000 });

    // First result should be auto-selected (index 0)
    // Press Enter to select it
    await page.keyboard.press('Enter');

    // Verify palette closes
    await searchPalette.waitForClosed({ timeout: 5000 });

    // Verify URL is on /files
    await page.waitForURL('**/files**', { timeout: 10000 });
  });

  // ============================================
  // 4. Dismissal behaviors
  // ============================================

  test('4.1 Escape closes palette', async () => {
    // Open palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Type some text
    await searchPalette.typeQuery('some-text');

    // Press Escape
    await page.keyboard.press('Escape');

    // Verify palette closes
    await searchPalette.waitForClosed({ timeout: 5000 });
  });

  test('4.2 Click outside closes palette', async () => {
    // Open palette
    await page.keyboard.press('Meta+k');
    await searchPalette.waitForOpen({ timeout: 5000 });

    // Click the backdrop (near top-left corner, outside the centered palette)
    await searchPalette.backdrop().click({ position: { x: 10, y: 10 } });

    // Verify palette closes
    await searchPalette.waitForClosed({ timeout: 5000 });
  });

  // ============================================
  // 9. Cleanup
  // ============================================

  test('9.1 Cleanup', async () => {
    // Delete the test file from CipherBox
    // Right-click the test file and delete it
    const isVisible = await fileList.isItemVisible(testFileName);
    if (isVisible) {
      await fileList.rightClickItem(testFileName);
      const deleteOption = page.locator('.context-menu-item', { hasText: 'Delete' });
      if (await deleteOption.isVisible({ timeout: 2000 }).catch(() => false)) {
        await deleteOption.click();
        // Confirm deletion if dialog appears
        const confirmBtn = page.locator('.dialog-button--destructive');
        if (await confirmBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
          await confirmBtn.click();
        }
        // Wait for item to disappear
        await fileList.waitForItemToDisappear(testFileName, { timeout: 15000 }).catch(() => {
          // File may already be gone
        });
      }
    }

    // Cleanup local test files
    cleanupTestFiles();
  });
});
