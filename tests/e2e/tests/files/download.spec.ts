import { expect } from '@playwright/test';
import { readFileSync } from 'fs';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { UploadZonePage } from '../../page-objects/file-browser/upload-zone.page';
import { FileListPage } from '../../page-objects/file-browser/file-list.page';
import { ContextMenuPage } from '../../page-objects/file-browser/context-menu.page';
import { createTestTextFile, cleanupTestFiles } from '../../utils/test-files';

/**
 * E2E tests for file download functionality.
 * Tests download via context menu and verifies downloaded content.
 */
authenticatedTest.describe('File Download', () => {
  authenticatedTest.afterEach(async () => {
    // Clean up test files after each test
    cleanupTestFiles();
  });

  authenticatedTest('can download file via context menu', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);

    // Create and upload test file
    const testFile = createTestTextFile('download-test.txt', 'Download test content');
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(testFile.name, { timeout: 5000 });

    // Set up download promise before triggering download
    const downloadPromise = authenticatedPage.waitForEvent('download');

    // Right-click file and select download
    await fileList.rightClickItem(testFile.name);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickDownload();

    // Wait for download to start
    const download = await downloadPromise;

    // Verify download started with correct filename
    expect(download.suggestedFilename()).toBe(testFile.name);
  });

  authenticatedTest('downloaded file has correct content', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);
    const contextMenu = new ContextMenuPage(authenticatedPage);

    // Create test file with specific content
    const fileContent = 'This is the exact content we expect to download.\nLine 2 of content.';
    const testFile = createTestTextFile('content-test.txt', fileContent);

    // Upload file
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(testFile.name, { timeout: 5000 });

    // Set up download promise
    const downloadPromise = authenticatedPage.waitForEvent('download');

    // Trigger download
    await fileList.rightClickItem(testFile.name);
    await contextMenu.waitForOpen({ timeout: 2000 });
    await contextMenu.clickDownload();

    // Wait for download and save to temporary location
    const download = await downloadPromise;
    const downloadPath = await download.path();

    // Verify downloaded file content matches original
    if (downloadPath) {
      const downloadedContent = readFileSync(downloadPath, 'utf-8');
      expect(downloadedContent).toBe(fileContent);
    } else {
      throw new Error('Download path is null - download may have failed');
    }
  });
});
