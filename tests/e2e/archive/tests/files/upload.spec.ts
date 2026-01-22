import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';
import { UploadZonePage } from '../../page-objects/file-browser/upload-zone.page';
import { FileListPage } from '../../page-objects/file-browser/file-list.page';
import { createTestTextFile, cleanupTestFiles } from '../../utils/test-files';

/**
 * E2E tests for file upload functionality.
 * Tests upload via drag-drop zone and verifies files appear in file list.
 */
authenticatedTest.describe('File Upload', () => {
  authenticatedTest.afterEach(async () => {
    // Clean up test files after each test
    cleanupTestFiles();
  });

  authenticatedTest('can upload a text file', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);

    // Create test file
    const testFile = createTestTextFile('test-upload.txt', 'Upload test content');

    // Upload file
    await uploadZone.uploadFile(testFile.path);

    // Wait for upload to complete
    await uploadZone.waitForUploadComplete({ timeout: 10000 });

    // Verify file appears in file list
    await fileList.waitForItemToAppear(testFile.name, { timeout: 5000 });
    await expect(fileList.getFileItem(testFile.name)).toBeVisible();
  });

  authenticatedTest('uploaded file shows correct name', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);

    // Create test file with specific name
    const fileName = 'my-document.txt';
    const testFile = createTestTextFile(fileName, 'Document content');

    // Upload file
    await uploadZone.uploadFile(testFile.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });

    // Verify exact file name matches
    await fileList.waitForItemToAppear(fileName, { timeout: 5000 });
    const visibleNames = await fileList.getVisibleItemNames();
    expect(visibleNames).toContain(fileName);
  });

  authenticatedTest('can upload multiple files sequentially', async ({ authenticatedPage }) => {
    const uploadZone = new UploadZonePage(authenticatedPage);
    const fileList = new FileListPage(authenticatedPage);

    // Create multiple test files
    const file1 = createTestTextFile('file1.txt', 'Content 1');
    const file2 = createTestTextFile('file2.txt', 'Content 2');
    const file3 = createTestTextFile('file3.txt', 'Content 3');

    // Upload files one by one
    await uploadZone.uploadFile(file1.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(file1.name, { timeout: 5000 });

    await uploadZone.uploadFile(file2.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(file2.name, { timeout: 5000 });

    await uploadZone.uploadFile(file3.path);
    await uploadZone.waitForUploadComplete({ timeout: 10000 });
    await fileList.waitForItemToAppear(file3.name, { timeout: 5000 });

    // Verify all files are visible
    await expect(fileList.getFileItem(file1.name)).toBeVisible();
    await expect(fileList.getFileItem(file2.name)).toBeVisible();
    await expect(fileList.getFileItem(file3.name)).toBeVisible();

    // Verify file count
    const itemCount = await fileList.getItemCount();
    expect(itemCount).toBeGreaterThanOrEqual(3);
  });
});
