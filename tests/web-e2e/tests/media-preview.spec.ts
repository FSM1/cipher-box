import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { createTestMediaFile, cleanupTestFiles } from '../utils/test-files';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';

/**
 * Media Preview E2E Test Suite
 *
 * Verifies that preview dialogs open and render correctly for:
 * - PDF files (canvas-based viewer)
 * - Video files (HTML5 video player)
 * - Audio files (canvas visualizer + hidden audio element)
 *
 * Covers the preview features implemented in Phase 12.1 that were
 * previously only manually verified.
 */
test.describe.serial('Media Preview', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  const timestamp = Date.now();
  const pdfName = `preview-doc-${timestamp}.pdf`;
  const videoName = `preview-video-${timestamp}.mp4`;
  const audioName = `preview-audio-${timestamp}.mp3`;

  test.setTimeout(180_000);

  test.beforeAll(async ({ browser: b }) => {
    browser = b;
    const account = createTestAccount();
    context = await browser.newContext();
    page = await context.newPage();
    await setupMockWallet(page, account);
    const result = await loginViaWallet(page, { timeout: 90_000 });
    expect(result.outcome).toBe('success');
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    contextMenu = new ContextMenuPage(page);
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    await deleteAccountViaPage(page);
    if (context) await context.close();
  });

  test('upload media fixtures', async () => {
    // Upload PDF
    const pdf = createTestMediaFile('test-document.pdf', pdfName);
    await uploadZone.uploadFile(pdf.path);
    await fileList.waitForItemToAppear(pdfName, { timeout: 60_000 });

    // Upload video
    const video = createTestMediaFile('test-video.mp4', videoName);
    await uploadZone.uploadFile(video.path);
    await fileList.waitForItemToAppear(videoName, { timeout: 60_000 });

    // Upload audio
    const audio = createTestMediaFile('test-audio.mp3', audioName);
    await uploadZone.uploadFile(audio.path);
    await fileList.waitForItemToAppear(audioName, { timeout: 60_000 });
  });

  test('PDF preview shows viewer with canvas', async () => {
    await fileList.rightClickItem(pdfName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();

    // Wait for PDF preview modal
    await page.locator('.pdf-preview-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // PDF viewer renders pages as canvas elements
    await expect(page.locator('.pdf-preview-modal canvas').first()).toBeVisible({
      timeout: 15_000,
    });

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.pdf-preview-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });

  test('video preview shows player', async () => {
    await fileList.rightClickItem(videoName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();

    // Wait for video player modal
    await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // Assert video element exists
    await expect(page.locator('.video-player-modal video')).toBeVisible({ timeout: 15_000 });

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.video-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });

  test('audio preview shows player', async () => {
    await fileList.rightClickItem(audioName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();

    // Wait for audio player modal -- audio uses a hidden <audio> element
    // with canvas visualization, so we check for the modal container
    await page.locator('.audio-player-modal').waitFor({ state: 'visible', timeout: 30_000 });
    expect(await page.locator('.audio-player-modal').isVisible()).toBe(true);

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.audio-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });

  test('preview error state for corrupt file', async () => {
    // Upload a text file with .mp4 extension to trigger an error state
    const corruptName = `corrupt-${timestamp}.mp4`;
    const { writeFileSync } = await import('fs');
    const { resolve } = await import('path');
    const corruptPath = resolve(
      process.cwd(),
      'tests/web-e2e/fixtures/files',
      corruptName
    );
    writeFileSync(corruptPath, 'This is not a valid video file');

    await uploadZone.uploadFile(corruptPath);
    await fileList.waitForItemToAppear(corruptName, { timeout: 60_000 });

    // Open preview
    await fileList.rightClickItem(corruptName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();

    // Wait for the video modal to appear
    await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // Check for error state -- the video element may show an error or the
    // error container may appear. Accept either outcome.
    const errorVisible = await page
      .locator('.video-preview-error')
      .waitFor({ state: 'visible', timeout: 15_000 })
      .then(() => true)
      .catch(() => false);

    if (!errorVisible) {
      // The video element itself may have errored -- check via evaluate
      const videoError = await page.evaluate(() => {
        const video = document.querySelector('.video-player-modal video') as HTMLVideoElement;
        return video ? video.error !== null : false;
      });
      // Accept either explicit error container or video element error
      expect(errorVisible || videoError).toBe(true);
    }

    // Clean up temp file
    const { unlinkSync, existsSync } = await import('fs');
    if (existsSync(corruptPath)) unlinkSync(corruptPath);

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.video-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });
});
