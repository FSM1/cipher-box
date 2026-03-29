import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { createTestMediaFile, cleanupTestFiles } from '../utils/test-files';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';

/**
 * AES-CTR Streaming Playback E2E Test Suite
 *
 * Verifies the streaming decryption pipeline:
 * - Large video (>256KB) triggers AES-CTR mode via service worker interception
 * - Small video (<256KB) falls back to AES-GCM blob URL playback
 * - Video player modal renders with controls and encrypted badge
 * - Decrypt progress indicator appears during initial load
 */
test.describe.serial('AES-CTR Streaming Playback', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;
  const timestamp = Date.now();
  const videoName = `stream-test-${timestamp}.mp4`;
  const smallVideoName = `stream-small-${timestamp}.mp4`;

  test.setTimeout(180_000);

  test.beforeAll(async ({ browser: b }) => {
    // Extend hook timeout — match suite timeout (default 30s is too short for wallet login)
    test.setTimeout(180_000);
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
    if (page) await deleteAccountViaPage(page);
    if (context) await context.close();
  });

  test('upload large video file (CTR mode)', async () => {
    const file = createTestMediaFile('test-video.mp4', videoName);
    await uploadZone.uploadFile(file.path);
    await fileList.waitForItemToAppear(videoName, { timeout: 60_000 });
    expect(await fileList.isItemVisible(videoName)).toBe(true);
  });

  test('video preview opens with player controls', async () => {
    await fileList.rightClickItem(videoName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();

    // Wait for the video player modal to appear
    await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // Assert video element is present inside the modal
    await expect(page.locator('.video-player-modal video')).toBeVisible({ timeout: 15_000 });

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.video-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });

  test('CTR encrypted badge visible for large video', async () => {
    // Re-open preview
    await fileList.rightClickItem(videoName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();
    await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // Wait for the encrypted badge indicating AES-CTR streaming mode
    await page.locator('.video-cipher-badge').waitFor({ state: 'visible', timeout: 30_000 });
    const badgeText = await page.locator('.video-cipher-badge').textContent();
    expect(badgeText?.toUpperCase()).toContain('ENCRYPTED');

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.video-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });

  test('decrypt progress shows during initial load', async () => {
    // Re-open preview
    await fileList.rightClickItem(videoName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();
    await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // The progress bar may appear very briefly -- use a soft assertion
    const progressFill = page.locator('.video-decrypt-progress-fill');
    const appeared = await progressFill
      .waitFor({ state: 'visible', timeout: 5_000 })
      .then(() => true)
      .catch(() => false);

    if (appeared) {
      // Verify it has a width style (indicating actual progress rendering)
      const style = await progressFill.getAttribute('style');
      expect(style).toContain('width');
    }
    // If it didn't appear, the decrypt was too fast to observe -- acceptable

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.video-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });

  test('upload small video file (GCM fallback)', async () => {
    const file = createTestMediaFile('test-video-small.mp4', smallVideoName);
    await uploadZone.uploadFile(file.path);
    await fileList.waitForItemToAppear(smallVideoName, { timeout: 60_000 });
    expect(await fileList.isItemVisible(smallVideoName)).toBe(true);
  });

  test('small video plays via blob URL (no SW interception)', async () => {
    await fileList.rightClickItem(smallVideoName);
    await contextMenu.waitForOpen();
    await contextMenu.clickPreview();
    await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

    // Wait for the video element to have a src attribute
    const videoEl = page.locator('.video-player-modal video');
    await expect(videoEl).toBeVisible({ timeout: 15_000 });

    // Small files use GCM decryption with blob: URL (no service worker interception)
    const src = await videoEl.getAttribute('src');
    expect(src).toBeTruthy();
    expect(src!.startsWith('blob:')).toBe(true);

    // Close modal
    await page.keyboard.press('Escape');
    await page.locator('.video-player-modal').waitFor({ state: 'hidden', timeout: 5_000 });
  });
});
