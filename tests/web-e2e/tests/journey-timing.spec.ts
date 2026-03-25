import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { createTestAccount, setupMockWallet } from '../utils/wallet-login-helpers';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Journey Timing E2E Test Suite
 *
 * Measures real browser wall-clock time for three critical user journeys:
 * 1. Login-to-Vault: Mock wallet login -> file list visible
 * 2. Upload-to-Visible: File upload -> file appears in list
 * 3. Share-to-Accessible: Share creation -> recipient sees shared item
 *
 * All timings use performance.now() (high resolution, ~microsecond precision).
 * Results are output as structured JSON prefixed with JOURNEY_TIMING: for grep capture.
 *
 * PERF-06: End-to-end user journey timing baselines.
 */

interface JourneyResult {
  journey: string;
  totalMs: number | null;
  phases?: Record<string, number>;
  fileSizeBytes?: number;
  note?: string;
}

const journeyResults: JourneyResult[] = [];

test.describe.serial('Journey Timing', () => {
  // Shared state across serial tests
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  // Page objects for Alice (primary account)
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;

  // For share journey
  let bob: WalletTestAccount | null = null;

  // Test data
  const runId = Date.now().toString();
  const uploadFileName = `journey-upload-${runId}.txt`;
  const shareFileName = `journey-share-${runId}.txt`;

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();

    // Output summary of all journey results
    console.log(
      `JOURNEY_TIMING: ${JSON.stringify({
        summary: true,
        capturedAt: new Date().toISOString(),
        journeys: journeyResults,
      })}`
    );

    // Close Bob's context if created
    if (bob) {
      await closeWalletTestAccounts([bob]);
    }

    // Close Alice's context
    if (context) {
      await context.close();
    }
  });

  // ============================================
  // Journey 1: Login-to-Vault
  // ============================================

  test('Journey 1: login-to-vault', async () => {
    test.setTimeout(120_000);

    // Setup: create account and context BEFORE timing starts
    const account = createTestAccount();
    context = await browser.newContext();
    page = await context.newPage();
    await setupMockWallet(page, account);

    // --- TIMING START ---
    const journeyStart = performance.now();

    // Navigate to login page and initiate wallet login
    await page.goto('/');

    // Wait for Core Kit to initialize (wallet button becomes enabled)
    const walletButton = page.locator('[data-testid="wallet-login-button"]');
    await walletButton.waitFor({ state: 'visible', timeout: 20_000 });
    await page.waitForFunction(
      () => {
        const btn = document.querySelector(
          '[data-testid="wallet-login-button"]'
        ) as HTMLButtonElement;
        return btn && !btn.disabled;
      },
      { timeout: 20_000 }
    );

    // Click wallet button and select Mock Wallet
    await walletButton.click();
    const connectorList = page.locator('.wallet-connector-list');
    await connectorList.waitFor({ state: 'visible', timeout: 5_000 });
    const mockWalletOption = page.locator('.wallet-connector-option', {
      hasText: 'Mock Wallet',
    });
    await mockWalletOption.click();

    // Wait for redirect to /files
    await page.waitForURL('**/files', { timeout: 60_000 });
    const walletAuthEnd = performance.now();

    // Wait for file list or empty state to be visible (vault loaded)
    await Promise.race([
      page.locator('.file-list[role="grid"]').waitFor({ state: 'visible', timeout: 30_000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30_000 }),
    ]);

    // --- TIMING END ---
    const journeyEnd = performance.now();

    const walletAuthMs = Math.round(walletAuthEnd - journeyStart);
    const vaultLoadMs = Math.round(journeyEnd - walletAuthEnd);
    const totalMs = Math.round(journeyEnd - journeyStart);

    const result: JourneyResult = {
      journey: 'login-to-vault',
      totalMs,
      phases: { walletAuthMs, vaultLoadMs },
    };

    journeyResults.push(result);
    console.log(`JOURNEY_TIMING: ${JSON.stringify(result)}`);

    // Sanity check: should complete in under 60s
    expect(totalMs).toBeLessThan(60_000);

    // Initialize page objects for subsequent tests
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
  });

  // ============================================
  // Journey 2: Upload-to-Visible
  // ============================================

  test('Journey 2: upload-to-visible', async () => {
    test.setTimeout(60_000);

    // Create a 100KB test file
    const fileContent = 'x'.repeat(102_400); // 100KB of text
    const testFile = createTestTextFile(uploadFileName, fileContent);

    // --- TIMING START ---
    const journeyStart = performance.now();

    // Upload via file input
    await uploadZone.uploadFile(testFile.path);

    // Wait for file to appear in the file list
    await fileList.waitForItemToAppear(uploadFileName, { timeout: 30_000 });

    // --- TIMING END ---
    const journeyEnd = performance.now();

    const totalMs = Math.round(journeyEnd - journeyStart);

    const result: JourneyResult = {
      journey: 'upload-to-visible',
      totalMs,
      fileSizeBytes: 102_400,
    };

    journeyResults.push(result);
    console.log(`JOURNEY_TIMING: ${JSON.stringify(result)}`);

    // Sanity check: should complete in under 30s
    expect(totalMs).toBeLessThan(30_000);
  });

  // ============================================
  // Journey 3: Share-to-Accessible
  // ============================================

  test('Journey 3: share-to-accessible', async () => {
    test.setTimeout(180_000);

    // Alice needs a file to share. Upload a dedicated file for this journey.
    const shareContent = 'This file is for the share timing journey';
    const shareFile = createTestTextFile(shareFileName, shareContent);
    await uploadZone.uploadFile(shareFile.path);
    await fileList.waitForItemToAppear(shareFileName, { timeout: 30_000 });

    // Create Bob's account (separate context, separate wallet identity)
    try {
      bob = await createWalletTestAccount(browser, 'bob');
    } catch (err) {
      // If Bob's account creation fails, record a partial result
      const result: JourneyResult = {
        journey: 'share-to-accessible',
        totalMs: null,
        note: `Multi-account setup failed: ${err instanceof Error ? err.message : String(err)}`,
      };
      journeyResults.push(result);
      console.log(`JOURNEY_TIMING: ${JSON.stringify(result)}`);
      return;
    }

    // Initialize page objects
    const aliceContextMenu = new ContextMenuPage(page);
    const aliceShareDialog = new ShareDialogPage(page);
    const bobSharedBrowser = new SharedFileBrowserPage(bob.page);

    // --- TIMING START ---
    const journeyStart = performance.now();

    // Alice: right-click file -> Share -> enter Bob's public key -> confirm
    await fileList.rightClickItem(shareFileName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
    await aliceShareDialog.waitForRecipientsLoaded();
    await aliceShareDialog.shareWithKey(bob.publicKey);
    await aliceShareDialog.waitForSuccess({ timeout: 30_000 });
    await aliceShareDialog.close();

    const shareCreateEnd = performance.now();

    // Bob: navigate to Shared section and wait for the shared item
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30_000 });
    await bobSharedBrowser.waitForSharedItem(shareFileName, { timeout: 30_000 });

    // --- TIMING END ---
    const journeyEnd = performance.now();

    const shareCreateMs = Math.round(shareCreateEnd - journeyStart);
    const recipientAccessMs = Math.round(journeyEnd - shareCreateEnd);
    const totalMs = Math.round(journeyEnd - journeyStart);

    const result: JourneyResult = {
      journey: 'share-to-accessible',
      totalMs,
      phases: { shareCreateMs, recipientAccessMs },
    };

    journeyResults.push(result);
    console.log(`JOURNEY_TIMING: ${JSON.stringify(result)}`);

    // Sanity check: should complete in under 120s
    expect(totalMs).toBeLessThan(120_000);
  });
});
