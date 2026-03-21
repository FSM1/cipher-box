import { Browser, BrowserContext, Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { setupMockWallet, loginViaWallet } from './wallet-login-helpers';
import { createTestTextFile } from './test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';

/**
 * Conflict detection test helpers.
 *
 * Simulates concurrent device publishes by using a second browser session
 * logged in as the same user. When the second session uploads a file,
 * the server-side sequence number increments, making the first session's
 * local sequence stale.
 */

/**
 * A second browser session logged in as the same user.
 * Used to simulate another device publishing to the same vault.
 */
export interface ConflictDevice {
  context: BrowserContext;
  page: Page;
  fileList: FileListPage;
  uploadZone: UploadZonePage;
}

/**
 * Create a second browser session logged in as the same wallet identity.
 *
 * This simulates a second device accessing the same vault. When this
 * session performs mutations (upload, create folder), it bumps the
 * server-side sequence number, making the primary session's local
 * sequence stale.
 *
 * @param browser - Playwright browser instance
 * @param account - Same wallet account as the primary session
 */
export async function createConflictDevice(
  browser: Browser,
  account: PrivateKeyAccount
): Promise<ConflictDevice> {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await setupMockWallet(page, account);
    await loginViaWallet(page, { timeout: 90_000 });

    // Wait for vault to load
    await Promise.race([
      page.locator('.file-list[role="grid"]').waitFor({ state: 'visible', timeout: 30_000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30_000 }),
    ]);

    return {
      context,
      page,
      fileList: new FileListPage(page),
      uploadZone: new UploadZonePage(page),
    };
  } catch (err) {
    await context.close().catch(() => undefined);
    throw err;
  }
}

/**
 * Bump the server-side sequence by uploading a file from the second device.
 *
 * This is a real mutation through the UI — no direct API calls or store
 * access needed. The upload publishes new folder metadata with an
 * incremented sequence number, making any other session's local sequence
 * stale.
 *
 * @param device - Second browser session (conflict device)
 * @param runId - Unique test run identifier for file naming
 * @returns Name of the uploaded bump file
 */
export async function bumpSequenceViaSecondDevice(
  device: ConflictDevice,
  runId: string
): Promise<string> {
  const bumpFileName = `seq-bump-${runId}-${Date.now()}.txt`;
  const bumpFile = createTestTextFile(bumpFileName, 'sequence bump from second device');
  await device.uploadZone.uploadFile(bumpFile.path);
  await device.fileList.waitForItemToAppear(bumpFileName, { timeout: 60_000 });
  return bumpFileName;
}

/**
 * Close the conflict device session.
 */
export async function closeConflictDevice(device: ConflictDevice): Promise<void> {
  await device.context.close().catch(() => undefined);
}
