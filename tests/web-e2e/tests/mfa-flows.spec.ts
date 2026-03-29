import { test, expect, type Page, type BrowserContext } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import {
  createTestAccount,
  setupMockWallet,
  createWalletContext,
  loginViaWallet,
} from '../utils/wallet-login-helpers';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import {
  navigateToSecurityTab,
  getMfaStatusText,
  enrollMfa,
  enterRecoveryPhrase,
  waitForDeviceApproval,
  approveDevice,
  denyDevice,
} from '../utils/mfa-helpers';

/**
 * MFA E2E Flow Tests (TC-MFA-01 through TC-MFA-05)
 *
 * Tests the full MFA lifecycle using real wallet login (Core Kit
 * initialization via @johanneskares/wallet-mock). Serial execution
 * is required because MFA enrollment in TC-MFA-01 persists for
 * subsequent tests.
 *
 * Architecture:
 * - A random private key is generated per test run, giving a unique
 *   wallet address -> unique backend userId -> fresh DKG identity on
 *   Sapphire Devnet. This ensures no pre-existing MFA state.
 * - Primary browser context acts as the "existing device" throughout.
 * - New contexts are created for "new device" scenarios (TC-MFA-03/04/05).
 * - All contexts use the same random account so Core Kit maps them to
 *   the same DKG identity.
 *
 * Network:
 * - Core Kit operations hit Web3Auth Sapphire Devnet (5-15s per op).
 * - Full suite may take 60-120s.
 * - Tagged @mfa for optional CI filtering.
 *
 * Prerequisites:
 * - Local API running at http://localhost:3000
 * - Local web app running at http://localhost:5173
 */
test.describe.serial('MFA flows @mfa', () => {
  let account: PrivateKeyAccount;
  let primaryContext: BrowserContext;
  let primaryPage: Page;
  let recoveryPhrase: string;

  test.beforeAll(async ({ browser }) => {
    // Generate a random wallet identity for this test run
    account = createTestAccount();

    // Create primary context with mock wallet
    primaryContext = await browser.newContext();
    primaryPage = await primaryContext.newPage();
    await setupMockWallet(primaryPage, account);
  });

  test.afterAll(async () => {
    if (primaryPage) {
      await deleteAccountViaPage(primaryPage);
    }
    await primaryContext.close();
  });

  // ──────────────────────────────────────────────────
  // TC-MFA-01: Wallet login and MFA enrollment
  // ──────────────────────────────────────────────────
  test('TC-MFA-01: wallet login and MFA enrollment', async () => {
    test.setTimeout(120_000); // Core Kit init + enableMFA can be slow

    // 1. Login via wallet (happy path — no MFA yet, fresh identity)
    const result = await loginViaWallet(primaryPage, { timeout: 60_000 });
    expect(result.outcome).toBe('success');

    // Wait for login effects to fully settle before navigating away.
    // loginViaWallet resolves when the URL hits /files, but React state
    // updates (setIsLoggingIn(false), vault init effects) may still be
    // pending. Navigating to /settings too early can cause a late-firing
    // navigate('/files') from the login flow to redirect us back.
    // The "New Folder" button only renders when FileBrowser is fully mounted
    // and the auth guard has passed — a reliable proxy for "settled".
    await primaryPage.getByRole('button', { name: 'New Folder' }).waitFor({
      state: 'visible',
      timeout: 15_000,
    });

    // 2. Navigate to Settings → Security tab
    await navigateToSecurityTab(primaryPage);

    // 3. Verify MFA is currently disabled
    const statusBefore = await getMfaStatusText(primaryPage);
    expect(statusBefore).toBe('[DISABLED]');

    // 4. Run through the enrollment wizard
    //    This calls enableMFA on Devnet (~10-15s), generates recovery phrase,
    //    requires acknowledge checkbox, and confirms success.
    recoveryPhrase = await enrollMfa(primaryPage, { enableTimeout: 60_000 });

    // 5. Verify we got a valid 24-word phrase
    const words = recoveryPhrase.split(' ');
    expect(words).toHaveLength(24);
    expect(words.every((w) => w.length > 0)).toBe(true);

    // 6. Verify MFA is now enabled in the Security tab
    const statusAfter = await getMfaStatusText(primaryPage);
    expect(statusAfter).toBe('[ENABLED]');
  });

  // ──────────────────────────────────────────────────
  // TC-MFA-02: MFA status reflected in Security tab
  // ──────────────────────────────────────────────────
  test('TC-MFA-02: MFA status reflected in Security tab', async () => {
    test.setTimeout(30_000);

    // Navigate to Security tab (same context as enrollment)
    await navigateToSecurityTab(primaryPage);

    // Status badge should show [ENABLED]
    const status = await getMfaStatusText(primaryPage);
    expect(status).toBe('[ENABLED]');

    // Factor info should be visible with factor count
    const factorInfo = primaryPage.locator('.security-tab-factor-info');
    await expect(factorInfo).toBeVisible({ timeout: 5_000 });
    const factorText = await factorInfo.textContent();
    expect(factorText).toMatch(/\d+ factors active/);

    // The --enable-mfa button should NOT be visible (MFA already enabled)
    await expect(primaryPage.locator('[data-testid="mfa-enable-btn"]')).not.toBeVisible();
  });

  // ──────────────────────────────────────────────────
  // TC-MFA-03: Device approval — approve
  // ──────────────────────────────────────────────────
  test('TC-MFA-03: device approval - approve', async ({ browser }) => {
    test.setTimeout(120_000);

    // 1. Ensure primary page is on /files (approver device, polls for requests)
    await primaryPage.evaluate(() => {
      window.location.hash = '#/files';
    });
    await primaryPage.waitForURL('**/files', { timeout: 15_000 });

    // 2. Create new context B (no localStorage = new device, same wallet identity)
    const { context: contextB, page: pageB } = await createWalletContext(browser, account);

    try {
      // 3. Login via wallet on context B → should enter REQUIRED_SHARE
      const resultB = await loginViaWallet(pageB, { timeout: 60_000 });
      expect(resultB.outcome).toBe('requiredShare');

      // 4. Wait for DeviceWaitingScreen on context B
      await expect(pageB.locator('[data-testid="device-waiting"]')).toBeVisible({
        timeout: 10_000,
      });

      // 5. Wait for DeviceApprovalModal on primary page
      //    (polling picks up the approval request from context B)
      await waitForDeviceApproval(primaryPage, { timeout: 60_000 });

      // 6. Approve the request on primary page
      await approveDevice(primaryPage);

      // 7. Wait for context B to complete login → redirect to /files
      await pageB.waitForURL('**/files', { timeout: 60_000 });
    } finally {
      await contextB.close();
    }
  });

  // ──────────────────────────────────────────────────
  // TC-MFA-04: Recovery phrase restore
  // ──────────────────────────────────────────────────
  test('TC-MFA-04: recovery phrase restore', async ({ browser }) => {
    test.setTimeout(120_000);

    // 1. Create new context C (new device, same wallet identity)
    const { context: contextC, page: pageC } = await createWalletContext(browser, account);

    try {
      // 2. Login via wallet → should enter REQUIRED_SHARE
      const resultC = await loginViaWallet(pageC, { timeout: 60_000 });
      expect(resultC.outcome).toBe('requiredShare');

      // 3. Wait for DeviceWaitingScreen
      await expect(pageC.locator('[data-testid="device-waiting"]')).toBeVisible({
        timeout: 10_000,
      });

      // 4. Click "use recovery phrase instead"
      const recoveryLink = pageC.locator('[data-testid="device-waiting-recovery-link"]');
      await recoveryLink.waitFor({ state: 'visible', timeout: 10_000 });
      await recoveryLink.click();

      // 5. Enter recovery phrase and submit
      await enterRecoveryPhrase(pageC, recoveryPhrase, { timeout: 60_000 });

      // 6. Verify page redirected to /files (recovery succeeded)
      await expect(pageC).toHaveURL(/.*files/);
    } finally {
      await contextC.close();
    }
  });

  // ──────────────────────────────────────────────────
  // TC-MFA-05: Device approval — deny
  // ──────────────────────────────────────────────────
  test('TC-MFA-05: device approval - deny', async ({ browser }) => {
    test.setTimeout(120_000);

    // 1. Ensure primary page is on /files (denier device)
    await primaryPage.evaluate(() => {
      window.location.hash = '#/files';
    });
    await primaryPage.waitForURL('**/files', { timeout: 15_000 });

    // 2. Create new context D (new device, same wallet identity)
    const { context: contextD, page: pageD } = await createWalletContext(browser, account);

    try {
      // 3. Login via wallet → should enter REQUIRED_SHARE
      const resultD = await loginViaWallet(pageD, { timeout: 60_000 });
      expect(resultD.outcome).toBe('requiredShare');

      // 4. Wait for DeviceWaitingScreen on context D
      await expect(pageD.locator('[data-testid="device-waiting"]')).toBeVisible({
        timeout: 10_000,
      });

      // 5. Wait for DeviceApprovalModal on primary page
      await waitForDeviceApproval(primaryPage, { timeout: 60_000 });

      // 6. Deny the request on primary page
      await denyDevice(primaryPage);

      // 7. Verify context D shows "Request was denied" message
      const statusMessage = pageD.locator('[data-testid="device-waiting-status"]');
      await expect(statusMessage).toBeVisible({ timeout: 30_000 });
      const statusText = await statusMessage.textContent();
      expect(statusText).toContain('denied');
    } finally {
      await contextD.close();
    }
  });
});
