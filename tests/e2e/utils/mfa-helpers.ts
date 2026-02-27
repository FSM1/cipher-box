import { type Page, expect } from '@playwright/test';

/**
 * Navigate to the Settings page and click the Security tab.
 *
 * Waits for the security tab content to be visible before returning.
 */
export async function navigateToSecurityTab(page: Page): Promise<void> {
  // Navigate to settings (hash router)
  await page.evaluate(() => {
    window.location.hash = '#/settings';
  });
  await page.waitForURL('**/settings', { timeout: 15_000 });

  // Click the SECURITY tab
  const securityTab = page.locator('#tab-security');
  await securityTab.waitFor({ state: 'visible', timeout: 10_000 });
  await securityTab.click();

  // Wait for the security tab content to render
  await page.locator('[data-testid="security-tab"]').waitFor({ state: 'visible', timeout: 10_000 });
}

/**
 * Read the MFA status badge text from the Security tab.
 *
 * Assumes the Security tab is already visible. Returns the text
 * content of the status badge (e.g. "[ENABLED]" or "[DISABLED]").
 */
export async function getMfaStatusText(page: Page): Promise<string> {
  const badge = page.locator('[data-testid="mfa-status-badge"]');
  await badge.waitFor({ state: 'visible', timeout: 10_000 });
  const text = await badge.textContent();
  return text?.trim() ?? '';
}

/**
 * Run through the full MFA enrollment wizard.
 *
 * Assumes the page is on the Security tab with MFA currently disabled.
 * Steps:
 * 1. Click --enable-mfa button
 * 2. Step 1: Click --continue
 * 3. Step 2: Wait for enableMFA to complete (hits Devnet, ~10-15s)
 * 4. Extract recovery phrase words
 * 5. Check acknowledge checkbox
 * 6. Click --continue
 * 7. Step 3: Click --done
 *
 * Returns the 24-word recovery phrase as a single space-separated string.
 *
 * @param page - Page on the Security tab
 * @param options.enableTimeout - Max time to wait for MFA enablement (default: 45s)
 */
export async function enrollMfa(
  page: Page,
  options: { enableTimeout?: number } = {}
): Promise<string> {
  const enableTimeout = options.enableTimeout ?? 45_000;

  // Click the --enable-mfa button to open the wizard
  const enableBtn = page.locator('[data-testid="mfa-enable-btn"]');
  await enableBtn.waitFor({ state: 'visible', timeout: 10_000 });
  await enableBtn.click();

  // Step 1: Wizard explanation screen
  await page
    .locator('[data-testid="mfa-wizard-step-1"]')
    .waitFor({ state: 'visible', timeout: 10_000 });
  const continueBtn1 = page.locator('[data-testid="mfa-wizard-continue"]');
  await continueBtn1.click();

  // Step 2: Wait for MFA enablement + recovery phrase generation
  await page
    .locator('[data-testid="mfa-wizard-step-2"]')
    .waitFor({ state: 'visible', timeout: 10_000 });

  // Wait for loading to finish (enableMFA hits Devnet — can take 10-15s)
  // Wait for either: recovery phrase grid (success) or error div (failure)
  const gridLocator = page.locator('[data-testid="recovery-phrase-grid"]');
  const errorLocator = page.locator('[data-testid="mfa-wizard-error"]');

  await gridLocator.or(errorLocator).waitFor({ state: 'visible', timeout: enableTimeout });

  if (await errorLocator.isVisible()) {
    const errorText = await errorLocator.textContent();
    throw new Error(`MFA enrollment failed: ${errorText}`);
  }

  // Extract the recovery phrase words
  const phrase = await extractRecoveryPhrase(page);

  // Check the acknowledge checkbox
  const checkbox = page.locator('[data-testid="mfa-wizard-acknowledge"]');
  await checkbox.click();

  // Click --continue to go to step 3
  const continueBtn2 = page.locator('[data-testid="mfa-wizard-continue"]');
  await continueBtn2.click();

  // Step 3: Success confirmation
  await page
    .locator('[data-testid="mfa-wizard-step-3"]')
    .waitFor({ state: 'visible', timeout: 10_000 });

  // Click --done to close wizard
  const doneBtn = page.locator('[data-testid="mfa-wizard-done"]');
  await doneBtn.click();

  // Wait for wizard to close (security tab should be back to normal state)
  await expect(page.locator('[data-testid="mfa-wizard"]')).not.toBeVisible({ timeout: 5_000 });

  return phrase;
}

/**
 * Extract the 24-word recovery phrase from the RecoveryPhraseGrid.
 *
 * Reads individual word spans from the grid and joins them.
 * Assumes the grid is already visible on the page.
 */
export async function extractRecoveryPhrase(page: Page): Promise<string> {
  const grid = page.locator('[data-testid="recovery-phrase-grid"]');
  await grid.waitFor({ state: 'visible', timeout: 10_000 });

  const wordSpans = grid.locator('.recovery-phrase-word');
  const count = await wordSpans.count();
  const words: string[] = [];
  for (let i = 0; i < count; i++) {
    const text = await wordSpans.nth(i).textContent();
    if (text) words.push(text.trim());
  }

  if (words.length !== 24) {
    throw new Error(`Expected 24 recovery phrase words, got ${words.length}`);
  }

  return words.join(' ');
}

/**
 * Enter a recovery phrase into the RecoveryInput form and submit.
 *
 * Assumes the RecoveryInput component is visible (user clicked
 * "use recovery phrase instead" on DeviceWaitingScreen).
 *
 * @param page - Page showing the RecoveryInput component
 * @param mnemonic - The 24-word recovery phrase (space-separated)
 * @param options.timeout - Max time to wait for recovery to complete (default: 45s)
 */
export async function enterRecoveryPhrase(
  page: Page,
  mnemonic: string,
  options: { timeout?: number } = {}
): Promise<void> {
  const timeout = options.timeout ?? 45_000;

  // Wait for the recovery input form
  await page
    .locator('[data-testid="recovery-input"]')
    .waitFor({ state: 'visible', timeout: 10_000 });

  // Fill in the phrase
  const textarea = page.locator('[data-testid="recovery-textarea"]');
  await textarea.fill(mnemonic);

  // Click --recover
  const submitBtn = page.locator('[data-testid="recovery-submit"]');
  await submitBtn.click();

  // Wait for recovery to complete (redirects to /files)
  await page.waitForURL('**/files', { timeout });
}

/**
 * Wait for the DeviceApprovalModal to appear on an existing device.
 *
 * This modal shows when a new device requests approval and the existing
 * device is polling for pending requests.
 *
 * @param page - Page of the existing (approver) device
 * @param options.timeout - Max time to wait (default: 60s)
 */
export async function waitForDeviceApproval(
  page: Page,
  options: { timeout?: number } = {}
): Promise<void> {
  const timeout = options.timeout ?? 60_000;
  await page.locator('[data-testid="device-approval-modal"]').waitFor({
    state: 'visible',
    timeout,
  });
}

/**
 * Click the --approve button on the DeviceApprovalModal.
 *
 * Assumes the modal is already visible (use waitForDeviceApproval first).
 * Does not wait for modal dismissal — the approver's background polling
 * may briefly re-add the request from a stale in-flight response.
 * Tests should verify the action took effect via the requester side instead.
 */
export async function approveDevice(page: Page): Promise<void> {
  const approveBtn = page.locator('[data-testid="device-approval-approve"]');
  await approveBtn.waitFor({ state: 'visible', timeout: 5_000 });
  await approveBtn.click();
}

/**
 * Click the --deny button on the DeviceApprovalModal.
 *
 * Assumes the modal is already visible (use waitForDeviceApproval first).
 * Same polling caveat as approveDevice — verify via requester side.
 */
export async function denyDevice(page: Page): Promise<void> {
  const denyBtn = page.locator('[data-testid="device-approval-deny"]');
  await denyBtn.waitFor({ state: 'visible', timeout: 5_000 });
  await denyBtn.click();
}
