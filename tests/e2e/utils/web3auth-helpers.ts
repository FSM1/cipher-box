import { Page, FrameLocator } from '@playwright/test';

/**
 * Waits for the Web3Auth modal iframe to appear and returns a locator for it.
 * The Web3Auth modal is rendered in an iframe for security.
 */
export async function waitForWeb3AuthModal(page: Page): Promise<FrameLocator> {
  // Web3Auth renders its modal in an iframe
  // Wait for the iframe to appear (with increased timeout for modal loading)
  await page.waitForSelector('iframe[id*="w3a"]', { timeout: 10000 });

  // Get the frame locator
  const frame = page.frameLocator('iframe[id*="w3a"]');

  // Wait for modal content to be visible
  await frame.locator('[data-testid="w3a-modal"], .w3a-modal, #w3a-modal').waitFor({
    state: 'visible',
    timeout: 5000,
  });

  return frame;
}

/**
 * Performs email login through Web3Auth modal.
 * Note: This function requires manual OTP verification in non-CI environments.
 * For automated CI testing, use storage state or API-based auth instead.
 *
 * @param page - Playwright page instance
 * @param email - Email address for login
 */
export async function loginViaEmail(page: Page, email: string): Promise<void> {
  // Click the Sign In button on the login page
  await page.click('button:has-text("Sign In")');

  // Wait for Web3Auth modal to appear
  const modal = await waitForWeb3AuthModal(page);

  // Look for email login option
  // Web3Auth modal structure may vary, so we try multiple selectors
  const emailButton = modal.locator(
    'button:has-text("Email"), [data-testid="email-login"], button:has([alt*="email"])'
  );
  await emailButton.first().click();

  // Enter email address
  const emailInput = modal.locator('input[type="email"], input[name="email"]');
  await emailInput.fill(email);

  // Submit email
  const submitButton = modal.locator(
    'button[type="submit"], button:has-text("Continue"), button:has-text("Send")'
  );
  await submitButton.first().click();

  // Note: At this point, in Sapphire Devnet, OTP verification is required.
  // For interactive tests, user needs to enter OTP manually.
  // For CI tests, this should be replaced with storage state or API auth.

  // Wait for redirect to dashboard after successful login
  await page.waitForURL('**/dashboard', { timeout: 60000 });
}

/**
 * Gets the current storage state (cookies and localStorage).
 * Useful for saving authenticated session state.
 */
export async function getStorageState(page: Page): Promise<object> {
  return await page.context().storageState();
}

/**
 * Waits for the user to be authenticated by checking for auth indicators.
 * This is useful after manual login or when loading storage state.
 */
export async function waitForAuthentication(page: Page): Promise<void> {
  // Wait for logout button to appear (indicator of authenticated state)
  await page.waitForSelector('button:has-text("Logout")', { timeout: 10000 });
}
