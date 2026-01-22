import { Page, FrameLocator } from '@playwright/test';

/**
 * Test credentials from environment variables.
 * These are loaded from .env locally or GitHub Secrets in CI.
 */
export const TEST_CREDENTIALS = {
  email: process.env.WEB3AUTH_TEST_EMAIL || '',
  otp: process.env.WEB3AUTH_TEST_OTP || '',
};

/**
 * Waits for the Web3Auth/MetaMask modal to appear.
 * The modal can be either an iframe (older Web3Auth) or a direct DOM element (newer MetaMask SDK).
 *
 * @returns Object with isIframe flag and either frameLocator or page for interacting with modal
 */
export async function waitForWeb3AuthModal(
  page: Page
): Promise<{ isIframe: boolean; locator: FrameLocator | Page }> {
  // Try to detect which type of modal we have
  // Newer MetaMask SDK renders directly in the DOM, older Web3Auth uses iframe

  // Wait for either iframe or direct modal to appear
  await Promise.race([
    page.waitForSelector('iframe[id*="w3a"]', { timeout: 15000 }).catch(() => null),
    page
      .waitForSelector('[class*="w3a-modal"], [data-testid="w3a-modal"]', { timeout: 15000 })
      .catch(() => null),
    page
      .waitForSelector('button:has-text("Continue with Email")', { timeout: 15000 })
      .catch(() => null),
  ]);

  // Check if iframe exists
  const iframe = await page.$('iframe[id*="w3a"]');
  if (iframe) {
    const frame = page.frameLocator('iframe[id*="w3a"]');
    await frame.locator('[data-testid="w3a-modal"], .w3a-modal, #w3a-modal').waitFor({
      state: 'visible',
      timeout: 10000,
    });
    return { isIframe: true, locator: frame };
  }

  // Modal is rendered directly in the page (MetaMask SDK style)
  return { isIframe: false, locator: page };
}

/**
 * Performs email login through Web3Auth modal with automated OTP entry.
 * Uses test account credentials from environment variables.
 *
 * @param page - Playwright page instance
 * @param email - Email address for login
 * @param otp - Optional OTP code (defaults to TEST_CREDENTIALS.otp)
 */
export async function loginViaEmail(page: Page, email: string, otp?: string): Promise<void> {
  const otpCode = otp || TEST_CREDENTIALS.otp;

  // Click the Sign In button on the login page
  await page.click('button:has-text("Sign In")');

  // Wait for Web3Auth modal to appear
  await waitForWeb3AuthModal(page);

  // Click the "Continue with Email/Phone" button to reveal the email input
  const emailPhoneButton = page.locator(
    'button:has-text("Continue with Email"), :text("Continue with Email/Phone")'
  );
  await emailPhoneButton.first().waitFor({ state: 'visible', timeout: 10000 });
  await emailPhoneButton.first().click();

  // Wait for email input to appear after clicking the button
  const emailInput = page.locator(
    'input[placeholder*="@example.com"], input[placeholder*="email" i], input[type="email"], input[type="text"]'
  );
  await emailInput.first().waitFor({ state: 'visible', timeout: 10000 });

  // Fill the email input
  await emailInput.first().fill(email);

  // Press Enter or click submit button to proceed
  await page.keyboard.press('Enter');

  // Wait a moment for the form to process
  await page.waitForTimeout(2000);

  // Wait for OTP input screen to appear and enter code
  await enterOtpCode(page, otpCode);

  // Wait for redirect to dashboard after successful login
  await page.waitForURL('**/dashboard', { timeout: 60000 });
}

/**
 * Enters the OTP code in the Web3Auth modal.
 * Handles both single input and multiple input (one per digit) OTP fields.
 *
 * @param page - Playwright page instance
 * @param otp - The OTP code to enter
 */
export async function enterOtpCode(page: Page, otp: string): Promise<void> {
  // Wait for OTP input to appear (Web3Auth shows OTP screen after email submission)
  // Try multiple selectors as Web3Auth UI may vary
  const otpContainer = page.locator(
    '[data-testid="otp-input"], .otp-input, input[type="tel"], input[inputmode="numeric"], input[autocomplete="one-time-code"], input[maxlength="1"]'
  );

  await otpContainer.first().waitFor({ state: 'visible', timeout: 15000 });

  // Check if it's a single input or multiple inputs (one per digit)
  const multipleInputs = page.locator('input[maxlength="1"]');
  const multipleCount = await multipleInputs.count();

  if (multipleCount >= 4) {
    // Multiple input fields (one per digit) - common OTP UI pattern
    for (let i = 0; i < otp.length && i < multipleCount; i++) {
      await multipleInputs.nth(i).fill(otp[i]);
    }
  } else {
    // Single input field - enter full OTP
    const singleInput = page.locator(
      'input[type="tel"], input[inputmode="numeric"], input[autocomplete="one-time-code"]'
    );
    await singleInput.first().fill(otp);
  }

  // Look for verify/submit button and click it if present
  const verifyButton = page.locator(
    'button:has-text("Verify"), button:has-text("Submit"), button:has-text("Confirm"), button[type="submit"]'
  );

  const verifyButtonCount = await verifyButton.count();
  if (verifyButtonCount > 0) {
    await verifyButton.first().click();
  }
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
