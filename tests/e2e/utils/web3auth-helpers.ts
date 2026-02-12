import { Page } from '@playwright/test';

/**
 * Test credentials from environment variables.
 * These are loaded from .env locally or GitHub Secrets in CI.
 *
 * With Core Kit, the E2E flow uses CipherBox's own login UI:
 * 1. Enter email in CipherBox email input
 * 2. Backend sends OTP (static OTP in test mode)
 * 3. Enter OTP code
 * 4. CipherBox JWT -> Core Kit loginWithJWT -> backend auth -> vault init
 */
export const TEST_CREDENTIALS = {
  email: process.env.WEB3AUTH_TEST_EMAIL || '',
  otp: process.env.WEB3AUTH_TEST_OTP || '',
};

/**
 * Performs email login through CipherBox's custom login UI.
 * With Core Kit (Phase 12), login is handled entirely through CipherBox's
 * own email + OTP form -- no more Web3Auth modal popup/iframe.
 *
 * Flow:
 * 1. Navigate to login page
 * 2. Enter email in CipherBox's email input
 * 3. Click [SEND OTP]
 * 4. Wait for OTP form, enter test OTP code
 * 5. Click [VERIFY]
 * 6. Wait for redirect to /files (login + vault init complete)
 *
 * @param page - Playwright page instance
 * @param email - Email address for login
 * @param otp - Optional OTP code (defaults to TEST_CREDENTIALS.otp)
 */
export async function loginViaEmail(page: Page, email: string, otp?: string): Promise<void> {
  const otpCode = otp || TEST_CREDENTIALS.otp;

  // If SKIP_CORE_KIT is set, use direct API auth (fallback for environments
  // where Core Kit loginWithJWT doesn't work, e.g., Web3Auth devnet rate limits)
  if (process.env.SKIP_CORE_KIT) {
    console.warn('[E2E] SKIP_CORE_KIT set -- using direct API auth (no Core Kit loginWithJWT)');
    await loginViaDirectApi(page, email, otpCode);
    return;
  }

  // Navigate to login page
  await page.goto('/');

  // Step 1: Enter email in CipherBox's own email input
  const emailInput = page.locator('[data-testid="email-input"]');
  await emailInput.waitFor({ state: 'visible', timeout: 15000 });
  await emailInput.fill(email);

  // Step 2: Click [SEND OTP] button
  const sendOtpButton = page.locator('[data-testid="send-otp-button"]');
  await sendOtpButton.click();

  // Step 3: Wait for OTP input to appear (backend sends OTP, form transitions)
  const otpInput = page.locator('[data-testid="otp-input"]');
  await otpInput.waitFor({ state: 'visible', timeout: 15000 });

  // Step 4: Enter the test OTP code
  await otpInput.fill(otpCode);

  // Step 5: Click [VERIFY] button
  const verifyButton = page.locator('[data-testid="verify-button"]');
  await verifyButton.click();

  // Step 6: Wait for login to complete and redirect to files page
  // Core Kit loginWithJWT + backend auth + vault init can take time
  await page.waitForURL('**/files', { timeout: 60000 });
}

/**
 * Direct API auth fallback for E2E when Core Kit is unavailable.
 * Skips Core Kit loginWithJWT entirely -- authenticates directly with
 * the CipherBox backend using the identity endpoint + auth/login.
 *
 * This is useful when:
 * - Web3Auth devnet has rate limits or downtime
 * - JWKS validation issues prevent Core Kit from working in CI
 * - Running quick smoke tests that don't need full Core Kit flow
 *
 * Note: This does NOT exercise the Core Kit MPC key derivation path.
 * The user's vault keypair will be different from Core Kit-derived keys.
 */
async function loginViaDirectApi(page: Page, email: string, otp: string): Promise<void> {
  // Navigate to the app -- we'll inject auth state programmatically
  await page.goto('/');

  // Use the API base URL from env or default
  const apiBase = process.env.API_BASE_URL || 'http://localhost:3000';

  // Call identity endpoint to get CipherBox JWT
  const verifyResponse = await page.request.post(`${apiBase}/auth/identity/email/verify`, {
    data: { email, otp },
  });

  if (!verifyResponse.ok()) {
    throw new Error(`Identity email verify failed: ${verifyResponse.status()}`);
  }

  const { idToken } = await verifyResponse.json();

  // Call auth/login with the CipherBox JWT (corekit login type)
  // Note: Without Core Kit, we don't have a real secp256k1 publicKey.
  // The backend will use the placeholder publicKey for this user.
  const loginResponse = await page.request.post(`${apiBase}/auth/login`, {
    data: {
      idToken,
      publicKey: 'e2e-direct-api-placeholder',
      loginType: 'corekit',
    },
  });

  if (!loginResponse.ok()) {
    throw new Error(`Auth login failed: ${loginResponse.status()}`);
  }

  const { accessToken } = await loginResponse.json();

  // Inject the access token into the app's auth store via localStorage/evaluate
  await page.evaluate((token: string) => {
    // Set the access token in the Zustand auth store persistence
    const authState = {
      state: {
        accessToken: token,
        isAuthenticated: true,
        lastAuthMethod: 'email_passwordless',
      },
      version: 0,
    };
    localStorage.setItem('auth-storage', JSON.stringify(authState));
  }, accessToken);

  // Reload to pick up the injected auth state
  await page.reload({ waitUntil: 'domcontentloaded' });

  // Wait for redirect to files page
  await page.waitForURL('**/files', { timeout: 30000 });
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
  // Wait for user menu to appear (indicator of authenticated state)
  // Phase 6.3: Logout moved to UserMenu dropdown
  await page.waitForSelector('[data-testid="user-menu"]', { timeout: 15000 });
}
