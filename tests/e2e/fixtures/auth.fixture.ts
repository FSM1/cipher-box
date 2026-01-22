import { test as base, Page } from '@playwright/test';
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Path to the storage state file containing authenticated session.
 * This file is gitignored and needs to be generated once locally.
 */
const AUTH_STATE_FILE = resolve(__dirname, '../.auth/user.json');

/**
 * Extended test fixture that provides authenticated page context.
 * This fixture handles authentication in two ways:
 * 1. If storage state exists: Fast path - load saved auth state
 * 2. If no storage state: User needs to perform manual login once to save state
 *
 * Usage:
 * ```typescript
 * import { authenticatedTest } from '../fixtures/auth.fixture';
 *
 * authenticatedTest('my test', async ({ authenticatedPage }) => {
 *   // Page is already authenticated and on dashboard
 *   await authenticatedPage.click('button');
 * });
 * ```
 */

type AuthenticatedFixtures = {
  authenticatedPage: Page;
};

/**
 * Checks if the auth state file contains valid authentication (not just a placeholder).
 */
function hasValidAuthState(): boolean {
  if (!existsSync(AUTH_STATE_FILE)) {
    return false;
  }

  try {
    const storageState = JSON.parse(readFileSync(AUTH_STATE_FILE, 'utf-8'));
    // Check if there are actual cookies (placeholder has empty array)
    return storageState.cookies && storageState.cookies.length > 0;
  } catch {
    return false;
  }
}

/**
 * Test fixture that provides an authenticated page.
 * The page will be on the dashboard and ready for testing.
 *
 * Authentication is handled by:
 * 1. global-setup.ts which performs automated login and saves auth state
 * 2. playwright.config.ts which loads storageState for all tests
 * 3. If Web3Auth session isn't restored, this fixture enables E2E test mode
 *    which triggers the app to refresh the session using the backend API
 *    without requiring Web3Auth to be connected.
 *
 * IMPORTANT: Web3Auth sessions may expire. If tests fail with auth errors,
 * regenerate the auth state by running: pnpm test:e2e:headed
 * and completing the Web3Auth login manually.
 */
export const authenticatedTest = base.extend<AuthenticatedFixtures>({
  authenticatedPage: async ({ page }, use) => {
    // Check if we have valid auth state (with actual cookies, not placeholder)
    if (!hasValidAuthState()) {
      throw new Error(`
        Valid authentication state not found at ${AUTH_STATE_FILE}

        This usually means:
        1. Web3Auth test credentials are not configured (WEB3AUTH_TEST_EMAIL, WEB3AUTH_TEST_OTP)
        2. Automated login in global-setup.ts failed
        3. The auth state file contains only a placeholder

        To fix:
        - Run 'pnpm test:e2e:headed' and complete Web3Auth login manually
        - Or ensure .env file has WEB3AUTH_TEST_EMAIL and WEB3AUTH_TEST_OTP set
        - For CI, ensure GitHub Secrets are configured
      `);
    }

    // Explicitly load the LATEST storage state from file
    // This ensures we get any tokens that were rotated by previous tests
    const latestState = JSON.parse(readFileSync(AUTH_STATE_FILE, 'utf-8'));

    // Debug: log the refresh token being used
    const refreshToken = latestState.cookies?.find(
      (c: { name: string }) => c.name === 'refresh_token'
    );
    console.log(`[Fixture] Loading refresh token: ${refreshToken?.value?.substring(0, 8)}...`);

    // Add cookies from the latest state to the context
    // This overrides any stale cookies that Playwright cached at context creation
    if (latestState.cookies?.length > 0) {
      await page.context().addCookies(latestState.cookies);
    }

    // Set E2E test mode flag BEFORE navigating to the page.
    // This tells the app's useAuth hook to try session restoration
    // using just the refresh token (without requiring Web3Auth isConnected).
    await page.addInitScript(() => {
      sessionStorage.setItem('__e2e_test_mode__', 'true');
    });

    // Navigate to dashboard (cookies are now set)
    await page.goto('/dashboard');

    // Wait for either:
    // 1. Logout button (authenticated) - success
    // 2. Sign In button (redirected to login) - session restoration failed
    const result = await Promise.race([
      page
        .waitForSelector('button:has-text("Logout")', { timeout: 20000 })
        .then(() => 'authenticated' as const),
      page
        .waitForSelector('button:has-text("Sign In")', { timeout: 20000 })
        .then(() => 'login_page' as const),
    ]);

    if (result === 'login_page') {
      // Session restoration failed even with E2E test mode enabled.
      // This likely means the refresh token is expired or invalid.

      throw new Error(`
        Session restoration failed in E2E test mode.

        The app was unable to restore the session using the refresh token cookie.
        This typically means:
        1. The refresh token has expired (tokens expire after ~7 days)
        2. The refresh token was revoked or is invalid

        To fix:
        1. Delete tests/e2e/.auth/user.json
        2. Run 'pnpm test:e2e:headed tests/auth/login.spec.ts'
        3. Complete the Web3Auth login manually in the browser
        4. The new auth state will be saved automatically
      `);
    }

    // Save updated storage state with the new (rotated) refresh token cookie
    // This ensures subsequent tests can authenticate successfully
    // Note: This must happen BEFORE the test runs, not after, because tests that
    // perform logout will revoke all tokens, making the saved state invalid.
    await saveAuthState(page);

    // Use the authenticated page
    await use(page);

    // Note: We intentionally do NOT save state after the test completes.
    // If the test performed a logout, all tokens are revoked and the state would be invalid.
    // The next test will refresh and save a new valid state.
  },
});

/**
 * Helper to create authenticated context with storage state.
 * Used by tests that need to setup authentication.
 */
export async function saveAuthState(page: Page): Promise<void> {
  // Ensure .auth directory exists
  const authDir = dirname(AUTH_STATE_FILE);
  if (!existsSync(authDir)) {
    mkdirSync(authDir, { recursive: true });
  }

  // Save storage state
  const storageState = await page.context().storageState();

  // Debug: log the refresh token being saved
  const refreshToken = storageState.cookies?.find(
    (c: { name: string }) => c.name === 'refresh_token'
  );
  console.log(`[Fixture] Saving refresh token: ${refreshToken?.value?.substring(0, 8)}...`);

  writeFileSync(AUTH_STATE_FILE, JSON.stringify(storageState, null, 2));

  console.log(`Authentication state saved to ${AUTH_STATE_FILE}`);
}
