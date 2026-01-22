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
 *
 * This fixture just navigates to dashboard and verifies authentication.
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
        - Ensure .env file has WEB3AUTH_TEST_EMAIL and WEB3AUTH_TEST_OTP set
        - Check global-setup.ts logs for login errors
        - For CI, ensure GitHub Secrets are configured
      `);
    }

    // Storage state (cookies + localStorage) is already loaded by playwright.config.ts
    // Just navigate to dashboard and verify authentication
    await page.goto('/dashboard');

    // Verify authentication by checking for logout button
    await page.waitForSelector('button:has-text("Logout")', { timeout: 10000 });

    // Use the authenticated page
    await use(page);
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
  writeFileSync(AUTH_STATE_FILE, JSON.stringify(storageState, null, 2));

  console.log(`Authentication state saved to ${AUTH_STATE_FILE}`);
}
