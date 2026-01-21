import { test as base, Page } from '@playwright/test';
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'fs';
import { resolve, dirname } from 'path';

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
 * Test fixture that provides an authenticated page.
 * The page will be on the dashboard and ready for testing.
 */
export const authenticatedTest = base.extend<AuthenticatedFixtures>({
  authenticatedPage: async ({ page }, use) => {
    // Check if storage state file exists
    if (existsSync(AUTH_STATE_FILE)) {
      // Fast path: Load saved authentication state
      const storageState = JSON.parse(readFileSync(AUTH_STATE_FILE, 'utf-8'));
      await page.context().addCookies(storageState.cookies);

      // Navigate to dashboard
      await page.goto('/dashboard');

      // Verify authentication by checking for logout button
      await page.waitForSelector('button:has-text("Logout")', { timeout: 5000 });
    } else {
      // No storage state available
      // For now, skip the test and inform user
      throw new Error(`
        Authentication state not found at ${AUTH_STATE_FILE}

        To run authenticated tests, you need to:
        1. Run a manual login test once to save auth state
        2. Or use the setup script to generate auth state

        For CI environments, auth state should be generated during setup.
      `);
    }

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
