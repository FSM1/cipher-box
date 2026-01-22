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

    // Storage state (cookies + localStorage) is already loaded by playwright.config.ts
    // Navigate to dashboard
    await page.goto('/dashboard');

    // Wait for either:
    // 1. Logout button (authenticated) - success
    // 2. Sign In button (redirected to login) - session expired
    const result = await Promise.race([
      page
        .waitForSelector('button:has-text("Logout")', { timeout: 15000 })
        .then(() => 'authenticated' as const),
      page
        .waitForSelector('button:has-text("Sign In")', { timeout: 15000 })
        .then(() => 'login_page' as const),
    ]);

    if (result === 'login_page') {
      throw new Error(`
        Web3Auth session has expired or is invalid.

        The storage state contains cookies, but Web3Auth doesn't recognize the session.
        This typically happens when:
        1. The Web3Auth session has expired (sessions last ~7 days)
        2. The localStorage data is stale or corrupted

        To fix:
        1. Delete tests/e2e/.auth/user.json
        2. Run 'pnpm test:e2e:headed tests/auth/login.spec.ts'
        3. Complete the Web3Auth login manually in the browser
        4. The new auth state will be saved automatically
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
