import { test as base, expect } from '@playwright/test';
import { LoginPage } from '../page-objects/login.page';
import { DashboardPage } from '../page-objects/dashboard.page';

/**
 * Extended test fixtures with page objects for consistent test setup.
 * Provides pre-instantiated page objects for common pages.
 */
type TestFixtures = {
  loginPage: LoginPage;
  dashboardPage: DashboardPage;
};

/**
 * Extended Playwright test with custom fixtures.
 * Import this instead of @playwright/test in test files.
 */
export const test = base.extend<TestFixtures>({
  /**
   * Login page fixture - automatically instantiated with current page
   */
  loginPage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);
    await use(loginPage);
  },

  /**
   * Dashboard page fixture - automatically instantiated with current page
   */
  dashboardPage: async ({ page }, use) => {
    const dashboardPage = new DashboardPage(page);
    await use(dashboardPage);
  },

  // TODO: Add authenticatedPage fixture
  // This will require Web3Auth test account setup and API-based authentication
  // authenticatedPage: async ({ page, request }, use) => {
  //   const token = await getAuthToken(request, TEST_CREDENTIALS);
  //   await page.context().addCookies([
  //     { name: 'authToken', value: token, domain: 'localhost', path: '/' }
  //   ]);
  //   await cleanVault(request, token);
  //   await page.goto('/dashboard');
  //   await use(page);
  // },
});

/**
 * Re-export expect for convenience - import both test and expect from this file
 */
export { expect };
