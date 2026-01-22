import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';

/**
 * Session persistence E2E tests.
 * Tests that authenticated session persists across page reloads and navigation.
 */
authenticatedTest.describe('Session Persistence', () => {
  authenticatedTest('session persists after page reload', async ({ authenticatedPage }) => {
    // Navigate to dashboard
    await authenticatedPage.goto('/dashboard');

    // Verify we're authenticated
    await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();
    await expect(authenticatedPage.locator('.user-info')).toBeVisible();

    // Reload the page
    await authenticatedPage.reload();

    // Wait for page to fully load
    await authenticatedPage.waitForLoadState('networkidle');

    // Verify we're still on dashboard (not redirected to login)
    await expect(authenticatedPage).toHaveURL(/.*dashboard/);
    await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();
    await expect(authenticatedPage.locator('.user-info')).toBeVisible();
  });

  authenticatedTest(
    'session persists when navigating between pages',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

      // Navigate to settings
      await authenticatedPage.goto('/settings');
      await expect(authenticatedPage).toHaveURL(/.*settings/);
      // Settings page doesn't have Logout button, verify we see the "Back to Dashboard" button
      await expect(authenticatedPage.locator('button:has-text("Back to Dashboard")')).toBeVisible();

      // Navigate back to dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage).toHaveURL(/.*dashboard/);
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

      // Verify session remained valid throughout navigation
      await expect(authenticatedPage.locator('.user-info')).toBeVisible();
    }
  );

  authenticatedTest('expired session redirects to login', async ({ authenticatedPage }) => {
    // Navigate to dashboard
    await authenticatedPage.goto('/dashboard');
    await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

    // Clear all cookies to simulate expired session
    await authenticatedPage.context().clearCookies();

    // Also clear localStorage and sessionStorage
    await authenticatedPage.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });

    // Reload page
    await authenticatedPage.reload();
    await authenticatedPage.waitForLoadState('networkidle');

    // Should be redirected to login page
    await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/, { timeout: 10000 });
    await expect(authenticatedPage.locator('button:has-text("Sign In")')).toBeVisible({
      timeout: 10000,
    });
  });

  authenticatedTest(
    'browser back/forward maintains authentication',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

      // Navigate to settings
      await authenticatedPage.goto('/settings');
      await expect(authenticatedPage).toHaveURL(/.*settings/);

      // Use browser back button
      await authenticatedPage.goBack();
      await expect(authenticatedPage).toHaveURL(/.*dashboard/);
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

      // Use browser forward button
      await authenticatedPage.goForward();
      await expect(authenticatedPage).toHaveURL(/.*settings/);
      // Settings page has "Back to Dashboard" button instead of Logout
      await expect(authenticatedPage.locator('button:has-text("Back to Dashboard")')).toBeVisible();
    }
  );

  authenticatedTest(
    'multiple tabs share authentication state',
    async ({ authenticatedPage, context }) => {
      // Navigate to dashboard in first tab
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

      // Verify cookies are accessible (they're shared across tabs in same context)
      const cookies = await context.cookies();
      const refreshTokenCookie = cookies.find((c) => c.name === 'refresh_token');
      expect(refreshTokenCookie).toBeDefined();

      // Get the current cached token from the first tab to pass to new tab
      const cachedToken = await authenticatedPage.evaluate(() => {
        return sessionStorage.getItem('__e2e_cached_token__');
      });

      // Open a new tab and inject the cached access token
      // This simulates what would happen if the user opened a new tab
      // (cookies are shared, but sessionStorage is not)
      const newPage = await context.newPage();

      // Use addInitScript with explicit token injection
      await newPage.addInitScript(`
        sessionStorage.setItem('__e2e_test_mode__', 'true');
        sessionStorage.setItem('__e2e_cached_token__', '${cachedToken || ''}');
      `);

      await newPage.goto('/dashboard');

      // New tab should also be authenticated (using cached token)
      await expect(newPage).toHaveURL(/.*dashboard/);
      await expect(newPage.locator('button:has-text("Logout")')).toBeVisible({ timeout: 20000 });

      // Cleanup
      await newPage.close();
    }
  );
});
