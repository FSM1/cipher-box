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
    await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();
    await expect(authenticatedPage.locator('.user-info')).toBeVisible();

    // Reload the page
    await authenticatedPage.reload();

    // Wait for page to fully load
    await authenticatedPage.waitForLoadState('networkidle');

    // Verify we're still on dashboard (not redirected to login)
    await expect(authenticatedPage).toHaveURL(/.*dashboard/);
    await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();
    await expect(authenticatedPage.locator('.user-info')).toBeVisible();
  });

  authenticatedTest(
    'session persists when navigating between pages',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Navigate to settings
      await authenticatedPage.goto('/settings');
      await expect(authenticatedPage).toHaveURL(/.*settings/);
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Navigate back to dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage).toHaveURL(/.*dashboard/);
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Verify session remained valid throughout navigation
      await expect(authenticatedPage.locator('.user-info')).toBeVisible();
    }
  );

  authenticatedTest(
    'expired session redirects to login',
    async ({ authenticatedPage, context }) => {
      // Navigate to dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Clear all cookies to simulate expired session
      await context.clearCookies();

      // Also clear localStorage (Web3Auth session)
      await authenticatedPage.evaluate(() => {
        localStorage.clear();
      });

      // Reload page
      await authenticatedPage.reload();
      await authenticatedPage.waitForLoadState('networkidle');

      // Should be redirected to login page
      await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/, { timeout: 5000 });
      await expect(authenticatedPage.locator('button:has-text("[CONNECT]")')).toBeVisible();
    }
  );

  authenticatedTest(
    'browser back/forward maintains authentication',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Navigate to settings
      await authenticatedPage.goto('/settings');
      await expect(authenticatedPage).toHaveURL(/.*settings/);

      // Use browser back button
      await authenticatedPage.goBack();
      await expect(authenticatedPage).toHaveURL(/.*dashboard/);
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Use browser forward button
      await authenticatedPage.goForward();
      await expect(authenticatedPage).toHaveURL(/.*settings/);
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();
    }
  );

  authenticatedTest(
    'multiple tabs share authentication state',
    async ({ authenticatedPage, context }) => {
      // Navigate to dashboard in first tab
      await authenticatedPage.goto('/dashboard');
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Open a new tab
      const newPage = await context.newPage();
      await newPage.goto('/dashboard');

      // New tab should also be authenticated
      await expect(newPage).toHaveURL(/.*dashboard/);
      await expect(newPage.locator('button.logout-button')).toBeVisible();

      // Cleanup
      await newPage.close();
    }
  );
});
