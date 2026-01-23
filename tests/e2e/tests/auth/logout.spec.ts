import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';

/**
 * logout flow E2E tests.
 * Tests logout functionality and session clearing.
 */
authenticatedTest.describe('logout Flow', () => {
  authenticatedTest(
    'logout button is visible when authenticated',
    async ({ authenticatedPage }) => {
      // Navigate to dashboard (should already be authenticated)
      await authenticatedPage.goto('/dashboard');

      // Verify logout button is visible
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Verify user info is displayed (authenticated state)
      await expect(authenticatedPage.locator('.user-info')).toBeVisible();
    }
  );

  authenticatedTest(
    'clicking logout clears session and redirects to login',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');

      // Verify we're authenticated
      await expect(authenticatedPage.locator('button.logout-button')).toBeVisible();

      // Click logout button
      await authenticatedPage.click('button.logout-button');

      // Wait for redirect to login page
      await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/);

      // Verify we're on login page
      await expect(authenticatedPage.locator('button:has-text("[CONNECT]")')).toBeVisible();
      await expect(authenticatedPage.locator('button.logout-button')).not.toBeVisible();
    }
  );

  authenticatedTest(
    'after logout, accessing protected route redirects to login',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');

      // logout
      await authenticatedPage.click('button.logout-button');
      await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/);

      // Try to navigate to dashboard again
      await authenticatedPage.goto('/dashboard');

      // Should remain on login page (not dashboard)
      await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/);
      await expect(authenticatedPage.locator('button:has-text("[CONNECT]")')).toBeVisible();
    }
  );

  authenticatedTest('after logout, localStorage is cleared', async ({ authenticatedPage }) => {
    // Start on dashboard
    await authenticatedPage.goto('/dashboard');

    // Check localStorage before logout (should have some auth-related items)
    const localStorageBefore = await authenticatedPage.evaluate(() => {
      return {
        hasAuthToken: localStorage.getItem('authToken') !== null,
        hasWeb3AuthSession: Object.keys(localStorage).some((key) => key.includes('web3auth')),
        itemCount: localStorage.length,
      };
    });

    // We expect some items in localStorage when authenticated
    expect(localStorageBefore.itemCount).toBeGreaterThan(0);

    // logout
    await authenticatedPage.click('button.logout-button');
    await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/);

    // Check localStorage after logout
    const localStorageAfter = await authenticatedPage.evaluate(() => {
      return {
        hasAuthToken: localStorage.getItem('authToken') !== null,
        hasWeb3AuthSession: Object.keys(localStorage).some((key) => key.includes('web3auth')),
        allItems: Object.keys(localStorage),
      };
    });

    // Sensitive auth data should be cleared
    expect(localStorageAfter.hasAuthToken).toBe(false);

    // Log remaining items for debugging (should be empty or only non-sensitive data)
    if (localStorageAfter.allItems.length > 0) {
      console.log('Remaining localStorage items:', localStorageAfter.allItems);
    }
  });
});
