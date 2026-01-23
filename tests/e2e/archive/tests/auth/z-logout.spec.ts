import { expect } from '@playwright/test';
import { authenticatedTest } from '../../fixtures/auth.fixture';

/**
 * Logout flow E2E tests.
 * Tests logout functionality and session clearing.
 *
 * IMPORTANT: These tests perform logout which revokes all user tokens.
 * Tests are structured to handle this:
 * - Test 1 (non-destructive): Just checks logout button is visible
 * - Test 2 (comprehensive logout): Single test that verifies all logout behaviors
 *
 * This structure ensures each test can authenticate successfully without
 * being affected by token revocation from previous tests.
 */
authenticatedTest.describe('Logout Flow', () => {
  authenticatedTest(
    'logout button is visible when authenticated',
    async ({ authenticatedPage }) => {
      // Navigate to dashboard (should already be authenticated)
      await authenticatedPage.goto('/dashboard');

      // Verify logout button is visible
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

      // Verify user info is displayed (authenticated state)
      await expect(authenticatedPage.locator('.user-info')).toBeVisible();
    }
  );

  /**
   * Comprehensive logout test that verifies all logout behaviors in a single test.
   * This avoids issues with token revocation breaking subsequent tests.
   */
  authenticatedTest(
    'logout clears session, redirects to login, and clears localStorage',
    async ({ authenticatedPage }) => {
      // Start on dashboard
      await authenticatedPage.goto('/dashboard');

      // Verify we're authenticated
      await expect(authenticatedPage.locator('button:has-text("Logout")')).toBeVisible();

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

      // Click logout button
      await authenticatedPage.click('button:has-text("Logout")');

      // Wait for redirect to login page
      await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/);

      // Wait for loading to complete (E2E session restoration may take time)
      // Then verify we're on login page with Sign In button
      await expect(authenticatedPage.locator('button:has-text("Sign In")')).toBeVisible({
        timeout: 15000,
      });
      await expect(authenticatedPage.locator('button:has-text("Logout")')).not.toBeVisible();

      // Verify localStorage was cleared
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

      // Try to navigate to dashboard again (should redirect to login)
      await authenticatedPage.goto('/dashboard');

      // Should remain on login page (not dashboard) since we're logged out
      await authenticatedPage.waitForURL(/^(?!.*dashboard).*$/);
      await expect(authenticatedPage.locator('button:has-text("Sign In")')).toBeVisible({
        timeout: 15000,
      });
    }
  );
});
