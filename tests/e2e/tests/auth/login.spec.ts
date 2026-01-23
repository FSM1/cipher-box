import { test, expect } from '@playwright/test';
import {
  waitForWeb3AuthModal,
  loginViaEmail,
  TEST_CREDENTIALS,
} from '../../utils/web3auth-helpers';

/**
 * Login flow E2E tests.
 * Tests the complete authentication journey via Web3Auth.
 *
 * These tests need fresh browser context without any stored authentication,
 * so we override the storageState from playwright.config.ts
 */
test.describe('Login Flow', () => {
  // Don't use stored authentication for login flow tests - start fresh
  test.use({ storageState: { cookies: [], origins: [] } });
  test('shows login page for unauthenticated users', async ({ page }) => {
    // Navigate to root
    await page.goto('/');

    // Verify login page is displayed
    await expect(page.locator('h1:has-text("CIPHERBOX")')).toBeVisible();
    await expect(page.locator('text=zero-knowledge encrypted storage')).toBeVisible();
    await expect(page.locator('button.auth-button')).toBeVisible();

    // Verify user is not authenticated (no logout button)
    await expect(page.locator('button.logout-button')).not.toBeVisible();
  });

  test('clicking login opens Web3Auth modal', async ({ page }) => {
    // Navigate to login page
    await page.goto('/');

    // Click the [CONNECT] button
    await page.click('button.auth-button');

    // Wait for Web3Auth modal to appear
    try {
      const { locator: modal } = await waitForWeb3AuthModal(page);

      // Verify modal content is visible - look for email login option
      const emailButton = modal.locator(
        'button:has-text("Continue with Email"), button:has-text("Email")'
      );
      await expect(emailButton.first()).toBeVisible();

      // Close modal by pressing Escape or clicking outside
      await page.keyboard.press('Escape');
    } catch (error) {
      // If Web3Auth modal doesn't appear, it might be a configuration issue
      console.error('Web3Auth modal did not appear:', error);
      throw error;
    }
  });

  // This test uses Web3Auth test credentials with static OTP for automated login
  test('redirects to dashboard after successful login', async ({ page }) => {
    // Skip if test credentials are not configured
    test.skip(
      !TEST_CREDENTIALS.email || !TEST_CREDENTIALS.otp,
      'Web3Auth test credentials not configured (WEB3AUTH_TEST_EMAIL, WEB3AUTH_TEST_OTP)'
    );

    // Perform full login flow with test credentials
    await page.goto('/');
    await loginViaEmail(page, TEST_CREDENTIALS.email, TEST_CREDENTIALS.otp);

    // Verify we're on the dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('button.logout-button')).toBeVisible();
  });

  test('redirects unauthenticated users from protected routes to login', async ({ page }) => {
    // Try to navigate directly to dashboard without authentication
    await page.goto('/dashboard');

    // Should be redirected to login page
    // Dashboard checks authentication and redirects if not authenticated
    await page.waitForURL(/^(?!.*dashboard).*$/); // Wait for URL to not contain 'dashboard'

    // Verify we're back on login page
    await expect(page.locator('button.auth-button')).toBeVisible();
    await expect(page.locator('text=zero-knowledge encrypted storage')).toBeVisible();
  });

  test('redirects unauthenticated users from settings to login', async ({ page }) => {
    // Try to navigate to settings without authentication
    await page.goto('/settings');

    // Should be redirected to login page
    await page.waitForURL(/^(?!.*settings).*$/);

    // Verify we're on login page
    await expect(page.locator('button.auth-button')).toBeVisible();
  });
});
