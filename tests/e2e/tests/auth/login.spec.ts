import { test, expect } from '@playwright/test';
import { waitForWeb3AuthModal, loginViaEmail } from '../../utils/web3auth-helpers';

/**
 * Login flow E2E tests.
 * Tests the complete authentication journey via Web3Auth.
 */
test.describe('Login Flow', () => {
  test('shows login page for unauthenticated users', async ({ page }) => {
    // Navigate to root
    await page.goto('/');

    // Verify login page is displayed
    await expect(page.locator('h1:has-text("CipherBox")')).toBeVisible();
    await expect(page.locator('text=Zero-knowledge encrypted cloud storage')).toBeVisible();
    await expect(page.locator('button:has-text("Sign In")')).toBeVisible();

    // Verify user is not authenticated (no logout button)
    await expect(page.locator('button:has-text("Logout")')).not.toBeVisible();
  });

  test('clicking login opens Web3Auth modal', async ({ page }) => {
    // Navigate to login page
    await page.goto('/');

    // Click the Sign In button
    await page.click('button:has-text("Sign In")');

    // Wait for Web3Auth modal to appear
    try {
      const modal = await waitForWeb3AuthModal(page);

      // Verify modal content is visible
      // Web3Auth modal should have login options
      const modalContent = modal.locator('*').first();
      await expect(modalContent).toBeVisible();

      // Close modal by pressing Escape to clean up
      await page.keyboard.press('Escape');
    } catch (error) {
      // If Web3Auth modal doesn't appear, it might be a configuration issue
      console.error('Web3Auth modal did not appear:', error);
      throw error;
    }
  });

  // This test requires manual OTP verification and should be skipped in CI
  test('redirects to dashboard after successful login', async ({ page }) => {
    test.skip(!!process.env.CI, 'Requires manual OTP entry, skip in CI');

    const testEmail = process.env.WEB3AUTH_TEST_EMAIL || 'test@example.com';

    // Perform full login flow
    await page.goto('/');
    await loginViaEmail(page, testEmail);

    // Verify we're on the dashboard
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('button:has-text("Logout")')).toBeVisible();

    // Note: This test requires manual OTP entry during execution
    // For CI, use storage state or API-based auth instead
  });

  test('redirects unauthenticated users from protected routes to login', async ({ page }) => {
    // Try to navigate directly to dashboard without authentication
    await page.goto('/dashboard');

    // Should be redirected to login page
    // Dashboard checks authentication and redirects if not authenticated
    await page.waitForURL(/^(?!.*dashboard).*$/); // Wait for URL to not contain 'dashboard'

    // Verify we're back on login page
    await expect(page.locator('button:has-text("Sign In")')).toBeVisible();
    await expect(page.locator('text=Zero-knowledge encrypted cloud storage')).toBeVisible();
  });

  test('redirects unauthenticated users from settings to login', async ({ page }) => {
    // Try to navigate to settings without authentication
    await page.goto('/settings');

    // Should be redirected to login page
    await page.waitForURL(/^(?!.*settings).*$/);

    // Verify we're on login page
    await expect(page.locator('button:has-text("Sign In")')).toBeVisible();
  });
});
