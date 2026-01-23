import { test, expect } from '../fixtures';

/**
 * Smoke test to verify the E2E testing infrastructure is working correctly.
 * Tests basic page load and interaction capabilities.
 */
test.describe('Smoke Test', () => {
  test('homepage loads and shows login button', async ({ page, loginPage }) => {
    // Navigate to the homepage
    await loginPage.goto();

    // Verify the page loads successfully
    await expect(page).toHaveURL('/');

    // Verify the page title contains expected text
    await expect(page).toHaveTitle(/CipherBox|Cipher/i);

    // Verify the login button is visible
    // Use class selector as button text might vary (connecting... vs [CONNECT])
    const loginButton = page.locator('button.auth-button');
    await expect(loginButton).toBeVisible();

    // Verify button text is either [CONNECT] or connecting...
    const buttonText = await loginButton.textContent();
    expect(buttonText).toMatch(/\[CONNECT\]|connecting\.\.\./i);
  });
});
