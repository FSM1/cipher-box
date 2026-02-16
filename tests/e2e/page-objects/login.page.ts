import { BasePage } from './base.page';

/**
 * Login page object for CipherBox authentication flows.
 * With Core Kit (Phase 12), login is through CipherBox's own UI:
 * - Email + OTP form (two-step)
 * - Google OAuth button
 * - Wallet login via EIP-6963 connectors (Phase 12.5)
 *
 * No more Web3Auth modal/iframe interaction needed.
 */
export class LoginPage extends BasePage {
  // Email step selectors
  private get emailInput() {
    return this.page.locator('[data-testid="email-input"]');
  }

  private get sendOtpButton() {
    return this.page.locator('[data-testid="send-otp-button"]');
  }

  // OTP step selectors
  private get otpInput() {
    return this.page.locator('[data-testid="otp-input"]');
  }

  private get verifyButton() {
    return this.page.locator('[data-testid="verify-button"]');
  }

  // Google login
  private get googleLoginButton() {
    return this.page.locator('[data-testid="google-login-button"]');
  }

  // Wallet login selectors
  private get walletLoginButton() {
    return this.page.locator('[data-testid="wallet-login-button"]');
  }

  private get walletConnectorList() {
    return this.page.locator('.wallet-connector-list');
  }

  private get walletConnectorCancel() {
    return this.page.locator('.wallet-connector-cancel');
  }

  private get walletNoProviders() {
    return this.page.locator('.wallet-no-providers');
  }

  private get walletLoginStatus() {
    return this.page.locator('.wallet-login-status');
  }

  private get walletError() {
    return this.page.locator('.wallet-login-wrapper .login-error');
  }

  /**
   * Navigate to the login page
   */
  async goto(): Promise<void> {
    await super.goto('/');
  }

  /**
   * Enter email address and submit to request OTP
   */
  async enterEmail(email: string): Promise<void> {
    await this.emailInput.waitFor({ state: 'visible', timeout: 10000 });
    await this.emailInput.fill(email);
    await this.sendOtpButton.click();
  }

  /**
   * Enter OTP code and submit to verify
   */
  async enterOtp(otp: string): Promise<void> {
    await this.otpInput.waitFor({ state: 'visible', timeout: 10000 });
    await this.otpInput.fill(otp);
    await this.verifyButton.click();
  }

  /**
   * Full email + OTP login flow
   */
  async loginWithEmail(email: string, otp: string): Promise<void> {
    await this.enterEmail(email);
    await this.enterOtp(otp);
    // Wait for redirect to files page
    await this.page.waitForURL('**/files', { timeout: 60000 });
  }

  /**
   * Click Google login button (requires VITE_GOOGLE_CLIENT_ID to be configured)
   */
  async clickGoogleLogin(): Promise<void> {
    await this.googleLoginButton.click();
  }

  /**
   * Check if Google login button is available (not in "not configured" state)
   */
  async isGoogleLoginAvailable(): Promise<boolean> {
    const text = await this.googleLoginButton.textContent();
    return text !== null && !text.includes('NOT CONFIGURED');
  }

  // ============================
  // Wallet login methods
  // ============================

  /**
   * Click the [WALLET] login button to show connector list
   */
  async clickWalletLogin(): Promise<void> {
    await this.walletLoginButton.waitFor({ state: 'visible', timeout: 10000 });
    await this.walletLoginButton.click();
  }

  /**
   * Get list of wallet connector names visible in the connector list
   */
  async getWalletConnectors(): Promise<string[]> {
    await this.walletConnectorList.waitFor({ state: 'visible', timeout: 5000 });
    const options = this.page.locator('.wallet-connector-option');
    const count = await options.count();
    const names: string[] = [];
    for (let i = 0; i < count; i++) {
      const text = await options.nth(i).textContent();
      if (text) names.push(text.replace(/^\[|\]$/g, '').trim());
    }
    return names;
  }

  /**
   * Select a specific wallet connector by matching its display name
   */
  async selectWalletConnector(name: string): Promise<void> {
    await this.walletConnectorList.waitFor({ state: 'visible', timeout: 5000 });
    const option = this.page.locator('.wallet-connector-option', { hasText: name });
    await option.click();
  }

  /**
   * Click the cancel button in the connector list
   */
  async cancelWalletLogin(): Promise<void> {
    await this.walletConnectorCancel.click();
  }

  /**
   * Get wallet error text if visible, null otherwise
   */
  async getWalletError(): Promise<string | null> {
    const isVisible = await this.walletError.isVisible().catch(() => false);
    if (!isVisible) return null;
    return await this.walletError.textContent();
  }

  /**
   * Check if the wallet connector list is currently shown
   */
  async isWalletConnectorListVisible(): Promise<boolean> {
    return await this.walletConnectorList.isVisible().catch(() => false);
  }

  /**
   * Get wallet status text (e.g., "connecting wallet...", "sign the message...")
   */
  async getWalletStatus(): Promise<string | null> {
    const isVisible = await this.walletLoginStatus.isVisible().catch(() => false);
    if (!isVisible) return null;
    return await this.walletLoginStatus.textContent();
  }

  /**
   * Check if the wallet login button is visible
   */
  async isWalletLoginButtonVisible(): Promise<boolean> {
    return await this.walletLoginButton.isVisible().catch(() => false);
  }

  /**
   * Check if the wallet login button is enabled (not disabled)
   */
  async isWalletLoginButtonEnabled(): Promise<boolean> {
    return await this.walletLoginButton.isEnabled().catch(() => false);
  }

  /**
   * Check if no-wallet-providers message is shown
   */
  async isNoWalletProvidersVisible(): Promise<boolean> {
    return await this.walletNoProviders.isVisible().catch(() => false);
  }
}
