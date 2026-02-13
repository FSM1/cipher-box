import { BasePage } from './base.page';

/**
 * Login page object for CipherBox authentication flows.
 * With Core Kit (Phase 12), login is through CipherBox's own UI:
 * - Email + OTP form (two-step)
 * - Google OAuth button
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
}
