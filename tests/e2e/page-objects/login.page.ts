import { BasePage } from './base.page';

/**
 * Login page object for authentication flows.
 * Handles navigation to login and Web3Auth modal interaction.
 */
export class LoginPage extends BasePage {
  /**
   * Locator for the login button on the homepage
   * Uses class selector for stability (text varies: [CONNECT] or connecting...)
   */
  private get loginButton() {
    return this.page.locator('button.login-button');
  }

  /**
   * Navigate to the homepage
   */
  async goto(): Promise<void> {
    await super.goto('/');
  }

  /**
   * Click the login button to open Web3Auth modal
   */
  async clickLogin(): Promise<void> {
    await this.loginButton.click();
  }

  // TODO: Web3Auth modal interaction is complex with iframe handling
  // For now, we'll handle authentication programmatically via API in fixtures
  // Future enhancement: Add methods for Web3Auth modal interaction
  // - waitForWeb3AuthModal()
  // - loginWithEmail(email: string)
  // - loginWithWallet(provider: string)
}
