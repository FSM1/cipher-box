import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for InvitePage landing page.
 *
 * Encapsulates the invite link recipient experience:
 * - Navigation to invite URL (HashRouter format)
 * - State detection (loading, valid, claiming, claimed, error)
 * - Auth area visibility
 * - Error card messages and home button
 *
 * Uses CSS class selectors matching the InvitePage component.
 */
export class InvitePageObject {
  constructor(private readonly page: Page) {}

  // ============================================
  // Navigation
  // ============================================

  /**
   * Navigate to an invite URL with token and ephemeral key.
   * URL format: http://localhost:5173/#/invite/TOKEN?key=KEY
   */
  async goto(token: string, ephemeralKeyHex: string): Promise<void> {
    const baseUrl = this.getBaseUrl();
    await this.page.goto(`${baseUrl}#/invite/${token}?key=${ephemeralKeyHex}`);
  }

  /**
   * Navigate to an invite URL without the ephemeral key (invalid URL test).
   */
  async gotoInvalidUrl(token: string): Promise<void> {
    const baseUrl = this.getBaseUrl();
    await this.page.goto(`${baseUrl}#/invite/${token}`);
  }

  /**
   * Derive the base URL from the current page, falling back to localhost:5173
   * for fresh contexts (about:blank).
   */
  private getBaseUrl(): string {
    const currentUrl = this.page.url();
    if (!currentUrl || currentUrl === 'about:blank') {
      return 'http://localhost:5173/';
    }
    return currentUrl.split('#')[0];
  }

  // ============================================
  // Card elements
  // ============================================

  /**
   * Get the invite card element.
   */
  card(): Locator {
    return this.page.locator('.invite-card');
  }

  /**
   * Get the error-styled invite card.
   */
  errorCard(): Locator {
    return this.page.locator('.invite-card--error');
  }

  /**
   * Get the CipherBox title heading.
   */
  title(): Locator {
    return this.page.locator('.invite-card__title');
  }

  /**
   * Get the main message text ("someone shared a file with you").
   */
  message(): Locator {
    return this.page.locator('.invite-card__message');
  }

  // ============================================
  // State detection
  // ============================================

  /**
   * Check if the page is in loading state.
   */
  async isLoading(): Promise<boolean> {
    return await this.page.locator('.invite-card__loading').isVisible();
  }

  /**
   * Check if the invite is valid (shows login CTA).
   */
  async isValid(): Promise<boolean> {
    return await this.page.locator('.invite-card__auth-area').isVisible();
  }

  /**
   * Check if the page is in claiming state.
   */
  async isClaiming(): Promise<boolean> {
    return await this.page.locator('.invite-card__claiming').isVisible();
  }

  /**
   * Check if the page is in error state.
   */
  async isError(): Promise<boolean> {
    return await this.page.locator('.invite-card--error').isVisible();
  }

  /**
   * Get the error message text.
   */
  async getErrorMessage(): Promise<string> {
    return (await this.page.locator('.invite-card__error').textContent()) ?? '';
  }

  // ============================================
  // Auth area
  // ============================================

  /**
   * Get the auth area element (login buttons rendered on invite page).
   */
  authArea(): Locator {
    return this.page.locator('.invite-card__auth-area');
  }

  /**
   * Check if the auth area (login buttons) is visible.
   */
  async isAuthAreaVisible(): Promise<boolean> {
    return await this.authArea().isVisible();
  }

  // ============================================
  // Home button (on error cards)
  // ============================================

  /**
   * Get the "[GO HOME]" button.
   */
  homeButton(): Locator {
    return this.page.locator('.invite-card__home-btn');
  }

  /**
   * Click the "[GO HOME]" button.
   */
  async clickHome(): Promise<void> {
    await this.homeButton().click();
  }

  // ============================================
  // Wait helpers
  // ============================================

  /**
   * Wait for the invite page to reach a valid state (auth area visible).
   */
  async waitForValidState(options?: { timeout?: number }): Promise<void> {
    await this.authArea().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the invite page to reach an error state.
   */
  async waitForErrorState(options?: { timeout?: number }): Promise<void> {
    await this.page.locator('.invite-card__error').waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the claiming state to appear.
   */
  async waitForClaimingState(options?: { timeout?: number }): Promise<void> {
    await this.page.locator('.invite-card__claiming').waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the claim to complete and redirect to /shared or /files.
   */
  async waitForClaimedRedirect(options?: { timeout?: number }): Promise<void> {
    const timeout = options?.timeout ?? 30000;
    await this.page.waitForURL(/(shared|files)/, { timeout });
  }
}
