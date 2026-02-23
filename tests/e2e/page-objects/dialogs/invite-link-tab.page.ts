import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for InviteLinkTab component inside ShareDialog.
 *
 * Encapsulates invite link actions: tab switching, create link,
 * clipboard intercept, invite list management, revoke.
 * Uses CSS class selectors matching the InviteLinkTab and ShareDialog components.
 */
export class InviteLinkTabPage {
  constructor(private readonly page: Page) {}

  // ============================================
  // Tab navigation (on the ShareDialog tab bar)
  // ============================================

  /**
   * Get the "DIRECT SHARE" tab button.
   */
  directShareTab(): Locator {
    return this.page.locator('.share-tab', { hasText: 'DIRECT SHARE' });
  }

  /**
   * Get the "INVITE LINK" tab button.
   */
  inviteLinkTab(): Locator {
    return this.page.locator('.share-tab', { hasText: 'INVITE LINK' });
  }

  /**
   * Switch to the Invite Link tab.
   */
  async switchToInviteTab(): Promise<void> {
    await this.inviteLinkTab().click();
  }

  /**
   * Switch to the Direct Share tab.
   */
  async switchToDirectTab(): Promise<void> {
    await this.directShareTab().click();
  }

  /**
   * Check if the Invite Link tab is currently active.
   */
  async isInviteTabActive(): Promise<boolean> {
    const cls = (await this.inviteLinkTab().getAttribute('class')) ?? '';
    return cls.includes('share-tab--active');
  }

  /**
   * Check if the Direct Share tab is currently active.
   */
  async isDirectTabActive(): Promise<boolean> {
    const cls = (await this.directShareTab().getAttribute('class')) ?? '';
    return cls.includes('share-tab--active');
  }

  // ============================================
  // Invite creation
  // ============================================

  /**
   * Get the "create invite link" button.
   */
  createButton(): Locator {
    return this.page.locator('.invite-link-create-btn');
  }

  /**
   * Click the create invite link button.
   */
  async clickCreate(): Promise<void> {
    await this.createButton().click();
  }

  /**
   * Get the success message element.
   */
  successMessage(): Locator {
    return this.page.locator('.invite-link-tab .share-success[role="status"]');
  }

  /**
   * Get the error message element.
   */
  errorMessage(): Locator {
    return this.page.locator('.invite-link-tab .share-error[role="alert"]');
  }

  /**
   * Wait for the success message and return its text.
   */
  async waitForSuccess(options?: { timeout?: number }): Promise<string> {
    await this.successMessage().waitFor({ state: 'visible', ...options });
    return (await this.successMessage().textContent()) ?? '';
  }

  /**
   * Wait for the error message and return its text.
   */
  async waitForError(options?: { timeout?: number }): Promise<string> {
    await this.errorMessage().waitFor({ state: 'visible', ...options });
    return (await this.errorMessage().textContent()) ?? '';
  }

  // ============================================
  // Active invites list
  // ============================================

  /**
   * Get all invite list items.
   */
  inviteItems(): Locator {
    return this.page.locator('.invite-link-item');
  }

  /**
   * Get the number of active invites.
   */
  async getInviteCount(): Promise<number> {
    return await this.inviteItems().count();
  }

  /**
   * Get a specific invite item by index.
   */
  inviteItem(index: number): Locator {
    return this.inviteItems().nth(index);
  }

  /**
   * Get the empty state element ("no active invite links").
   */
  emptyState(): Locator {
    return this.page.locator('.invite-link-tab .share-recipients-empty');
  }

  /**
   * Get the loading state element.
   */
  loadingState(): Locator {
    return this.page.locator('.invite-link-tab .share-recipients-loading');
  }

  /**
   * Wait for the invite list to finish loading.
   */
  async waitForLoaded(): Promise<void> {
    // Wait for either items, empty state, or ensure loading disappears
    await this.page
      .locator(
        '.invite-link-item, .invite-link-tab .share-recipients-empty, .invite-link-tab .share-error'
      )
      .first()
      .waitFor({ state: 'visible', timeout: 10000 });
  }

  // ============================================
  // Revoke actions (inline confirm pattern)
  // ============================================

  /**
   * Click the revoke button on a specific invite item.
   */
  async clickRevoke(index: number): Promise<void> {
    await this.inviteItem(index).locator('.share-revoke-btn').click();
  }

  /**
   * Confirm the revoke action on a specific invite item.
   */
  async confirmRevoke(index: number): Promise<void> {
    await this.inviteItem(index).locator('.share-revoke-confirm-btn--yes').click();
  }

  /**
   * Cancel the revoke action on a specific invite item.
   */
  async cancelRevoke(index: number): Promise<void> {
    await this.inviteItem(index).locator('.share-revoke-confirm-btn--no').click();
  }

  /**
   * Revoke an invite: click revoke, confirm, wait for item to disappear.
   */
  async revokeInvite(index: number): Promise<void> {
    // Capture the item reference before revoking
    const itemCount = await this.getInviteCount();
    await this.clickRevoke(index);
    await this.confirmRevoke(index);
    // Wait for item count to decrease
    await this.page.waitForFunction(
      (expected) => document.querySelectorAll('.invite-link-item').length < expected,
      itemCount,
      { timeout: 10000 }
    );
  }

  // ============================================
  // Clipboard capture
  // ============================================

  /**
   * Intercept navigator.clipboard.writeText to capture copied content.
   * Must be called BEFORE the action that copies to clipboard.
   */
  async interceptClipboard(): Promise<void> {
    await this.page.evaluate(() => {
      (window as unknown as Record<string, string>).__clipboardContent = '';
      const original = navigator.clipboard.writeText.bind(navigator.clipboard);
      navigator.clipboard.writeText = async (text: string) => {
        (window as unknown as Record<string, string>).__clipboardContent = text;
        return original(text);
      };
    });
  }

  /**
   * Read the last content written to clipboard via the intercepted writeText.
   */
  async getClipboardContent(): Promise<string> {
    return this.page.evaluate(
      () => (window as unknown as Record<string, string>).__clipboardContent ?? ''
    );
  }
}
