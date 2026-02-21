import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for ShareDialog component interactions.
 *
 * Encapsulates sharing actions: enter recipient key, submit, view recipients, revoke.
 * Uses CSS class selectors matching the ShareDialog component.
 */
export class ShareDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the share dialog modal (identified by title starting with "SHARE:").
   */
  dialog(): Locator {
    return this.page.locator('.modal-overlay .modal-content', { hasText: /SHARE:/ });
  }

  /**
   * Get the public key input field.
   */
  pubKeyInput(): Locator {
    return this.page.locator('#share-pubkey-input');
  }

  /**
   * Get the share submit button ("--share").
   */
  submitButton(): Locator {
    return this.page.locator('.share-submit-btn');
  }

  /**
   * Get the error message element.
   */
  errorMessage(): Locator {
    return this.page.locator('.share-error[role="alert"]');
  }

  /**
   * Get the success message element.
   */
  successMessage(): Locator {
    return this.page.locator('.share-success[role="status"]');
  }

  /**
   * Get the progress indicator (shown during folder sharing key re-wrapping).
   */
  progressIndicator(): Locator {
    return this.page.locator('.share-progress[role="status"]');
  }

  /**
   * Get the recipients list container.
   */
  recipientsList(): Locator {
    return this.page.locator('.share-recipients-list');
  }

  /**
   * Get all recipient row elements.
   */
  recipientRows(): Locator {
    return this.page.locator('.share-recipient');
  }

  /**
   * Get a specific recipient row by its truncated key text.
   */
  recipientRow(truncatedKey: string): Locator {
    return this.page.locator('.share-recipient', { hasText: truncatedKey });
  }

  /**
   * Get the "no recipients yet" empty state.
   */
  recipientsEmpty(): Locator {
    return this.page.locator('.share-recipients-empty');
  }

  /**
   * Get the recipients loading indicator.
   */
  recipientsLoading(): Locator {
    return this.page.locator('.share-recipients-loading');
  }

  /**
   * Wait for the share dialog to be visible.
   */
  async waitForOpen(options?: { timeout?: number }): Promise<void> {
    await this.dialog().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the share dialog to close.
   */
  async waitForClose(options?: { timeout?: number }): Promise<void> {
    await this.dialog().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Check if the dialog is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.dialog().isVisible();
  }

  /**
   * Enter a public key into the input field and submit the share.
   * Waits for the success or error message to appear.
   */
  async shareWithKey(publicKey: string): Promise<void> {
    await this.pubKeyInput().fill(publicKey);
    await this.submitButton().click();
  }

  /**
   * Wait for success message to appear after sharing.
   */
  async waitForSuccess(options?: { timeout?: number }): Promise<string> {
    await this.successMessage().waitFor({ state: 'visible', ...options });
    return (await this.successMessage().textContent()) ?? '';
  }

  /**
   * Wait for error message to appear.
   */
  async waitForError(options?: { timeout?: number }): Promise<string> {
    await this.errorMessage().waitFor({ state: 'visible', ...options });
    return (await this.errorMessage().textContent()) ?? '';
  }

  /**
   * Wait for progress indicator to appear and then disappear (folder sharing complete).
   */
  async waitForProgressComplete(options?: { timeout?: number }): Promise<void> {
    // Wait for progress to appear first
    await this.progressIndicator().waitFor({ state: 'visible', timeout: 10000 });
    // Then wait for it to disappear (sharing complete)
    await this.progressIndicator().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Get the number of current recipients.
   */
  async getRecipientCount(): Promise<number> {
    return await this.recipientRows().count();
  }

  /**
   * Get all recipient truncated keys.
   */
  async getRecipientKeys(): Promise<string[]> {
    const rows = this.recipientRows();
    const count = await rows.count();
    const keys: string[] = [];
    for (let i = 0; i < count; i++) {
      const keyText = await rows.nth(i).locator('.share-recipient-key').textContent();
      if (keyText) keys.push(keyText.trim());
    }
    return keys;
  }

  /**
   * Click the revoke button for a specific recipient (by truncated key).
   */
  async clickRevoke(truncatedKey: string): Promise<void> {
    const row = this.recipientRow(truncatedKey);
    await row.locator('.share-revoke-btn').click();
  }

  /**
   * Confirm the revoke action (click [y] in the confirmation).
   */
  async confirmRevoke(truncatedKey: string): Promise<void> {
    const row = this.recipientRow(truncatedKey);
    await row.locator('.share-revoke-confirm-btn--yes').click();
  }

  /**
   * Cancel the revoke action (click [n] in the confirmation).
   */
  async cancelRevoke(truncatedKey: string): Promise<void> {
    const row = this.recipientRow(truncatedKey);
    await row.locator('.share-revoke-confirm-btn--no').click();
  }

  /**
   * Revoke a recipient: click revoke, then confirm.
   * Waits for the recipient to disappear from the list.
   */
  async revokeRecipient(truncatedKey: string): Promise<void> {
    await this.clickRevoke(truncatedKey);
    await this.confirmRevoke(truncatedKey);
    // Wait for the recipient row to disappear
    await this.recipientRow(truncatedKey).waitFor({ state: 'hidden', timeout: 10000 });
  }

  /**
   * Wait for recipients to finish loading.
   */
  async waitForRecipientsLoaded(): Promise<void> {
    // Wait for loading state to disappear
    await this.recipientsLoading()
      .waitFor({ state: 'hidden', timeout: 10000 })
      .catch(() => {
        // Loading may have already finished
      });
  }

  /**
   * Close the dialog by pressing Escape.
   */
  async close(): Promise<void> {
    await this.page.keyboard.press('Escape');
    await this.waitForClose();
  }
}
