import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for ConfirmDialog component.
 *
 * Used for confirming destructive actions like file/folder deletion.
 * Encapsulates dialog visibility, content, and button interactions.
 */
export class ConfirmDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * ConfirmDialog renders inside a Modal component.
   */
  dialog(): Locator {
    return this.page.locator('.dialog-content').filter({
      has: this.page.locator('.dialog-message'),
    });
  }

  /**
   * Get the dialog title.
   */
  title(): Locator {
    // Modal component has the title in its header
    return this.page.locator('.modal-title');
  }

  /**
   * Get the dialog message/body text.
   */
  message(): Locator {
    return this.page.locator('.dialog-message');
  }

  /**
   * Get the confirm button (primary/destructive action).
   */
  confirmButton(): Locator {
    return this.page.locator('.dialog-button--destructive, .dialog-button--primary').first();
  }

  /**
   * Get the cancel button.
   */
  cancelButton(): Locator {
    return this.page.locator('.dialog-button--secondary', { hasText: 'Cancel' });
  }

  /**
   * Check if the dialog is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.dialog().isVisible();
  }

  /**
   * Wait for the dialog to open.
   */
  async waitForOpen(options?: { timeout?: number }): Promise<void> {
    await this.dialog().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the dialog to close.
   */
  async waitForClose(options?: { timeout?: number }): Promise<void> {
    await this.dialog().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Get the dialog title text.
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }

  /**
   * Get the dialog message text.
   */
  async getMessage(): Promise<string> {
    return (await this.message().textContent()) ?? '';
  }

  /**
   * Click the confirm button.
   */
  async clickConfirm(): Promise<void> {
    await this.confirmButton().click();
  }

  /**
   * Click the cancel button.
   */
  async clickCancel(): Promise<void> {
    await this.cancelButton().click();
  }

  /**
   * Check if the dialog is in loading state.
   * Loading state disables buttons and may show "Deleting..." text.
   */
  async isLoading(): Promise<boolean> {
    const confirmText = await this.confirmButton().textContent();
    return confirmText?.includes('...') ?? false;
  }

  /**
   * Get the confirm button label.
   * Returns "Delete", "Deleting...", or other action text.
   */
  async getConfirmLabel(): Promise<string> {
    return (await this.confirmButton().textContent()) ?? '';
  }
}
