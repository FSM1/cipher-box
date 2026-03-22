import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for TextEditorDialog component.
 *
 * Encapsulates the text editor modal: loading state, textarea editing,
 * status line, save/cancel buttons, and error display.
 */
export class TextEditorDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * TextEditorDialog renders inside a Modal with .text-editor-modal class.
   */
  dialog(): Locator {
    return this.page.locator('.text-editor-modal .modal-container');
  }

  /**
   * Get the dialog title.
   */
  title(): Locator {
    return this.dialog().locator('.modal-title');
  }

  /**
   * Get the close button (X).
   */
  closeButton(): Locator {
    return this.dialog().locator('.modal-close');
  }

  /**
   * Get the loading indicator.
   */
  loadingIndicator(): Locator {
    return this.dialog().locator('.text-editor-loading');
  }

  /**
   * Get the textarea element.
   */
  textarea(): Locator {
    return this.dialog().locator('.text-editor-textarea');
  }

  /**
   * Get the status line.
   */
  statusLine(): Locator {
    return this.dialog().locator('.text-editor-status');
  }

  /**
   * Get the error message.
   */
  errorMessage(): Locator {
    return this.dialog().locator('.text-editor-error');
  }

  /**
   * Get the cancel button.
   */
  cancelButton(): Locator {
    return this.dialog().locator('.dialog-button--secondary', { hasText: 'cancel' });
  }

  /**
   * Get the save button.
   */
  saveButton(): Locator {
    return this.dialog().locator('.dialog-button--primary');
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
   * Wait for file content to finish loading (loading indicator disappears, textarea appears).
   */
  async waitForContentLoaded(options?: { timeout?: number }): Promise<void> {
    await this.textarea().waitFor({ state: 'visible', ...options });
  }

  /**
   * Check if the dialog is in loading state.
   */
  async isLoading(): Promise<boolean> {
    return await this.loadingIndicator().isVisible();
  }

  /**
   * Get the dialog title text.
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }

  /**
   * Get the textarea content.
   */
  async getContent(): Promise<string> {
    return await this.textarea().inputValue();
  }

  /**
   * Set the textarea content (clears existing and types new).
   */
  async setContent(text: string): Promise<void> {
    await this.textarea().fill(text);
  }

  /**
   * Get the status line text.
   */
  async getStatusText(): Promise<string> {
    return (await this.statusLine().textContent()) ?? '';
  }

  /**
   * Check if the status line shows "modified" indicator.
   */
  async isModified(): Promise<boolean> {
    const text = await this.getStatusText();
    return text.includes('modified');
  }

  /**
   * Check if the save button is disabled.
   */
  async isSaveDisabled(): Promise<boolean> {
    return await this.saveButton().isDisabled();
  }

  /**
   * Get the save button text.
   */
  async getSaveButtonText(): Promise<string> {
    return (await this.saveButton().textContent()) ?? '';
  }

  /**
   * Check if there is an error message displayed.
   */
  async hasError(): Promise<boolean> {
    return await this.errorMessage().isVisible();
  }

  /**
   * Get the error message text.
   */
  async getErrorText(): Promise<string> {
    return (await this.errorMessage().textContent()) ?? '';
  }

  /**
   * Click the save button.
   */
  async clickSave(): Promise<void> {
    await this.saveButton().click();
  }

  /**
   * Click the cancel button.
   */
  async clickCancel(): Promise<void> {
    await this.cancelButton().click();
  }

  /**
   * Close the dialog via the X button.
   */
  async close(): Promise<void> {
    await this.closeButton().click();
    await this.waitForClose();
  }
}
