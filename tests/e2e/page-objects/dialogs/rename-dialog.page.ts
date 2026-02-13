import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for RenameDialog component.
 *
 * Used for renaming files and folders.
 * Encapsulates dialog visibility, input interactions, validation, and buttons.
 */
export class RenameDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * RenameDialog renders inside a Modal component with a form.
   */
  dialog(): Locator {
    return this.page.locator('.dialog-content').filter({
      has: this.page.locator('#rename-input'),
    });
  }

  /**
   * Get the dialog title.
   */
  title(): Locator {
    return this.page.locator('.modal-title');
  }

  /**
   * Get the name input field.
   */
  nameInput(): Locator {
    return this.page.locator('#rename-input');
  }

  /**
   * Get the save/rename button.
   */
  saveButton(): Locator {
    return this.page.locator('.dialog-button--primary[type="submit"]');
  }

  /**
   * Get the cancel button.
   */
  cancelButton(): Locator {
    return this.page.locator('.dialog-button--secondary', { hasText: 'Cancel' });
  }

  /**
   * Get the validation error message if displayed.
   */
  errorMessage(): Locator {
    return this.page.locator('.dialog-error');
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
   * Get the current value in the name input.
   */
  async getCurrentName(): Promise<string> {
    return (await this.nameInput().inputValue()) ?? '';
  }

  /**
   * Enter a new name (appends to current value).
   */
  async enterNewName(name: string): Promise<void> {
    await this.nameInput().fill(name);
  }

  /**
   * Clear the input and enter a new name.
   */
  async clearAndEnterName(name: string): Promise<void> {
    await this.nameInput().clear();
    await this.nameInput().fill(name);
  }

  /**
   * Click the save/rename button.
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
   * Get the validation error text if displayed.
   * Returns null if no error.
   */
  async getValidationError(): Promise<string | null> {
    const isVisible = await this.errorMessage().isVisible();
    if (!isVisible) {
      return null;
    }
    return await this.errorMessage().textContent();
  }

  /**
   * Check if the save button is disabled.
   * Button is disabled when validation fails or during loading.
   */
  async isSaveDisabled(): Promise<boolean> {
    return (await this.saveButton().isDisabled()) ?? false;
  }

  /**
   * Check if the dialog is in loading state.
   */
  async isLoading(): Promise<boolean> {
    const saveText = await this.saveButton().textContent();
    return saveText?.includes('Renaming...') ?? false;
  }

  /**
   * Full rename flow: clear input, enter new name, save, wait for close.
   *
   * @param newName - The new name to set
   */
  async rename(newName: string): Promise<void> {
    await this.clearAndEnterName(newName);
    await this.clickSave();
    await this.waitForClose();
  }

  /**
   * Get the dialog title text.
   * Returns "Rename File" or "Rename Folder".
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }
}
