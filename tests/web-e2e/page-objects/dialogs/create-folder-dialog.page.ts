import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for CreateFolderDialog component.
 *
 * Used for creating new folders.
 * Encapsulates dialog visibility, input interactions, validation, and buttons.
 */
export class CreateFolderDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * CreateFolderDialog renders inside a Modal component with a form.
   */
  dialog(): Locator {
    return this.page.locator('.dialog-content').filter({
      has: this.page.locator('#folder-name-input'),
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
    return this.page.locator('#folder-name-input');
  }

  /**
   * Get the create button.
   */
  createButton(): Locator {
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
   * Enter a folder name.
   */
  async enterName(name: string): Promise<void> {
    await this.nameInput().fill(name);
  }

  /**
   * Click the create button.
   */
  async clickCreate(): Promise<void> {
    await this.createButton().click();
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
   * Check if the create button is disabled.
   * Button is disabled when validation fails or during loading.
   */
  async isCreateDisabled(): Promise<boolean> {
    return (await this.createButton().isDisabled()) ?? false;
  }

  /**
   * Check if the dialog is in loading state.
   */
  async isLoading(): Promise<boolean> {
    const createText = await this.createButton().textContent();
    return createText?.includes('Creating...') ?? false;
  }

  /**
   * Full create folder flow: enter name, create, wait for close.
   *
   * @param name - The folder name
   */
  async createFolder(name: string): Promise<void> {
    await this.enterName(name);
    await this.clickCreate();
    await this.waitForClose();
  }

  /**
   * Get the dialog title text.
   * Should return "New Folder".
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }
}
