import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for MoveDialog component.
 *
 * Used for moving files and folders to different locations.
 * Encapsulates dialog visibility, folder list interactions, and buttons.
 */
export class MoveDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * MoveDialog renders inside a Modal component.
   */
  dialog(): Locator {
    return this.page.locator('.dialog-content').filter({
      has: this.page.locator('.move-dialog-folder-list'),
    });
  }

  /**
   * Get the dialog title.
   */
  title(): Locator {
    return this.page.locator('.modal-title');
  }

  /**
   * Get the folder list container.
   */
  folderList(): Locator {
    return this.page.locator('.move-dialog-folder-list');
  }

  /**
   * Get a specific folder item by name.
   */
  getFolderItem(name: string): Locator {
    return this.folderList().locator('.move-dialog-folder-item', { hasText: name });
  }

  /**
   * Get all folder items.
   */
  folderItems(): Locator {
    return this.folderList().locator('.move-dialog-folder-item');
  }

  /**
   * Get the move button.
   */
  moveButton(): Locator {
    return this.page.locator('.dialog-button--primary', { hasText: 'Move' });
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
    return this.dialog().locator('.dialog-error');
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
   * Select a folder by name.
   */
  async selectFolder(name: string): Promise<void> {
    await this.getFolderItem(name).click();
  }

  /**
   * Click the move button.
   */
  async clickMove(): Promise<void> {
    await this.moveButton().click();
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
   * Check if the move button is disabled.
   */
  async isMoveDisabled(): Promise<boolean> {
    return (await this.moveButton().isDisabled()) ?? false;
  }

  /**
   * Check if a folder item is disabled (invalid target).
   */
  async isFolderDisabled(name: string): Promise<boolean> {
    const item = this.getFolderItem(name);
    const className = await item.getAttribute('class');
    return className?.includes('move-dialog-folder-item--disabled') ?? false;
  }

  /**
   * Check if a folder item is selected.
   */
  async isFolderSelected(name: string): Promise<boolean> {
    const item = this.getFolderItem(name);
    const className = await item.getAttribute('class');
    return className?.includes('move-dialog-folder-item--selected') ?? false;
  }

  /**
   * Get all visible folder names in order.
   */
  async getVisibleFolderNames(): Promise<string[]> {
    const items = this.folderItems();
    const count = await items.count();
    const names: string[] = [];

    for (let i = 0; i < count; i++) {
      const nameText = await items.nth(i).locator('.move-dialog-folder-name').textContent();
      if (nameText) {
        names.push(nameText);
      }
    }

    return names;
  }

  /**
   * Full move flow: select folder, click move, wait for close.
   *
   * @param destinationName - Name of destination folder
   */
  async move(destinationName: string): Promise<void> {
    await this.selectFolder(destinationName);
    await this.clickMove();
    await this.waitForClose();
  }

  /**
   * Get the dialog title text.
   * Returns "Move File" or "Move Folder".
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }
}
