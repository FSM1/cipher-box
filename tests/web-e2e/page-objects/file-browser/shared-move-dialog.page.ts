import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for SharedMoveDialog component.
 *
 * The SharedMoveDialog loads the shared subtree via enumerateSharedSubtree and
 * renders destination folder rows with role="button". Read-only or current-folder
 * rows are disabled (aria-disabled="true", class "move-dialog-folder-item--disabled").
 *
 * Mirrors the shape of MoveDialogPage for the private-vault dialog.
 */
export class SharedMoveDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * SharedMoveDialog renders inside a Modal; the content div contains the
   * shared-move-dialog-folder-item rows which distinguish it from the private MoveDialog.
   */
  dialog(): Locator {
    return this.page.locator('.dialog-content').filter({
      has: this.page.locator('.move-dialog-folder-list'),
    });
  }

  /**
   * Get the modal title element.
   */
  title(): Locator {
    return this.page.locator('.modal-title');
  }

  /**
   * Get the folder list container (role="listbox").
   */
  folderList(): Locator {
    return this.page.locator('.move-dialog-folder-list[role="listbox"]');
  }

  /**
   * Get a specific shared picker row by folder name.
   * Rows have class "shared-move-dialog-folder-item" (in addition to
   * "move-dialog-folder-item") and role="button".
   */
  getFolderItem(name: string): Locator {
    return this.folderList().locator('.shared-move-dialog-folder-item', { hasText: name });
  }

  /**
   * Get all shared picker rows.
   */
  folderItems(): Locator {
    return this.folderList().locator('.shared-move-dialog-folder-item');
  }

  /**
   * Get the primary Move button.
   */
  moveButton(): Locator {
    return this.page.locator('.dialog-button--primary', { hasText: 'Move' });
  }

  /**
   * Get the Cancel button.
   */
  cancelButton(): Locator {
    return this.page.locator('.dialog-button--secondary', { hasText: 'Cancel' });
  }

  /**
   * Get the load error element (shown when enumerateSharedSubtree fails).
   */
  loadError(): Locator {
    return this.dialog().locator('.dialog-error');
  }

  /**
   * Get the loading indicator (shown while enumerateSharedSubtree is in progress).
   */
  loadingIndicator(): Locator {
    return this.dialog().locator('.move-dialog-empty', { hasText: 'loading shared folders' });
  }

  /**
   * Check if the dialog is visible.
   */
  async isVisible(): Promise<boolean> {
    return this.dialog().isVisible();
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
   * Wait for the subtree to finish loading (loading indicator gone and folder
   * list is visible).
   */
  async waitForTreeLoaded(options?: { timeout?: number }): Promise<void> {
    await this.folderList().waitFor({ state: 'visible', ...options });
    // Allow an extra tick for the loading indicator to disappear
    await this.loadingIndicator().waitFor({ state: 'hidden', timeout: options?.timeout ?? 15_000 });
  }

  /**
   * Select a destination folder by name.
   * The row must be enabled (writable and not the current folder).
   */
  async selectFolder(name: string): Promise<void> {
    await this.getFolderItem(name).click();
  }

  /**
   * Click the Move (confirm) button.
   */
  async clickMove(): Promise<void> {
    await this.moveButton().click();
  }

  /**
   * Click the Cancel button.
   */
  async clickCancel(): Promise<void> {
    await this.cancelButton().click();
  }

  /**
   * Check if the Move button is disabled.
   */
  async isMoveDisabled(): Promise<boolean> {
    return this.moveButton().isDisabled();
  }

  /**
   * Check if a folder row is disabled (read-only or current folder).
   */
  async isFolderDisabled(name: string): Promise<boolean> {
    const item = this.getFolderItem(name);
    const className = await item.getAttribute('class');
    return className?.includes('move-dialog-folder-item--disabled') ?? false;
  }

  /**
   * Check if a folder row is selected.
   */
  async isFolderSelected(name: string): Promise<boolean> {
    const item = this.getFolderItem(name);
    const className = await item.getAttribute('class');
    return className?.includes('move-dialog-folder-item--selected') ?? false;
  }

  /**
   * Get all visible folder names from the picker.
   */
  async getVisibleFolderNames(): Promise<string[]> {
    const items = this.folderItems();
    const count = await items.count();
    const names: string[] = [];
    for (let i = 0; i < count; i++) {
      const nameText = await items.nth(i).locator('.move-dialog-folder-name').textContent();
      if (nameText) {
        names.push(nameText.trim());
      }
    }
    return names;
  }

  /**
   * Get the dialog title text.
   * Returns "Move File", "Move Folder", or "Move N items" (batch mode).
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }

  /**
   * Full move flow: wait for tree to load, select folder, click Move, wait for close.
   */
  async move(destinationName: string, options?: { timeout?: number }): Promise<void> {
    await this.waitForTreeLoaded(options);
    await this.selectFolder(destinationName);
    await this.clickMove();
    await this.waitForClose(options);
  }
}
