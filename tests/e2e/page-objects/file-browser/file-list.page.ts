import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for FileList component interactions.
 *
 * Encapsulates all file and folder list interactions in the main content area.
 * Uses semantic selectors (getByRole, getByText) for maintainability.
 */
export class FileListPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the file list container (grid role).
   */
  fileListContainer(): Locator {
    return this.page.locator('.file-list[role="grid"]');
  }

  /**
   * Get all file list items.
   */
  fileItems(): Locator {
    return this.page.locator('.file-list-item');
  }

  /**
   * Get a specific item by name (file or folder).
   * Uses the item text content to locate.
   */
  getItem(name: string): Locator {
    return this.page.locator('.file-list-item', { hasText: name }).filter({
      has: this.page.locator('.file-list-item-name', { hasText: name }),
    });
  }

  /**
   * Get a specific file item by name.
   * Files have size displayed (not "-").
   */
  getFileItem(name: string): Locator {
    return this.getItem(name).filter({
      hasNot: this.page.locator('.file-list-item-size', { hasText: '-' }),
    });
  }

  /**
   * Get a specific folder item by name.
   * Folders have size displayed as "-".
   */
  getFolderItem(name: string): Locator {
    return this.getItem(name).filter({
      has: this.page.locator('.file-list-item-size', { hasText: '-' }),
    });
  }

  /**
   * Right-click an item to open context menu.
   */
  async rightClickItem(name: string): Promise<void> {
    await this.getItem(name).click({ button: 'right' });
  }

  /**
   * Double-click a folder to navigate into it.
   */
  async doubleClickFolder(name: string): Promise<void> {
    await this.getFolderItem(name).dblclick();
  }

  /**
   * Single click to select an item.
   */
  async selectItem(name: string): Promise<void> {
    await this.getItem(name).click();
  }

  /**
   * Get the total count of visible items.
   */
  async getItemCount(): Promise<number> {
    return await this.fileItems().count();
  }

  /**
   * Check if an item is visible in the list.
   */
  async isItemVisible(name: string): Promise<boolean> {
    return await this.getItem(name).isVisible();
  }

  /**
   * Wait for an item to appear in the list.
   * Useful after file upload or folder creation.
   */
  async waitForItemToAppear(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getItem(name).waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for an item to disappear from the list.
   * Useful after deletion or move.
   */
  async waitForItemToDisappear(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getItem(name).waitFor({ state: 'hidden', ...options });
  }

  /**
   * Check if an item is currently selected.
   */
  async isItemSelected(name: string): Promise<boolean> {
    const item = this.getItem(name);
    const className = await item.getAttribute('class');
    return className?.includes('file-list-item--selected') ?? false;
  }

  /**
   * Get the size displayed for a file item.
   */
  async getFileSize(name: string): Promise<string> {
    const item = this.getFileItem(name);
    return (await item.locator('.file-list-item-size').textContent()) ?? '';
  }

  /**
   * Get the modified date displayed for an item.
   */
  async getModifiedDate(name: string): Promise<string> {
    const item = this.getItem(name);
    return (await item.locator('.file-list-item-date').textContent()) ?? '';
  }

  /**
   * Get all visible item names in order.
   * Useful for verifying sort order.
   */
  async getVisibleItemNames(): Promise<string[]> {
    const items = this.fileItems();
    const count = await items.count();
    const names: string[] = [];

    for (let i = 0; i < count; i++) {
      const nameText = await items.nth(i).locator('.file-list-item-name').textContent();
      if (nameText) {
        names.push(nameText);
      }
    }

    return names;
  }

  /**
   * Get item type (file or folder) by examining the size field.
   * Folders show "-" for size, files show actual size.
   */
  async getItemType(name: string): Promise<'file' | 'folder'> {
    const item = this.getItem(name);
    const sizeText = await item.locator('.file-list-item-size').textContent();
    // Folders show "-" for size, files show actual size
    return sizeText?.trim() === '-' ? 'folder' : 'file';
  }

  /**
   * Get the internal item ID from the DOM data-item-id attribute.
   * This is the actual UUID used by the application, not the display name.
   *
   * @param name - Display name of the item
   * @returns The internal UUID of the item
   * @throws Error if item not found or doesn't have an ID
   */
  async getItemId(name: string): Promise<string> {
    const item = this.getItem(name);
    const itemId = await item.getAttribute('data-item-id');
    if (!itemId) {
      throw new Error(`Could not find item ID for "${name}"`);
    }
    return itemId;
  }

  /**
   * Perform a drag-drop move operation from the file list to a folder.
   * Uses Playwright's built-in drag and drop.
   *
   * @param itemName - Name of the item to drag
   * @param targetLocator - Locator for the drop target
   */
  async dragItemTo(
    itemName: string,
    targetLocator: import('@playwright/test').Locator
  ): Promise<void> {
    const sourceItem = this.getItem(itemName);
    await sourceItem.dragTo(targetLocator);
  }
}
