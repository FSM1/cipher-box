import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for SharedFileBrowser component interactions.
 *
 * Encapsulates the ~/shared view: listing received shares, navigating into
 * shared folders, and read-only operations (download, hide).
 */
export class SharedFileBrowserPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the shared browser container.
   */
  container(): Locator {
    return this.page.locator('.shared-browser');
  }

  /**
   * Get the empty state element (no shared items).
   */
  emptyState(): Locator {
    return this.page.getByTestId('shared-empty-state');
  }

  /**
   * Get the empty folder state element.
   */
  emptyFolderState(): Locator {
    return this.page.getByTestId('shared-empty-folder');
  }

  /**
   * Get the breadcrumbs navigation.
   */
  breadcrumbs(): Locator {
    return this.page.getByTestId('breadcrumbs');
  }

  /**
   * Get the loading indicator.
   */
  loadingIndicator(): Locator {
    return this.page.locator('.file-browser-loading');
  }

  /**
   * Get the error alert.
   */
  errorAlert(): Locator {
    return this.page.locator('.shared-error[role="alert"]');
  }

  /**
   * Get all shared item rows (top-level list view).
   */
  sharedItemRows(): Locator {
    return this.page.locator('.shared-list-row');
  }

  /**
   * Get a shared item row by name.
   */
  getSharedItem(name: string): Locator {
    return this.page.locator('.shared-list-row', { hasText: name });
  }

  /**
   * Get the [RO] badge on a shared item.
   */
  getReadOnlyBadge(name: string): Locator {
    return this.getSharedItem(name).locator('.shared-ro-badge');
  }

  /**
   * Get the "SHARED BY" text for a shared item.
   */
  async getSharedBy(name: string): Promise<string> {
    const row = this.getSharedItem(name);
    return (await row.locator('.shared-by-cell').textContent()) ?? '';
  }

  /**
   * Get all file/folder rows in a shared folder view (not the shared list).
   */
  folderItemRows(): Locator {
    return this.page.locator('.file-list-row:not(.file-list-row--parent):not(.shared-list-row)');
  }

  /**
   * Get a folder item row by name (inside a shared folder).
   */
  getFolderItem(name: string): Locator {
    return this.page.locator('.file-list-row:not(.file-list-row--parent):not(.shared-list-row)', {
      hasText: name,
    });
  }

  /**
   * Get the parent directory row ([..] PARENT_DIR).
   */
  parentDirRow(): Locator {
    return this.page.locator('.file-list-row--parent');
  }

  /**
   * Wait for the shared items list to load.
   */
  async waitForLoaded(options?: { timeout?: number }): Promise<void> {
    await this.loadingIndicator().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Check if the shared list is empty (no shared items).
   */
  async isEmpty(): Promise<boolean> {
    return await this.emptyState().isVisible();
  }

  /**
   * Get the count of shared items in the list.
   */
  async getSharedItemCount(): Promise<number> {
    return await this.sharedItemRows().count();
  }

  /**
   * Get all shared item names.
   */
  async getSharedItemNames(): Promise<string[]> {
    const rows = this.sharedItemRows();
    const count = await rows.count();
    const names: string[] = [];
    for (let i = 0; i < count; i++) {
      const nameText = await rows.nth(i).locator('.file-name').textContent();
      if (nameText) names.push(nameText.trim());
    }
    return names;
  }

  /**
   * Double-click a shared item to open it (navigate into folder or download file).
   */
  async openSharedItem(name: string): Promise<void> {
    await this.getSharedItem(name).dblclick();
  }

  /**
   * Right-click a shared item to open context menu.
   */
  async rightClickSharedItem(name: string): Promise<void> {
    await this.getSharedItem(name).click({ button: 'right' });
  }

  /**
   * Double-click a shared item.
   */
  async doubleClickSharedItem(name: string): Promise<void> {
    await this.getSharedItem(name).dblclick();
  }

  /**
   * Wait for a shared item to appear in the list.
   */
  async waitForSharedItem(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getSharedItem(name).waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for a shared item to disappear from the list.
   */
  async waitForSharedItemGone(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getSharedItem(name).waitFor({ state: 'hidden', ...options });
  }

  /**
   * Navigate into a shared folder by clicking on it.
   * Waits for the folder contents to load.
   */
  async navigateIntoFolder(name: string): Promise<void> {
    await this.openSharedItem(name);
    // Wait for folder view to appear (parent dir row indicates we're inside a folder)
    await this.parentDirRow().waitFor({ state: 'visible', timeout: 30000 });
  }

  /**
   * Navigate up to parent (double-click [..] PARENT_DIR).
   */
  async navigateUp(): Promise<void> {
    await this.parentDirRow().dblclick();
  }

  /**
   * Navigate back to the shared root by clicking "shared" in breadcrumbs.
   */
  async navigateToRoot(): Promise<void> {
    await this.breadcrumbs()
      .locator('button', { hasText: /^shared$/ })
      .click();
  }

  /**
   * Get the breadcrumb path text.
   */
  async getBreadcrumbPath(): Promise<string> {
    return (await this.breadcrumbs().textContent()) ?? '';
  }

  /**
   * Get the count of items in the current folder view.
   */
  async getFolderItemCount(): Promise<number> {
    return await this.folderItemRows().count();
  }

  /**
   * Get all item names in the current folder view.
   */
  async getFolderItemNames(): Promise<string[]> {
    const rows = this.folderItemRows();
    const count = await rows.count();
    const names: string[] = [];
    for (let i = 0; i < count; i++) {
      const nameText = await rows.nth(i).locator('.file-name').textContent();
      if (nameText) names.push(nameText.trim());
    }
    return names;
  }

  /**
   * Double-click a folder item (inside a shared folder) to navigate into it.
   */
  async doubleClickFolderItem(name: string): Promise<void> {
    await this.getFolderItem(name).dblclick();
  }

  /**
   * Right-click a folder item (inside a shared folder) to open context menu.
   */
  async rightClickFolderItem(name: string): Promise<void> {
    await this.getFolderItem(name).click({ button: 'right' });
  }
}
