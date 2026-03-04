import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for the Recycle Bin browser.
 *
 * Encapsulates navigation to the bin view, item listing, context menu
 * actions (restore, permanent delete), and the Empty Bin button.
 *
 * Selector strategy:
 * - data-testid for structural elements (bin-list, bin-item-*, bin-context-menu, etc.)
 * - CSS class selectors for empty state and list styling
 * - Role selectors for menu items
 */
export class BinPage {
  constructor(private readonly page: Page) {}

  // ============================================
  // Navigation
  // ============================================

  /**
   * Get the bin sidebar nav item.
   */
  binNavItem(): Locator {
    return this.page.getByTestId('nav-item-bin');
  }

  /**
   * Navigate to the bin page via the sidebar nav item.
   */
  async navigate(): Promise<void> {
    await this.binNavItem().click();
    await this.page.waitForURL('**/#/bin', { timeout: 15000 });
  }

  // ============================================
  // List elements
  // ============================================

  /**
   * Get the bin list container (visible when entries exist).
   */
  binList(): Locator {
    return this.page.getByTestId('bin-list');
  }

  /**
   * Get the empty state element (visible when bin is empty).
   */
  emptyState(): Locator {
    return this.page.getByTestId('bin-empty-state');
  }

  /**
   * Get all bin item locators.
   */
  binItems(): Locator {
    return this.page.locator('[data-testid^="bin-item-"]');
  }

  /**
   * Get the count of visible bin items.
   */
  async getBinItemCount(): Promise<number> {
    return await this.binItems().count();
  }

  /**
   * Get a specific bin item by its display name.
   * Matches items whose label text contains the given name.
   */
  getBinItemByName(name: string): Locator {
    return this.page.locator('[data-testid^="bin-item-"]', { hasText: name });
  }

  /**
   * Wait for a bin item with the given name to appear.
   */
  async waitForBinItem(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getBinItemByName(name).waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for a bin item with the given name to disappear.
   */
  async waitForBinItemToDisappear(name: string, options?: { timeout?: number }): Promise<void> {
    await this.getBinItemByName(name).waitFor({ state: 'hidden', ...options });
  }

  // ============================================
  // Empty Bin button
  // ============================================

  /**
   * Get the "Empty Bin" toolbar button.
   */
  emptyBinButton(): Locator {
    return this.page.getByTestId('empty-bin-btn');
  }

  // ============================================
  // Context menu
  // ============================================

  /**
   * Get the bin context menu container.
   */
  contextMenu(): Locator {
    return this.page.getByTestId('bin-context-menu');
  }

  /**
   * Right-click a bin item to open its context menu.
   */
  async rightClickItem(name: string): Promise<void> {
    await this.getBinItemByName(name).click({ button: 'right' });
    await this.contextMenu().waitFor({ state: 'visible', timeout: 5000 });
  }

  /**
   * Click the "Restore" option in the bin context menu.
   */
  async clickContextRestore(): Promise<void> {
    await this.contextMenu().locator('button[role="menuitem"]', { hasText: 'Restore' }).click();
  }

  /**
   * Click the "Delete Permanently" option in the bin context menu.
   */
  async clickContextPermanentDelete(): Promise<void> {
    await this.contextMenu()
      .locator('button[role="menuitem"]', { hasText: 'Delete Permanently' })
      .click();
  }

  // ============================================
  // Composite actions
  // ============================================

  /**
   * Restore a bin item by name via context menu.
   * Right-clicks the item and selects Restore.
   */
  async restoreItem(name: string): Promise<void> {
    await this.rightClickItem(name);
    await this.clickContextRestore();
  }

  /**
   * Permanently delete a bin item by name via context menu + confirm dialog.
   * Right-clicks the item, selects Delete Permanently, then clicks confirm.
   */
  async permanentlyDeleteItem(name: string): Promise<void> {
    await this.rightClickItem(name);
    await this.clickContextPermanentDelete();
    // Wait for confirm dialog and click the destructive confirm button
    await this.page.locator('.dialog-button--destructive').waitFor({ state: 'visible' });
    await this.page.locator('.dialog-button--destructive').click();
  }

  /**
   * Empty the entire bin via the toolbar button + confirm dialog.
   */
  async emptyBin(): Promise<void> {
    await this.emptyBinButton().click();
    // Wait for confirm dialog and click the destructive confirm button
    await this.page.locator('.dialog-button--destructive').waitFor({ state: 'visible' });
    await this.page.locator('.dialog-button--destructive').click();
  }
}
