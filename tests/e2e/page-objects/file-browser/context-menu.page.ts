import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for ContextMenu component interactions.
 *
 * Encapsulates right-click context menu actions (Download, Rename, Delete).
 * Uses semantic selectors (role="menu", role="menuitem").
 */
export class ContextMenuPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the context menu container.
   */
  menu(): Locator {
    return this.page.locator('.context-menu[role="menu"]');
  }

  /**
   * Get the Download menu option (files only).
   */
  renameOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Rename' });
  }

  /**
   * Get the Rename menu option.
   */
  deleteOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Delete' });
  }

  /**
   * Get the Download menu option (files only).
   */
  downloadOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Download' });
  }

  /**
   * Get the Move menu option.
   */
  moveOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Move to...' });
  }

  /**
   * Get the Edit menu option (text files only).
   */
  editOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Edit' });
  }

  /**
   * Get the Details menu option.
   */
  detailsOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Details' });
  }

  /**
   * Check if the context menu is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.menu().isVisible();
  }

  /**
   * Wait for the context menu to open.
   */
  async waitForOpen(options?: { timeout?: number }): Promise<void> {
    await this.menu().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the context menu to close.
   */
  async waitForClose(options?: { timeout?: number }): Promise<void> {
    await this.menu().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Click the Rename option.
   */
  async clickRename(): Promise<void> {
    await this.renameOption().click();
  }

  /**
   * Click the Delete option.
   */
  async clickDelete(): Promise<void> {
    await this.deleteOption().click();
  }

  /**
   * Click the Download option (files only).
   */
  async clickDownload(): Promise<void> {
    await this.downloadOption().click();
  }

  /**
   * Click the Move option.
   */
  async clickMove(): Promise<void> {
    await this.moveOption().click();
  }

  /**
   * Click the Edit option (text files only).
   */
  async clickEdit(): Promise<void> {
    await this.editOption().click();
  }

  /**
   * Click the Details option.
   */
  async clickDetails(): Promise<void> {
    await this.detailsOption().click();
  }

  /**
   * Get the Preview menu option (image, PDF, audio, video, text files).
   */
  previewOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Preview' });
  }

  /**
   * Click the Preview option to open the preview dialog.
   */
  async clickPreview(): Promise<void> {
    await this.previewOption().click();
  }

  /**
   * Get the Share menu option.
   */
  shareOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Share' });
  }

  /**
   * Click the Share option to open the share dialog.
   */
  async clickShare(): Promise<void> {
    await this.shareOption().click();
  }

  /**
   * Get the Hide menu option (shared items only).
   */
  hideOption(): Locator {
    return this.menu().locator('button[role="menuitem"]', { hasText: 'Hide' });
  }

  /**
   * Click the Hide option (shared items only).
   */
  async clickHide(): Promise<void> {
    await this.hideOption().click();
  }

  /**
   * Get all visible menu option labels.
   * Useful for verifying which actions are available.
   */
  async getVisibleOptions(): Promise<string[]> {
    const menuItems = this.menu().locator('button[role="menuitem"]');
    const count = await menuItems.count();
    const options: string[] = [];

    for (let i = 0; i < count; i++) {
      const text = await menuItems.nth(i).textContent();
      if (text) {
        // Extract text without icon
        const cleaned = text.replace(/[^\w\s]/g, '').trim();
        if (cleaned) {
          options.push(cleaned);
        }
      }
    }

    return options;
  }

  /**
   * Close the context menu by pressing Escape.
   */
  async closeWithEscape(): Promise<void> {
    await this.page.keyboard.press('Escape');
  }

  /**
   * Close the context menu by clicking outside of it.
   */
  async closeByClickingOutside(): Promise<void> {
    // Click at a position outside the menu
    await this.page.mouse.click(0, 0);
  }

  // ========================================
  // Batch context menu methods
  // ========================================

  /**
   * Get the batch header element (shows "N items selected").
   */
  header(): Locator {
    return this.menu().locator('.context-menu-header');
  }

  /**
   * Check if this is a batch context menu (has header).
   */
  async isBatchMenu(): Promise<boolean> {
    return await this.header().isVisible();
  }

  /**
   * Get the batch header text (e.g. "3 items selected").
   */
  async getHeaderText(): Promise<string> {
    return (await this.header().textContent()) ?? '';
  }

  /**
   * Click the batch download option ("Download files").
   */
  async clickBatchDownload(): Promise<void> {
    await this.menu().locator('button[role="menuitem"]', { hasText: 'Download' }).click();
  }

  /**
   * Click the batch move option ("Move to...").
   */
  async clickBatchMove(): Promise<void> {
    await this.menu().locator('button[role="menuitem"]', { hasText: 'Move to...' }).click();
  }

  /**
   * Click the batch delete option (e.g. "Delete 3 items").
   */
  async clickBatchDelete(): Promise<void> {
    await this.menu()
      .locator('button[role="menuitem"]', { hasText: /Delete \d+ items/ })
      .click();
  }
}
