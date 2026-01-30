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
}
