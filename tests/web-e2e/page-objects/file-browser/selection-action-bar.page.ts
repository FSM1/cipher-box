import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for SelectionActionBar component.
 *
 * Appears when multiple files/folders are selected. Provides batch actions
 * (download, move, delete) and displays the selection count.
 */
export class SelectionActionBarPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the action bar container.
   */
  container(): Locator {
    return this.page.locator('.selection-action-bar[role="toolbar"]');
  }

  /**
   * Get the count text element (e.g. "2 files, 1 folder selected").
   */
  countText(): Locator {
    return this.page.locator('.selection-action-bar-count');
  }

  /**
   * Get the clear selection button.
   */
  clearButton(): Locator {
    return this.page.locator('.selection-action-bar-clear');
  }

  /**
   * Get the download button.
   */
  downloadButton(): Locator {
    return this.container().locator('button', { hasText: 'download' });
  }

  /**
   * Get the move button.
   */
  moveButton(): Locator {
    return this.container().locator('button', { hasText: 'move' });
  }

  /**
   * Get the delete button.
   */
  deleteButton(): Locator {
    return this.page.locator('.selection-action-bar-delete');
  }

  /**
   * Check if the action bar is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.container().isVisible();
  }

  /**
   * Wait for the action bar to become visible.
   */
  async waitForVisible(options?: { timeout?: number }): Promise<void> {
    await this.container().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the action bar to become hidden.
   */
  async waitForHidden(options?: { timeout?: number }): Promise<void> {
    await this.container().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Get the selection count text (e.g. "2 files selected").
   */
  async getCountText(): Promise<string> {
    return (await this.countText().textContent()) ?? '';
  }

  /**
   * Click the clear selection button.
   */
  async clickClear(): Promise<void> {
    await this.clearButton().click();
  }

  /**
   * Click the download button.
   */
  async clickDownload(): Promise<void> {
    await this.downloadButton().click();
  }

  /**
   * Click the move button.
   */
  async clickMove(): Promise<void> {
    await this.moveButton().click();
  }

  /**
   * Click the delete button.
   */
  async clickDelete(): Promise<void> {
    await this.deleteButton().click();
  }

  /**
   * Check if the download button is visible.
   * Download is only shown when files (not just folders) are selected.
   */
  async isDownloadVisible(): Promise<boolean> {
    return await this.downloadButton().isVisible();
  }
}
