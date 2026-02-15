import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for ParentDirRow component interactions.
 *
 * Phase 6.3: The [..] PARENT_DIR row replaces FolderTree for upward navigation.
 * This row appears as the first item in the file list when not at root.
 *
 * Uses semantic selectors for maintainability.
 */
export class ParentDirPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the parent directory row.
   */
  row(): Locator {
    return this.page.locator('[data-testid="parent-dir-row"]');
  }

  /**
   * Alternative selector using class.
   */
  rowByClass(): Locator {
    return this.page.locator('.file-list-item--parent');
  }

  /**
   * Check if the parent directory row is visible.
   * It should be visible when not at root folder.
   */
  async isVisible(): Promise<boolean> {
    return await this.row().isVisible();
  }

  /**
   * Click the parent directory row to navigate up.
   */
  async click(): Promise<void> {
    await this.row().click();
  }

  /**
   * Wait for the parent directory row to appear.
   * Useful after navigating into a subfolder.
   */
  async waitForVisible(options?: { timeout?: number }): Promise<void> {
    await this.row().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the parent directory row to disappear.
   * Useful after navigating to root.
   */
  async waitForHidden(options?: { timeout?: number }): Promise<void> {
    await this.row().waitFor({ state: 'hidden', ...options });
  }
}
