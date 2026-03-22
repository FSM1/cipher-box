import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for Breadcrumbs component interactions.
 *
 * Interactive breadcrumb navigation with clickable segments
 * and drag-drop support for quick moves to parent folders.
 *
 * Uses semantic selectors for maintainability.
 */
export class BreadcrumbsPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the breadcrumbs container.
   */
  container(): Locator {
    return this.page.locator('.breadcrumb-nav');
  }

  /**
   * Get a breadcrumb item by folder name.
   */
  getBreadcrumbItem(name: string): Locator {
    return this.container().locator('.breadcrumb-item', {
      hasText: new RegExp(`^${name}$`, 'i'),
    });
  }

  /**
   * Get all breadcrumb items.
   */
  breadcrumbItems(): Locator {
    return this.container().locator('.breadcrumb-item');
  }

  /**
   * Check if the breadcrumbs component is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.container().isVisible();
  }

  /**
   * Click a breadcrumb segment to navigate.
   */
  async clickBreadcrumb(name: string): Promise<void> {
    await this.getBreadcrumbItem(name).click();
  }

  /**
   * Get all visible breadcrumb names in order.
   */
  async getVisibleBreadcrumbs(): Promise<string[]> {
    const items = this.breadcrumbItems();
    const count = await items.count();
    const names: string[] = [];

    for (let i = 0; i < count; i++) {
      const text = await items.nth(i).textContent();
      if (text) {
        names.push(text.trim());
      }
    }

    return names;
  }

  /**
   * Get the current path as a string (e.g., "~/my vault/documents").
   * Reads the full nav content.
   */
  async getPathString(): Promise<string> {
    const text = await this.container().textContent();
    return text?.trim() ?? '';
  }

  /**
   * Check if the current path contains a specific folder name.
   */
  async pathContains(folderName: string): Promise<boolean> {
    const path = await this.getPathString();
    return path.toLowerCase().includes(folderName.toLowerCase());
  }

  /**
   * Check if at root folder.
   * Root shows only "my vault" segment after ~/
   */
  async isAtRoot(): Promise<boolean> {
    const breadcrumbs = await this.getVisibleBreadcrumbs();
    return breadcrumbs.length === 1 && breadcrumbs[0].toLowerCase() === 'my vault';
  }

  /**
   * Get the current folder name (last breadcrumb segment).
   */
  async getCurrentFolderName(): Promise<string> {
    const breadcrumbs = await this.getVisibleBreadcrumbs();
    return breadcrumbs[breadcrumbs.length - 1] || 'my vault';
  }

  /**
   * Wait for path to contain a specific folder name.
   * Useful after navigation.
   */
  async waitForPathToContain(folderName: string, options?: { timeout?: number }): Promise<void> {
    await this.container()
      .locator('.breadcrumb-item', { hasText: new RegExp(folderName, 'i') })
      .waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the breadcrumbs to show only root.
   */
  async waitForRoot(options?: { timeout?: number }): Promise<void> {
    // Wait for "my vault" to be the only breadcrumb (root level)
    await this.page
      .locator('.breadcrumb-nav')
      .filter({ hasText: /my vault/i })
      .waitFor({ state: 'visible', ...options });
  }

  /**
   * Drag an item to a breadcrumb segment.
   * This performs a drag-and-drop from a source locator to a breadcrumb.
   *
   * @param sourceLocator - The locator for the item to drag
   * @param breadcrumbName - The name of the target breadcrumb
   */
  async dragItemToBreadcrumb(sourceLocator: Locator, breadcrumbName: string): Promise<void> {
    const target = this.getBreadcrumbItem(breadcrumbName);
    await sourceLocator.dragTo(target);
  }
}
