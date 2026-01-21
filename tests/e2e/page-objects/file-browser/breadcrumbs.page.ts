import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for Breadcrumbs component interactions.
 *
 * Encapsulates breadcrumb navigation for folder paths.
 * Uses semantic selectors for maintainability.
 */
export class BreadcrumbsPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the breadcrumbs container.
   */
  container(): Locator {
    return this.page.locator('.breadcrumbs');
  }

  /**
   * Get all breadcrumb items.
   */
  breadcrumbItems(): Locator {
    return this.page.locator('.breadcrumb-item');
  }

  /**
   * Get a specific breadcrumb by name.
   */
  getBreadcrumb(name: string): Locator {
    return this.page.locator('.breadcrumb-item', { hasText: name });
  }

  /**
   * Get the home breadcrumb (root).
   */
  getHomeBreadcrumb(): Locator {
    return this.page.locator('.breadcrumb-item').first();
  }

  /**
   * Click a breadcrumb to navigate to that folder.
   */
  async clickBreadcrumb(name: string): Promise<void> {
    await this.getBreadcrumb(name).click();
  }

  /**
   * Click the home breadcrumb to navigate to root.
   */
  async clickHome(): Promise<void> {
    await this.getHomeBreadcrumb().click();
  }

  /**
   * Check if the breadcrumbs component is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.container().isVisible();
  }

  /**
   * Get the current path as array of breadcrumb names.
   * Returns folder names from root to current location.
   */
  async getCurrentPath(): Promise<string[]> {
    const items = this.breadcrumbItems();
    const count = await items.count();
    const path: string[] = [];

    for (let i = 0; i < count; i++) {
      const text = await items.nth(i).textContent();
      if (text) {
        // Clean up text (remove separators, trim)
        const cleaned = text.replace(/[/›>]/g, '').trim();
        if (cleaned) {
          path.push(cleaned);
        }
      }
    }

    return path;
  }

  /**
   * Get the number of breadcrumb items.
   * Root folder has 1 breadcrumb, nested folders have more.
   */
  async getBreadcrumbCount(): Promise<number> {
    return await this.breadcrumbItems().count();
  }

  /**
   * Get the last (current) breadcrumb text.
   */
  async getCurrentBreadcrumb(): Promise<string> {
    const items = this.breadcrumbItems();
    const count = await items.count();
    if (count === 0) {
      return '';
    }
    const text = await items.nth(count - 1).textContent();
    return text?.trim() ?? '';
  }

  /**
   * Check if a breadcrumb is clickable (not the current/last item).
   * The last breadcrumb is typically non-clickable.
   */
  async isBreadcrumbClickable(name: string): Promise<boolean> {
    const breadcrumb = this.getBreadcrumb(name);
    const isDisabled = await breadcrumb.getAttribute('aria-disabled');
    return isDisabled !== 'true';
  }
}
