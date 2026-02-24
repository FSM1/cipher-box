import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for SearchPalette component interactions.
 *
 * Encapsulates the command palette overlay used for searching files and folders.
 * Provides locator methods for DOM elements and action methods for interactions.
 */
export class SearchPalettePage {
  constructor(private readonly page: Page) {}

  // ---------------------------------------------------------------------------
  // Locator methods
  // ---------------------------------------------------------------------------

  /**
   * The full-screen backdrop overlay (also has role="dialog").
   */
  backdrop(): Locator {
    return this.page.locator('.search-backdrop');
  }

  /**
   * The palette container (centered card with input + results).
   */
  palette(): Locator {
    return this.page.locator('.search-palette');
  }

  /**
   * The search text input.
   */
  input(): Locator {
    return this.page.locator('.search-input');
  }

  /**
   * The results container (role="listbox").
   */
  resultsList(): Locator {
    return this.page.locator('.search-results[role="listbox"]');
  }

  /**
   * All result item elements.
   */
  resultItems(): Locator {
    return this.page.locator('.search-result-item');
  }

  /**
   * A specific result item by zero-based index.
   */
  resultItem(index: number): Locator {
    return this.resultItems().nth(index);
  }

  /**
   * The name element within a specific result item.
   */
  resultName(index: number): Locator {
    return this.resultItem(index).locator('.search-result-name');
  }

  /**
   * The "no results" message element.
   */
  noResults(): Locator {
    return this.page.locator('.search-no-results');
  }

  /**
   * The "building index..." indicator.
   */
  buildingIndicator(): Locator {
    return this.page.locator('.search-building');
  }

  /**
   * The footer bar with keyboard hints and result count.
   */
  footer(): Locator {
    return this.page.locator('.search-footer');
  }

  /**
   * The result count text in the footer (e.g., "// 3 results").
   */
  footerCount(): Locator {
    return this.page.locator('.search-footer-count');
  }

  /**
   * The search button in the app header.
   */
  headerSearchButton(): Locator {
    return this.page.locator('.header-search-btn');
  }

  // ---------------------------------------------------------------------------
  // Action methods
  // ---------------------------------------------------------------------------

  /**
   * Wait for the search palette to become visible.
   */
  async waitForOpen(options?: { timeout?: number }): Promise<void> {
    await this.backdrop().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the search palette to close (hidden or detached).
   */
  async waitForClosed(options?: { timeout?: number }): Promise<void> {
    await this.backdrop().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Type a query into the search input.
   */
  async typeQuery(text: string): Promise<void> {
    await this.input().fill(text);
  }

  /**
   * Clear the search input.
   */
  async clearQuery(): Promise<void> {
    await this.input().fill('');
  }

  /**
   * Get the number of visible result items.
   */
  async getResultCount(): Promise<number> {
    return await this.resultItems().count();
  }

  /**
   * Get an array of result name texts.
   */
  async getResultNames(): Promise<string[]> {
    const items = this.page.locator('.search-result-item .search-result-name');
    const count = await items.count();
    const names: string[] = [];
    for (let i = 0; i < count; i++) {
      const text = await items.nth(i).textContent();
      if (text) names.push(text);
    }
    return names;
  }

  /**
   * Click a result item by zero-based index.
   */
  async clickResult(index: number): Promise<void> {
    await this.resultItem(index).click();
  }

  /**
   * Check whether the palette backdrop is currently visible.
   */
  async isOpen(): Promise<boolean> {
    return await this.backdrop().isVisible();
  }

  /**
   * Get the footer count text (e.g., "// 3 results").
   */
  async getFooterCountText(): Promise<string> {
    return (await this.footerCount().textContent()) ?? '';
  }

  /**
   * Wait for the search index to finish building.
   * Resolves immediately if the building indicator isn't visible.
   */
  async waitForIndexReady(options?: { timeout?: number }): Promise<void> {
    const indicator = this.buildingIndicator();
    // If the building indicator is currently visible, wait for it to disappear
    if (await indicator.isVisible()) {
      await indicator.waitFor({ state: 'hidden', ...options });
    }
  }

  /**
   * Wait for at least one result item to become visible.
   */
  async waitForResults(options?: { timeout?: number }): Promise<void> {
    await this.resultItems()
      .first()
      .waitFor({ state: 'visible', ...options });
  }

  /**
   * Find the index of the currently selected (highlighted) result item.
   * Returns -1 if no item has the "selected" class.
   */
  async selectedResultIndex(): Promise<number> {
    const items = this.resultItems();
    const count = await items.count();
    for (let i = 0; i < count; i++) {
      const className = await items.nth(i).getAttribute('class');
      if (className?.includes('selected')) {
        return i;
      }
    }
    return -1;
  }
}
