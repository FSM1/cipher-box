import { Page } from '@playwright/test';

/**
 * Base page object class with common utilities for all page objects.
 * Provides navigation, waiting, and locator helpers.
 */
export class BasePage {
  readonly page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  /**
   * Navigate to a path relative to baseURL
   */
  async goto(path: string): Promise<void> {
    await this.page.goto(path);
  }

  /**
   * Wait for page to finish loading (network idle)
   */
  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Get element by test ID attribute
   */
  getByTestId(testId: string) {
    return this.page.getByTestId(testId);
  }
}
