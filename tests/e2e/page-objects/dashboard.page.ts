import { expect } from '@playwright/test';
import { BasePage } from './base.page';

/**
 * Dashboard page object for the main application view.
 * Provides access to file list, folder tree, and navigation elements.
 */
export class DashboardPage extends BasePage {
  /**
   * Locator for the sidebar navigation
   */
  get sidebar() {
    return this.page.getByRole('navigation');
  }

  /**
   * Locator for the file list container
   */
  get fileList() {
    return this.getByTestId('file-list');
  }

  /**
   * Locator for the folder tree container
   */
  get folderTree() {
    return this.getByTestId('folder-tree');
  }

  /**
   * Locator for the logout button
   * Uses class selector for stability
   */
  get logoutButton() {
    return this.page.locator('button.logout-link');
  }

  /**
   * Navigate to the dashboard
   */
  async goto(): Promise<void> {
    await super.goto('/dashboard');
  }

  /**
   * Check if user is logged in by verifying dashboard elements are visible
   */
  async isLoggedIn(): Promise<boolean> {
    try {
      await expect(this.sidebar).toBeVisible({ timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }
}
