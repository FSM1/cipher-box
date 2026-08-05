import type { Locator, Page } from '@playwright/test';

/** The vault browser route and the chrome around it. */
export class FilesPage {
  constructor(readonly page: Page) {}

  get browser(): Locator {
    return this.page.getByTestId('file-browser');
  }

  get emptyState(): Locator {
    return this.page.getByTestId('empty-state');
  }

  get breadcrumbs(): Locator {
    return this.page.getByTestId('breadcrumbs');
  }

  get status(): Locator {
    return this.page.getByTestId('status-indicator');
  }

  /** What the route renders in place of the vault when no session backs it. */
  get checkingSession(): Locator {
    return this.page.getByTestId('files-signing-in');
  }

  async goto(): Promise<void> {
    await this.page.goto('/files');
  }

  /**
   * Opens the header menu and signs out. Hover, not click: the menu opens on
   * pointer entry and the trigger *toggles*, so a click races itself shut.
   */
  async signOut(): Promise<void> {
    await this.page.getByTestId('user-menu').hover();
    await this.page.getByTestId('logout-button').click();
  }
}
