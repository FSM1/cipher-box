import { expect, type Locator, type Page } from '@playwright/test';

/** The settings route and the device-scoped actions it hosts. */
export class SettingsPage {
  constructor(readonly page: Page) {}

  get panel(): Locator {
    return this.page.getByTestId('settings-page');
  }

  get accountId(): Locator {
    return this.page.getByTestId('settings-account-id');
  }

  /**
   * Navigates through the sidebar, not the address bar: this suite's session is
   * in-memory, so a document load would land the tab back on the front door.
   */
  async open(): Promise<void> {
    await this.page.getByTestId('nav-item-settings').click();
    await expect(this.panel).toBeVisible();
  }

  /** Saves the vault settings form as it currently stands. */
  async save(): Promise<void> {
    await this.page.getByTestId('settings-save').click();
  }

  get savedMark(): Locator {
    return this.page.getByTestId('settings-saved');
  }

  get saveError(): Locator {
    return this.page.getByTestId('settings-error');
  }

  async setProvider(endpoint: string): Promise<void> {
    await this.page.getByLabel('your ipfs provider').fill(endpoint);
  }

  async setPinMode(mode: string): Promise<void> {
    await this.page.getByLabel('where versions are pinned').selectOption(mode);
  }

  /** Raises the forget dialog, acknowledges what it takes, and confirms. */
  async forgetDevice(): Promise<void> {
    await this.page.getByTestId('settings-forget-device').click();
    await expect(this.page.getByTestId('forget-device-dialog')).toBeVisible();
    await this.page.getByLabel(/this browser will be signed out/).check();
    await this.page.getByTestId('forget-device-confirm').click();
  }
}
