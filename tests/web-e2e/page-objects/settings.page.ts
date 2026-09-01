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

  /**
   * Acknowledges the whole-record replace, then saves the form as it stands.
   *
   * A vault that has never published settings reads back as `defaults`, which
   * carries its own acknowledgement — so the first save of a cold-started vault
   * takes both.
   */
  async save(): Promise<void> {
    const unreadAck = this.page.getByTestId('settings-defaults-ack');
    if ((await unreadAck.count()) > 0) await unreadAck.check();
    await this.page.getByLabel(/replaces every stored setting/).check();
    await this.page.getByTestId('settings-save').click();
  }

  get savedMark(): Locator {
    return this.page.getByTestId('settings-saved');
  }

  get saveError(): Locator {
    return this.page.getByTestId('settings-error');
  }

  get provider(): Locator {
    return this.page.getByLabel('your ipfs provider');
  }

  get pinMode(): Locator {
    return this.page.getByLabel('where versions are pinned');
  }

  get providerKind(): Locator {
    return this.page.getByLabel('provider api');
  }

  get accessToken(): Locator {
    return this.page.getByLabel('provider access token');
  }

  get retention(): Locator {
    return this.page.getByLabel('keep newest versions');
  }

  get binRetention(): Locator {
    return this.page.getByLabel('days a deleted item is kept');
  }

  /**
   * Offered only once the read says a provider credential is stored, so its
   * presence is the engine reporting a bearer it will never read back out.
   */
  get clearCredential(): Locator {
    return this.page.getByTestId('settings-clear-credential');
  }

  /** Raises the forget dialog, acknowledges what it takes, and confirms. */
  async forgetDevice(): Promise<void> {
    await this.page.getByTestId('settings-forget-device').click();
    await expect(this.page.getByTestId('forget-device-dialog')).toBeVisible();
    await this.page.getByLabel(/this browser will be signed out/).check();
    await this.page.getByTestId('forget-device-confirm').click();
  }
}
