/**
 * Devices over a login secret the test process holds, so two browser contexts
 * can sign in on one account: two owner devices, or a holder that loads a
 * second link after its first session ended.
 *
 * Each context reads the secret through a binding. No `evaluate` argument
 * carries it, so no uploaded trace does either.
 */

import type { Browser, BrowserContext, Page } from '@playwright/test';
import { expect } from './fixtures';
import { FilesPage } from './page-objects/files.page';
import { SharePage } from './page-objects/share.page';
import { SECRET_BINDING, VaultPage } from './page-objects/vault.page';

/** One account's login: the secret, and the store namespace its devices use. */
export interface Login {
  readonly secret: string;
  readonly accountId: string;
}

/** A login nobody else in the run holds, so a fresh account over an empty vault. */
export function freshLogin(): Login {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  return {
    secret: Array.from(secret, (byte) => byte.toString(16).padStart(2, '0')).join(''),
    accountId: crypto.randomUUID(),
  };
}

/** One signed-in tab of a device. */
export interface Tab {
  readonly page: Page;
  readonly vault: VaultPage;
  readonly files: FilesPage;
  readonly share: SharePage;
}

/**
 * One device: a browser context of its own, so its own engine, its own stores
 * and its own tick. A second page of one context shares the origin's
 * `BroadcastChannel` and `navigator.locks`, so it is a second tab, not a
 * second device.
 */
export class Device {
  private constructor(
    readonly context: BrowserContext,
    readonly login: Login
  ) {}

  static async open(browser: Browser, login: Login): Promise<Device> {
    const context = await browser.newContext();
    await context.exposeFunction(SECRET_BINDING, () => login.secret);
    return new Device(context, login);
  }

  /** A page of this device that holds no session yet. */
  async page(): Promise<Page> {
    return this.context.pages()[0] ?? this.context.newPage();
  }

  /** Signs a tab in and waits for the settled vault root. */
  async online(): Promise<Tab> {
    const page = await this.page();
    const vault = new VaultPage(page);
    const files = new FilesPage(page);
    await vault.open();
    await vault.controlled();
    await vault.signInHeld(this.login.accountId);
    await page.waitForURL('**/files');
    await vault.settled();
    await expect(files.browser).toBeVisible();
    return { page, vault, files, share: new SharePage(page) };
  }

  /** Closes every tab, which stops this device's engine and so its tick. */
  async offline(): Promise<void> {
    for (const page of this.context.pages()) await page.close();
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}
