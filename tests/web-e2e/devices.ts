/**
 * Devices over a login secret the test process holds, so two browser contexts
 * can sign in on one account: two owner devices, or a holder that loads a
 * second link after its first session ended.
 *
 * Each context reads the secret through a binding, for the reason
 * `VaultPage.coldStart` mints its own in the page.
 */

import { toHex } from '@cipherbox/client';
import type { Browser, BrowserContext, Page } from '@playwright/test';
import { FilesPage } from './page-objects/files.page';
import { SharePage } from './page-objects/share.page';
import type { VaultPage } from './page-objects/vault.page';
import { coldStart } from './vault';

/** The binding a device context answers with its held login secret. */
const SECRET_BINDING = '__cipherboxE2eLoginSecret';

/** One account's login: the secret, and the store namespace its devices use. */
export interface Login {
  readonly secret: string;
  readonly accountId: string;
}

/** A login nobody else in the run holds, so a fresh account over an empty vault. */
export function freshLogin(): Login {
  return {
    secret: toHex(crypto.getRandomValues(new Uint8Array(32))),
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

  /** This device's open page, or a new one when it has none. */
  async page(): Promise<Page> {
    return this.context.pages()[0] ?? this.context.newPage();
  }

  /** Starts a session in `page`, a page of this device, on whatever route it holds. */
  async signIn(page: Page): Promise<void> {
    await page.evaluate(
      async ({ account, binding }) => {
        const held = (window as unknown as Record<string, () => Promise<string>>)[binding];
        await window.__CIPHERBOX_ENGINE__!.signIn(await held(), account);
      },
      { account: this.login.accountId, binding: SECRET_BINDING }
    );
  }

  /** Signs a tab in and waits for the settled vault root. */
  async online(): Promise<Tab> {
    const page = await this.page();
    const { vault, files } = await coldStart(page, async () => {
      await this.signIn(page);
      await page.waitForURL('**/files');
      return this.login.accountId;
    });
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
