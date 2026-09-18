/**
 * One web host on one vault: its own browser context, its own login secret.
 *
 * A second *tab* of one context is a follower of the same session — the origin's
 * `BroadcastChannel` and `navigator.locks` are what make two tabs one engine
 * (blueprint/web-client.md "Engine hosting and tab leadership"). A second host
 * therefore takes a context of its own, and a host that shares a vault with a
 * desktop mount takes that mount's login secret.
 */

import type { Browser, BrowserContext, Page } from '@playwright/test';
import { expect } from '@playwright/test';
import { FilesPage } from '../../web-e2e/page-objects/files.page';
import { SharePage } from '../../web-e2e/page-objects/share.page';
import { SharedPage } from '../../web-e2e/page-objects/shared.page';
import { VaultPage } from '../../web-e2e/page-objects/vault.page';
import { claimHere } from '../../web-e2e/sharing';
import type { Deadlines } from '../../desktop-e2e/src/profile';

const DIAGNOSTIC_LINES = 40;

/** How many engine events a failure report carries per tab. */
const ENGINE_EVENTS = 30;

export interface WebHostOptions {
  browser: Browser;
  /** Where the built bundle is served. */
  baseUrl: string;
  /** Names the host in every message. */
  name: string;
  /** The 32-byte login secret as 64 lowercase hex characters. */
  secretHex: string;
  /**
   * The store namespace this host's tabs share. It is not secret — it is what
   * lets a second tab join this vault by name.
   */
  accountId: string;
  deadlines: Deadlines;
}

/** One browser context signed in on one login secret. */
export class WebHost {
  private constructor(
    readonly name: string,
    private readonly accountId: string,
    private readonly secretHex: string,
    private readonly context: BrowserContext,
    readonly page: Page,
    readonly vault: VaultPage,
    readonly files: FilesPage,
    readonly share: SharePage,
    readonly shared: SharedPage,
    private readonly diagnostics: string[]
  ) {}

  /** Opens the front door, signs in, and lands on the vault browser. */
  static async open(options: WebHostOptions): Promise<WebHost> {
    const { page, context, diagnostics } = await tab(options);
    const vault = new VaultPage(page);
    await vault.open();
    await vault.controlled(options.deadlines.mountMs);
    await signIn(page, options.secretHex, options.accountId);
    await page.waitForURL('**/files');
    const host = WebHost.build(options, context, page, vault, diagnostics);
    await expect(host.files.browser).toBeVisible();
    await vault.settled();
    return host;
  }

  /** Spends `link` on the claim route, signed in on this host's own secret. */
  static async claim(options: WebHostOptions & { link: URL }): Promise<WebHost> {
    const { page, context, diagnostics } = await tab(options);
    const vault = new VaultPage(page);
    await claimHere(page, options.link, {
      account: options.accountId,
      start: async () => {
        await vault.controlled(options.deadlines.mountMs);
        await signIn(page, options.secretHex, options.accountId);
      },
    });
    return WebHost.build(options, context, page, vault, diagnostics);
  }

  private static build(
    options: WebHostOptions,
    context: BrowserContext,
    page: Page,
    vault: VaultPage,
    diagnostics: string[]
  ): WebHost {
    return new WebHost(
      options.name,
      options.accountId,
      options.secretHex,
      context,
      page,
      vault,
      new FilesPage(page),
      new SharePage(page),
      new SharedPage(page),
      diagnostics
    );
  }

  /**
   * A second tab of this host, adopted onto the same vault. Only the leader's
   * engine holds a key, so the follower is adopted on the account name.
   */
  async sibling(): Promise<{ page: Page; vault: VaultPage; files: FilesPage }> {
    const page = await this.context.newPage();
    const vault = new VaultPage(page);
    await vault.open();
    await signIn(page, this.secretHex, this.accountId);
    await page.waitForURL('**/files');
    const files = new FilesPage(page);
    await expect(files.browser).toBeVisible();
    return { page, vault, files };
  }

  /** The nocache manual refresh, the barrier `VaultPage.refresh` documents. */
  refresh(): Promise<void> {
    return this.vault.refresh();
  }

  /** Leaves the claim route for the vault browser the claimed copy offers. */
  async leaveClaim(): Promise<void> {
    await this.page.getByRole('link', { name: 'go to your files' }).click();
    await this.page.waitForURL('**/files');
    await expect(this.files.browser).toBeVisible();
  }

  /**
   * Returns to the vault browser through the sidebar. The focus window drives
   * the sync pass, and the vault browser is the route that focuses the root; a
   * document load would land the tab back on the front door, because this
   * session is in memory.
   */
  async openFiles(): Promise<void> {
    await this.page.getByTestId('nav-item-files').click();
    await expect(this.files.browser).toBeVisible();
  }

  /** What the browser said, for a failure that names only the call in flight. */
  tail(): string {
    return this.diagnostics.slice(-DIAGNOSTIC_LINES).join('\n') || '(nothing)';
  }

  /**
   * What this tab's engine holds, as one line. A console tail names nothing
   * when a write never reaches the wire, and the mount logs cannot tell a write
   * the tab refused from one it never made.
   */
  async state(): Promise<string> {
    const read = await this.page
      .evaluate(async (limit) => {
        const engine = window.__CIPHERBOX_ENGINE__!;
        return { view: await engine.snapshot(), events: engine.events().slice(-limit) };
      }, ENGINE_EVENTS)
      .catch((error: unknown) => ({ unreadable: error instanceof Error ? error.message : error }));
    return JSON.stringify(read);
  }

  close(): Promise<void> {
    return this.context.close();
  }
}

async function tab(
  options: WebHostOptions
): Promise<{ context: BrowserContext; page: Page; diagnostics: string[] }> {
  const context = await options.browser.newContext({ baseURL: options.baseUrl });
  const page = await context.newPage();
  const diagnostics: string[] = [];
  page.on('pageerror', (error) => diagnostics.push(`${options.name} pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') diagnostics.push(`${options.name} console: ${message.text()}`);
  });
  return { context, page, diagnostics };
}

/**
 * Signs the tab in on a secret this harness chose, which is what puts a web host
 * and a desktop mount on one vault. The secret crosses as an evaluation
 * argument: this harness enables no Playwright tracing, so it reaches no
 * artifact.
 */
function signIn(page: Page, secretHex: string, accountId: string): Promise<void> {
  return page.evaluate(
    ([secret, account]) => window.__CIPHERBOX_ENGINE__!.signIn(secret, account),
    [secretHex, accountId] as const
  );
}
