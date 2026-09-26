import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The `/invite` route. The panel carries where the page stands on `data-state`
 * — `checking`, `waiting`, `noLink`, `previewing`, `joinable`, `joined`,
 * `expired`, `revoked`, `unresolvable`, `untrusted`, `unreadable`, `joining`
 * or `refused` — so a spec asserts the state, not the copy.
 */
export class InvitePage {
  constructor(readonly page: Page) {}

  get panel(): Locator {
    return this.page.getByTestId('invite-claim');
  }

  /** Which account the join would be spent under. */
  get account(): Locator {
    return this.page.getByTestId('invite-account');
  }

  /** The preview's lead line, which names the owner and the folder when they verify. */
  get headline(): Locator {
    return this.page.getByTestId('invite-headline');
  }

  get permission(): Locator {
    return this.page.getByTestId('invite-permission');
  }

  /** The previewed folder's direct children. */
  get entries(): Locator {
    return this.page.getByTestId('invite-entry');
  }

  /** The name the claimant offers the owner, which the join carries. */
  get name(): Locator {
    return this.page.getByTestId('invite-name');
  }

  get joinButton(): Locator {
    return this.page.getByTestId('invite-join');
  }

  get openFolderButton(): Locator {
    return this.page.getByTestId('invite-open-folder');
  }

  /** The login methods the route renders in place while it waits for a session. */
  get signIn(): Locator {
    return this.page.getByTestId('sign-in-methods');
  }

  /**
   * A document load carries the fragment; a client-side navigation drops it.
   *
   * The fragment reaches the uploaded trace. It may: the link names one folder
   * of a vault the run cold-started, on a record store reachable only from
   * inside the job.
   */
  async open(url: URL): Promise<void> {
    await this.page.goto(url.toString());
    await expect(this.panel).toBeVisible();
  }

  /** Waits for the panel to report one state. */
  async expectState(state: string, timeout?: number): Promise<void> {
    await expect(this.panel).toHaveAttribute('data-state', state, { timeout });
  }

  /** Spends the link. The join needs this gesture; nothing joins on mount. */
  async join(): Promise<void> {
    await this.joinButton.click();
  }

  /** A join, or "open folder", lands on the shared folder in the vault browser. */
  async expectFolderOpened(timeout?: number): Promise<void> {
    await expect(this.page).toHaveURL(/\/files\/[0-9a-f]{32}$/, { timeout });
  }
}
