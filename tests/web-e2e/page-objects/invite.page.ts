import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The `/invite` claim route. The panel carries the claim's own progress on
 * `data-state` — `checking`, `waiting`, `ready`, `noLink`, `claiming`,
 * `claimed` or `refused` — so a spec asserts the state, not the copy.
 */
export class InvitePage {
  constructor(readonly page: Page) {}

  get panel(): Locator {
    return this.page.getByTestId('invite-claim');
  }

  /** Which account the claim would be spent under. */
  get account(): Locator {
    return this.page.getByTestId('invite-account');
  }

  get confirm(): Locator {
    return this.page.getByTestId('invite-claim-confirm');
  }

  get recheck(): Locator {
    return this.page.getByTestId('invite-recheck');
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

  /** Waits for the panel to report one claim state. */
  async expectState(state: string): Promise<void> {
    await expect(this.panel).toHaveAttribute('data-state', state);
  }

  /** Spends the link. The claim needs this gesture; nothing claims on mount. */
  async claim(): Promise<void> {
    await this.confirm.click();
  }
}
