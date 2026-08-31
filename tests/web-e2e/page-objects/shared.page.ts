import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The `/shared` route: the shares this vault accepted and the engine's standing
 * on each.
 *
 * A `shared-row` carries the scope node id on `data-scope`. Its `shared-standing`
 * carries the engine's own class name on `data-resolution` — `granted`,
 * `revocation-signal`, `unresolvable`, `epoch-lag`, or `none` where no pass has
 * answered — and the rendered weight on `data-tone`. Assert those, not the copy.
 */
export class SharedPage {
  constructor(readonly page: Page) {}

  get panel(): Locator {
    return this.page.getByTestId('shared-page');
  }

  get list(): Locator {
    return this.page.getByTestId('shared-list');
  }

  /** The list has landed and holds nothing, as opposed to not having been read. */
  get empty(): Locator {
    return this.page.getByTestId('shared-empty');
  }

  get error(): Locator {
    return this.page.getByTestId('shared-error');
  }

  /** The warning surface the shell mounts; a trust warning lands here. */
  get warnings(): Locator {
    return this.page.getByTestId('notification-notice');
  }

  /**
   * Navigates through the sidebar, not the address bar: this suite's session is
   * in-memory, so a document load would land the tab back on the front door.
   */
  async open(): Promise<void> {
    await this.page.getByTestId('nav-item-shared').click();
    await expect(this.panel).toBeVisible();
  }

  /**
   * Re-reads the accepted list. The verdicts move on the engine's focus tick,
   * so a spec that changed a grant refreshes first and then re-reads here.
   */
  async readAgain(): Promise<void> {
    await this.page.getByTestId('shared-reload').click();
  }
}
