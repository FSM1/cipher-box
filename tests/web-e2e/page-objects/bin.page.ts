import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The `/bin` route: what this vault soft-deleted, and the restore or purge each
 * row offers.
 *
 * A `bin-row` carries the node id on `data-node`. `bin-unestablished` and `bin-empty` are distinct states: the first means no
 * bin index was read, the second means one was read and holds nothing.
 */
export class BinPage {
  constructor(readonly page: Page) {}

  get panel(): Locator {
    return this.page.getByTestId('bin-page');
  }

  get list(): Locator {
    return this.page.getByTestId('bin-list');
  }

  /** The index landed and holds nothing, as opposed to not having been read. */
  get empty(): Locator {
    return this.page.getByTestId('bin-empty');
  }

  get unestablished(): Locator {
    return this.page.getByTestId('bin-unestablished');
  }

  get error(): Locator {
    return this.page.getByTestId('bin-error');
  }

  /** The vault's own retention, which dates every expiry on the page. */
  get retention(): Locator {
    return this.page.getByTestId('bin-retention');
  }

  /**
   * Navigates through the sidebar, not the address bar: this suite's session is
   * in-memory, so a document load would land the tab back on the front door.
   */
  async open(): Promise<void> {
    await this.page.getByTestId('nav-item-bin').click();
    await expect(this.panel).toBeVisible();
  }

  /** Re-reads the bin index; a read reaches the record plane every time. */
  async readAgain(): Promise<void> {
    await this.page.getByTestId('bin-reload').click();
  }

  /**
   * Re-reads until `name` is gone. A restore and a purge are journaled ops, so
   * the published index changes only once the queue drains past them.
   */
  async gone(name: string): Promise<void> {
    await expect
      .poll(
        async () => {
          await this.readAgain();
          return this.row(name).count();
        },
        { timeout: 60_000 }
      )
      .toBe(0);
  }

  /**
   * One listed entry, picked by the accessible name its own controls carry. The
   * row's text would match a substring of a longer sibling's. The name is exact
   * because the row also holds `restore <name> into another folder`.
   */
  row(name: string): Locator {
    return this.page.getByTestId('bin-row').filter({
      has: this.page.getByRole('button', { name: `restore ${name}`, exact: true }),
    });
  }

  /** Puts the entry back where it was deleted from. */
  async restore(name: string): Promise<void> {
    await this.row(name).getByTestId('bin-restore').click();
  }

  /** Destroys the entry, through the confirmation the purge takes. */
  async purge(name: string): Promise<void> {
    await this.row(name).getByTestId('bin-purge').click();
    await this.page.getByTestId('purge-confirm').click();
  }
}
