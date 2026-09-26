import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The `/shared` route: the shares this vault accepted and the engine's standing
 * on each.
 *
 * A `shared-row` carries the scope node id on `data-scope`, and `data-via-link`
 * is `true` where the vault holds the share through a link's keys rather than a
 * personal grant. Its `shared-standing`
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

  get rows(): Locator {
    return this.page.getByTestId('shared-row');
  }

  /**
   * Re-reads until the one accepted share reports `resolution`. The verdict
   * moves on the engine's sync pass, so each turn nudges that pass as well as
   * the list.
   */
  async awaitStanding(resolution: string, timeout = 60_000): Promise<void> {
    await this.awaitRow(
      async () => {
        if ((await this.rows.count()) !== 1) return 'no row';
        return this.rows.getByTestId('shared-standing').getAttribute('data-resolution');
      },
      resolution,
      { timeout, nudge: true, intervals: [5_000] }
    );
  }

  /**
   * Re-reads until the one accepted share reports `permission`. The committed
   * permission moves on the engine's sync pass, so each turn nudges that pass
   * as well as the list.
   */
  async awaitPermission(permission: string, timeout = 60_000): Promise<void> {
    await this.awaitRow(
      async () => {
        if ((await this.rows.count()) !== 1) return 'no row';
        return this.rows.getByTestId('shared-permission').textContent();
      },
      permission,
      { timeout, nudge: true, intervals: [5_000] }
    );
  }

  /**
   * Re-reads the list, and nothing else, until the row for `scope` reports
   * `resolution`. A manual refresh answers at its read legs, ahead of the
   * share legs of the same pass, so the verdict that pass records can land
   * after the refresh returns.
   */
  async readStanding(scope: string, resolution: string, timeout = 10_000): Promise<void> {
    await this.awaitRow(
      async () => {
        const standing = this.row(scope).getByTestId('shared-standing');
        if ((await standing.count()) !== 1) return 'no row';
        return standing.getAttribute('data-resolution');
      },
      resolution,
      { timeout, nudge: false, intervals: [250] }
    );
  }

  /**
   * Polls `read` against `expected`, one list re-read per turn. A verdict moves
   * on the engine's sync pass, which `nudge` forces alongside the re-read.
   */
  private async awaitRow(
    read: () => Promise<string | null>,
    expected: string,
    { timeout, nudge, intervals }: { timeout: number; nudge: boolean; intervals: number[] }
  ): Promise<void> {
    await expect
      .poll(
        async () => {
          if (nudge) await this.page.getByTestId('status-indicator').click();
          await this.readAgain();
          return read();
        },
        { timeout, intervals }
      )
      .toBe(expected);
  }

  /**
   * How the row for `scope` stands on one re-read of the list: `gone`, or its
   * resolution and whether the vault holds it through a link.
   */
  async standingOf(scope: string): Promise<string> {
    await this.readAgain();
    const row = this.row(scope);
    if ((await row.count()) === 0) return 'gone';
    const resolution = await row.getByTestId('shared-standing').getAttribute('data-resolution');
    return `${resolution} via-link=${await row.getAttribute('data-via-link')}`;
  }

  /** The row for the scope root `scope`, as lowercase hex. */
  row(scope: string): Locator {
    return this.page.locator(`[data-testid="shared-row"][data-scope="${scope}"]`);
  }

  /**
   * Opens a received share. The scope root is the handle a browse opens under,
   * so this lands on `/files/<scope>` in the one vault browser — never a second
   * one.
   */
  async openShare(scope: string): Promise<void> {
    await this.row(scope).getByTestId('shared-open').click();
  }
}
