import { expect, type Download, type Locator, type Page } from '@playwright/test';

/** The vault browser route and the chrome around it. */
export class FilesPage {
  constructor(readonly page: Page) {}

  get browser(): Locator {
    return this.page.getByTestId('file-browser');
  }

  get emptyState(): Locator {
    return this.page.getByTestId('empty-state');
  }

  get breadcrumbs(): Locator {
    return this.page.getByTestId('breadcrumbs');
  }

  get newFolderButton(): Locator {
    return this.page.getByTestId('new-folder-button');
  }

  get uploadZone(): Locator {
    return this.page.getByTestId('upload-zone');
  }

  /** The notice a scope another vault shared renders in place of the writes. */
  get readOnlyNotice(): Locator {
    return this.page.getByTestId('read-only-scope');
  }

  /**
   * A read grant offers no write: the engine refuses one there, so the browser
   * must not present the gesture.
   */
  async readOnly(timeout = 10_000): Promise<void> {
    await expect(this.readOnlyNotice).toBeVisible({ timeout });
    await expect(this.newFolderButton).toHaveCount(0);
    await expect(this.uploadZone).toHaveCount(0);
  }

  get status(): Locator {
    return this.page.getByTestId('status-indicator');
  }

  /**
   * Waits until the listing carries no unpublished row — the hookless stand-in
   * for a drained queue, since the chrome marks a row until its write publishes.
   * A dead-lettered write fails here rather than at whatever read used it: its
   * row can leave the listing, which clears the mark too, so the notice is what
   * tells the two apart.
   */
  async published(): Promise<void> {
    await expect(this.browser.locator('.file-list-item-status--dead')).toHaveCount(0);
    await expect(this.browser.locator('.file-list-item-status')).toHaveCount(0, {
      timeout: 180_000,
    });
    await expect(this.page.getByTestId('dead-letter-notice')).toHaveCount(0);
  }

  async goto(): Promise<void> {
    await this.page.goto('/files');
  }

  /**
   * Navigates through the sidebar, not the address bar: this suite's session is
   * in-memory, so a document load would land the tab back on the front door.
   */
  async openFromSidebar(): Promise<void> {
    await this.page.getByTestId('nav-item-files').click();
    await expect(this.browser).toBeVisible();
  }

  /**
   * Opens the header menu and signs out. Hover, not click: the menu opens on
   * pointer entry and the trigger *toggles*, so a click races itself shut.
   */
  async signOut(): Promise<void> {
    await this.page.getByTestId('user-menu').hover();
    await this.page.getByTestId('logout-button').click();
  }

  /**
   * One listed row, picked by the accessible name its own controls carry. The
   * row's text would match a substring of a longer sibling's.
   */
  row(name: string): Locator {
    return this.page
      .getByTestId('file-list-item')
      .filter({ has: this.page.getByRole('checkbox', { name: `select ${name}`, exact: true }) });
  }

  /**
   * Opens a folder and waits for the listing of that folder to land. The trail
   * names the folder only once the engine has reported a view of it, and the
   * surfaces that take a write mount on that same view: a picker driven before
   * it lands belongs to the folder just left, and the file it takes is lost.
   */
  async open(name: string): Promise<void> {
    await this.row(name).dblclick();
    await expect(this.breadcrumbs.locator('[aria-current="page"]')).toHaveText(name);
  }

  /**
   * The size and modified cells one row paints. A child whose own record the
   * listing has not resolved yet paints `...` in both, so a caller that reads
   * them tells a converged row from a named one.
   */
  async cells(name: string): Promise<{ size: string; modified: string }> {
    const row = this.row(name);
    const [size, modified] = await Promise.all([
      row.locator('.file-list-item-size').innerText(),
      row.locator('.file-list-item-date').innerText(),
    ]);
    return { size: size.trim(), modified: modified.trim() };
  }

  /**
   * How the modified cell renders each of `timestamps`. That cell carries a
   * date at day granularity in the tab's own locale, so a window assertion
   * compares the labels of the window's bounds rather than a parsed time.
   */
  renderedDays(timestamps: number[]): Promise<string[]> {
    return this.page.evaluate(
      (millis) =>
        millis.map((value) =>
          new Intl.DateTimeFormat(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
          }).format(new Date(value))
        ),
      timestamps
    );
  }

  async createFolder(name: string): Promise<void> {
    await this.page.getByTestId('new-folder-button').click();
    const dialog = this.page.getByTestId('create-folder-dialog');
    await dialog.getByLabel('folder name').fill(name);
    await this.page.getByTestId('create-folder-confirm').click();
    await expect(dialog).toHaveCount(0);
  }

  async rename(name: string, newName: string): Promise<void> {
    await this.act(name, 'rename');
    const dialog = this.page.getByTestId('rename-dialog');
    await dialog.getByLabel('new name').fill(newName);
    await this.page.getByTestId('rename-confirm').click();
    await expect(dialog).toHaveCount(0);
  }

  /** Moves a row into a subfolder of the listing it is in. */
  async move(name: string, destination: string): Promise<void> {
    await this.act(name, 'move to...');
    await this.pickDestination(destination);
  }

  /** Walks the open move dialog onto `destination` and confirms it. */
  private async pickDestination(destination: string): Promise<void> {
    const dialog = this.page.getByTestId('move-dialog');
    // The entry's accessible name is the folder name alone, so an exact name
    // match cannot take a longer neighbour such as `docs-old` for `docs`.
    await dialog.getByRole('button', { name: destination, exact: true }).click();
    await expect(dialog.getByTestId('folder-picker-destination')).toHaveText(destination);
    await this.page.getByTestId('move-confirm').click();
    await expect(dialog).toHaveCount(0);
  }

  async remove(name: string): Promise<void> {
    await this.act(name, 'delete');
    const dialog = this.page.getByTestId('delete-dialog');
    await this.page.getByTestId('delete-confirm').click();
    await expect(dialog).toHaveCount(0);
  }

  /** Hands the picker one file, as a drop would. */
  async upload(name: string, bytes: Uint8Array): Promise<void> {
    await this.page.getByLabel('Choose files to upload').setInputFiles({
      name,
      mimeType: 'application/octet-stream',
      // Playwright's own payload type; the boundary is the only place a Buffer
      // is wanted, so callers stay on Uint8Array.
      buffer: Buffer.from(bytes),
    });
  }

  async preview(name: string): Promise<string> {
    await this.openPreview(name);
    const shown = this.page.getByTestId('preview-text');
    await expect(shown).toBeVisible();
    return (await shown.textContent()) ?? '';
  }

  /** The preview dialog's body, which carries the rendered surface per kind. */
  get previewDialog(): Locator {
    return this.page.getByTestId('file-preview-dialog');
  }

  /** Raises the preview on a row and leaves the dialog open. */
  async openPreview(name: string): Promise<void> {
    await this.act(name, 'preview');
    await expect(this.previewDialog).toBeVisible();
  }

  async closePreview(): Promise<void> {
    await this.page.keyboard.press('Escape');
    await expect(this.previewDialog).toHaveCount(0);
  }

  async save(name: string): Promise<Download> {
    const [download] = await Promise.all([
      this.page.waitForEvent('download'),
      this.act(name, 'download'),
    ]);
    return download;
  }

  /** The bar the listing raises over a non-empty selection. */
  get selectionBar(): Locator {
    return this.page.getByTestId('selection-action-bar');
  }

  get selectionCount(): Locator {
    return this.page.getByTestId('selection-count');
  }

  /** Adds one row to the selection, or takes it back out. */
  async select(name: string): Promise<void> {
    await this.page.getByRole('checkbox', { name: `select ${name}`, exact: true }).click();
  }

  /** Selects every row of the listing, or clears it when all are selected. */
  async selectAll(): Promise<void> {
    await this.page.getByTestId('select-all').click();
  }

  /**
   * Saves every selected file. The browser raises one download per file, in
   * listing order, so the caller says how many it expects.
   */
  async saveSelected(count: number): Promise<Download[]> {
    // One listener collecting `count` events, not `count` waiters: parallel
    // `waitForEvent` calls all settle on the first download, so a batch that
    // raised one save would still answer with `count` copies of it.
    const collected: Download[] = [];
    let enough = (): void => undefined;
    const done = new Promise<void>((resolve) => (enough = resolve));
    const collect = (download: Download): void => {
      collected.push(download);
      if (collected.length >= count) enough();
    };
    this.page.on('download', collect);
    try {
      await this.page.getByTestId('selection-download').click();
      await done;
    } finally {
      this.page.off('download', collect);
    }
    return collected;
  }

  /** Moves every selected row into `destination`. */
  async moveSelected(destination: string): Promise<void> {
    await this.page.getByTestId('selection-move').click();
    await this.pickDestination(destination);
  }

  /** Deletes every selected row, through the confirmation the batch takes. */
  async removeSelected(): Promise<void> {
    await this.page.getByTestId('selection-delete').click();
    const dialog = this.page.getByTestId('delete-dialog');
    await this.page.getByTestId('delete-confirm').click();
    await expect(dialog).toHaveCount(0);
  }

  /** Raises a row's action menu and picks one item off it. */
  private async act(name: string, item: string): Promise<void> {
    await this.page.getByRole('button', { name: `actions for ${name}`, exact: true }).click();
    await this.page
      .getByTestId('context-menu')
      .getByRole('menuitem', { name: item, exact: true })
      .click();
  }
}
