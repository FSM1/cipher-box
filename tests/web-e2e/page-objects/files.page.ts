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

  get status(): Locator {
    return this.page.getByTestId('status-indicator');
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

  async open(name: string): Promise<void> {
    await this.row(name).dblclick();
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
    await dialog.getByTestId('folder-picker-entry').filter({ hasText: destination }).click();
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
    const downloads = Promise.all(
      Array.from({ length: count }, () => this.page.waitForEvent('download'))
    );
    await this.page.getByTestId('selection-download').click();
    return downloads;
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
