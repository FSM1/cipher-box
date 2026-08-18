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
    const dialog = this.page.getByTestId('move-dialog');
    await dialog.getByTestId('move-dialog-folder').filter({ hasText: destination }).click();
    await expect(dialog.getByTestId('move-dialog-destination')).toHaveText(destination);
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
    await this.act(name, 'preview');
    const shown = this.page.getByTestId('preview-text');
    await expect(shown).toBeVisible();
    return (await shown.textContent()) ?? '';
  }

  /**
   * Saves a listed file to disk through the row's own action, and hands back
   * the transfer the browser started.
   */
  async save(name: string): Promise<Download> {
    const [download] = await Promise.all([
      this.page.waitForEvent('download'),
      this.act(name, 'download'),
    ]);
    return download;
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
