import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for DetailsDialog component.
 *
 * Used for viewing file/folder metadata (CIDs, encryption info, IPNS data).
 * Encapsulates dialog visibility, detail rows, copy buttons, and section headers.
 */
export class DetailsDialogPage {
  constructor(private readonly page: Page) {}

  /**
   * Get the dialog container.
   * DetailsDialog renders inside a Modal component with .details-rows content.
   */
  dialog(): Locator {
    return this.page.locator('.modal-container').filter({
      has: this.page.locator('.details-rows'),
    });
  }

  /**
   * Get the dialog title.
   * Returns "File Details" or "Folder Details".
   */
  title(): Locator {
    return this.dialog().locator('.modal-title');
  }

  /**
   * Get the close button.
   */
  closeButton(): Locator {
    return this.dialog().locator('.modal-close');
  }

  /**
   * Get all detail rows.
   */
  rows(): Locator {
    return this.dialog().locator('.details-row');
  }

  /**
   * Get a detail row by its label text.
   */
  rowByLabel(label: string): Locator {
    // Use exact text match to avoid "Name" matching "IPNS Name"
    return this.dialog()
      .locator('.details-row')
      .filter({
        has: this.page.locator('.details-label', { hasText: new RegExp(`^${label}$`, 'i') }),
      });
  }

  /**
   * Get the value element within a row identified by label.
   */
  valueByLabel(label: string): Locator {
    const row = this.rowByLabel(label);
    return row
      .locator('.details-value, .details-copyable-text, .details-type-badge, .details-loading')
      .first();
  }

  /**
   * Get the copy button within a copyable row.
   */
  copyButtonByLabel(label: string): Locator {
    return this.rowByLabel(label).locator('.details-copy-btn');
  }

  /**
   * Get all section headers (e.g., "// encryption", "// timestamps", "// ipns").
   */
  sectionHeaders(): Locator {
    return this.dialog().locator('.details-section-header');
  }

  /**
   * Get a specific section header by text content.
   */
  sectionHeader(text: string): Locator {
    return this.dialog().locator('.details-section-header', { hasText: text });
  }

  /**
   * Get the type badge element.
   */
  typeBadge(): Locator {
    return this.dialog().locator('.details-type-badge');
  }

  /**
   * Check if the dialog is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.dialog().isVisible();
  }

  /**
   * Wait for the dialog to open.
   */
  async waitForOpen(options?: { timeout?: number }): Promise<void> {
    await this.dialog().waitFor({ state: 'visible', ...options });
  }

  /**
   * Wait for the dialog to close.
   */
  async waitForClose(options?: { timeout?: number }): Promise<void> {
    await this.dialog().waitFor({ state: 'hidden', ...options });
  }

  /**
   * Close the dialog via the close button.
   */
  async close(): Promise<void> {
    await this.closeButton().click();
    await this.waitForClose();
  }

  /**
   * Get the dialog title text.
   */
  async getTitle(): Promise<string> {
    return (await this.title().textContent()) ?? '';
  }

  /**
   * Get the value text for a given label.
   */
  async getValueText(label: string): Promise<string> {
    return (await this.valueByLabel(label).textContent()) ?? '';
  }

  /**
   * Get all visible label texts from the detail rows.
   */
  async getVisibleLabels(): Promise<string[]> {
    const labels = this.dialog().locator('.details-label');
    const count = await labels.count();
    const result: string[] = [];
    for (let i = 0; i < count; i++) {
      const text = await labels.nth(i).textContent();
      if (text) result.push(text.trim());
    }
    return result;
  }

  /**
   * Get all visible section header texts.
   */
  async getVisibleSectionHeaders(): Promise<string[]> {
    const headers = this.sectionHeaders();
    const count = await headers.count();
    const result: string[] = [];
    for (let i = 0; i < count; i++) {
      const text = await headers.nth(i).textContent();
      if (text) result.push(text.trim());
    }
    return result;
  }

  /**
   * Check if a row has a copy button (i.e., contains a copyable value).
   */
  async hasCopyButton(label: string): Promise<boolean> {
    return await this.copyButtonByLabel(label).isVisible();
  }

  /**
   * Click the copy button for a given label.
   */
  async clickCopy(label: string): Promise<void> {
    await this.copyButtonByLabel(label).click();
  }

  /**
   * Check if the copy button shows "ok" (copied state).
   */
  async isCopied(label: string): Promise<boolean> {
    const btn = this.copyButtonByLabel(label);
    const text = await btn.textContent();
    return text?.trim() === 'ok';
  }

  /**
   * Check if a value is in redacted style (italic dim).
   */
  async isValueRedacted(label: string): Promise<boolean> {
    const row = this.rowByLabel(label);
    return await row.locator('.details-value--redacted').isVisible();
  }

  /**
   * Get the type badge text (e.g., "[FILE]" or "[DIR]").
   */
  async getTypeBadgeText(): Promise<string> {
    return (await this.typeBadge().textContent()) ?? '';
  }

  /**
   * Check if the type badge has the file variant.
   */
  async isFileBadge(): Promise<boolean> {
    return await this.dialog().locator('.details-type-badge--file').isVisible();
  }

  /**
   * Check if the type badge has the folder variant.
   */
  async isFolderBadge(): Promise<boolean> {
    return await this.dialog().locator('.details-type-badge--folder').isVisible();
  }
}
