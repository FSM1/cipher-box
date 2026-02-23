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

  // ============================================
  // Version History Locators & Methods
  // ============================================

  /**
   * Get the version history section container.
   */
  versionSection(): Locator {
    return this.dialog().locator('.details-version-section');
  }

  /**
   * Get all version entry elements within the version section.
   */
  versionEntries(): Locator {
    return this.versionSection().locator('.details-version-entry');
  }

  /**
   * Get a specific version entry by index (0-based, 0 = newest displayed).
   */
  versionEntry(index: number): Locator {
    return this.versionEntries().nth(index);
  }

  /**
   * Get the version number element within a version entry.
   */
  versionNumber(index: number): Locator {
    return this.versionEntry(index).locator('.details-version-number');
  }

  /**
   * Get the version actions container within a version entry.
   */
  versionActions(index: number): Locator {
    return this.versionEntry(index).locator('.details-version-actions');
  }

  /**
   * Get the download button for a version entry.
   */
  versionDownloadBtn(index: number): Locator {
    return this.versionEntry(index).locator('button', { hasText: /^dl$/i });
  }

  /**
   * Get the restore button for a version entry.
   */
  versionRestoreBtn(index: number): Locator {
    return this.versionEntry(index).locator('button', { hasText: /^restore$/i });
  }

  /**
   * Get the delete button for a version entry.
   */
  versionDeleteBtn(index: number): Locator {
    return this.versionEntry(index).locator('button', { hasText: /^rm$/i });
  }

  /**
   * Get the inline confirm dialog within the version section.
   */
  versionConfirm(): Locator {
    return this.dialog().locator('.details-version-confirm');
  }

  /**
   * Get the confirm (yes) button in the inline confirm dialog.
   */
  versionConfirmYes(): Locator {
    return this.versionConfirm().locator('.details-version-confirm-btn--yes');
  }

  /**
   * Get the cancel (no) button in the inline confirm dialog.
   */
  versionConfirmNo(): Locator {
    return this.versionConfirm().locator('.details-version-confirm-btn--no');
  }

  /**
   * Get the version error element.
   */
  versionError(): Locator {
    return this.dialog().locator('.details-version-error');
  }

  /**
   * Check if the version history section is visible.
   */
  async isVersionSectionVisible(): Promise<boolean> {
    return await this.versionSection().isVisible();
  }

  /**
   * Get the count of version entries.
   */
  async getVersionCount(): Promise<number> {
    return await this.versionEntries().count();
  }

  /**
   * Get the version number text for a specific entry (e.g. "v1", "v2").
   */
  async getVersionNumberText(index: number): Promise<string> {
    return (await this.versionNumber(index).textContent()) ?? '';
  }

  /**
   * Get the version size text for a specific entry.
   */
  async getVersionSizeText(index: number): Promise<string> {
    return (await this.versionEntry(index).locator('.details-version-size').textContent()) ?? '';
  }

  /**
   * Click the download button for a version entry.
   */
  async clickVersionDownload(index: number): Promise<void> {
    await this.versionDownloadBtn(index).click();
  }

  /**
   * Click the restore button for a version entry (opens inline confirm).
   */
  async clickVersionRestore(index: number): Promise<void> {
    await this.versionRestoreBtn(index).click();
  }

  /**
   * Click the delete button for a version entry (opens inline confirm).
   */
  async clickVersionDelete(index: number): Promise<void> {
    await this.versionDeleteBtn(index).click();
  }

  /**
   * Check if the inline confirm dialog is visible.
   */
  async isVersionConfirmVisible(): Promise<boolean> {
    return await this.versionConfirm().isVisible();
  }

  /**
   * Click the confirm button in the inline confirm dialog.
   */
  async confirmVersionAction(): Promise<void> {
    await this.versionConfirmYes().click();
  }

  /**
   * Click the cancel button in the inline confirm dialog.
   */
  async cancelVersionAction(): Promise<void> {
    await this.versionConfirmNo().click();
  }

  /**
   * Get the version error text if visible, null otherwise.
   */
  async getVersionErrorText(): Promise<string | null> {
    const isVisible = await this.versionError().isVisible();
    if (!isVisible) return null;
    return (await this.versionError().textContent()) ?? null;
  }

  /**
   * Wait for the version history section to appear.
   */
  async waitForVersionSection(options?: { timeout?: number }): Promise<void> {
    await this.versionSection().waitFor({ state: 'visible', ...options });
  }
}
