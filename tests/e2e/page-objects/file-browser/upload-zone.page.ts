import { type Page, type Locator } from '@playwright/test';

/**
 * Page object for UploadZone component interactions.
 *
 * Encapsulates file upload functionality via both:
 * - Click to upload (file input)
 * - Drag and drop (not reliable in tests, use setInputFiles instead)
 */
export class UploadZonePage {
  constructor(private readonly page: Page) {}

  /**
   * Get the upload zone dropzone area.
   */
  dropzone(): Locator {
    return this.page.locator('.upload-zone');
  }

  /**
   * Get the hidden file input element (used by react-dropzone).
   * Uses first() as there may be multiple upload zones on the page.
   */
  private fileInput(): Locator {
    return this.page.locator('.upload-zone input[type="file"]').first();
  }

  /**
   * Get the upload zone error message if displayed.
   */
  errorMessage(): Locator {
    return this.page.locator('.upload-zone-error');
  }

  /**
   * Upload a single file via the file input.
   * This is the most reliable method for Playwright tests.
   *
   * @param filePath - Absolute or relative path to the file
   */
  async uploadFile(filePath: string): Promise<void> {
    await this.fileInput().setInputFiles(filePath);
  }

  /**
   * Upload multiple files via the file input.
   *
   * @param filePaths - Array of file paths
   */
  async uploadFiles(filePaths: string[]): Promise<void> {
    await this.fileInput().setInputFiles(filePaths);
  }

  /**
   * Click the dropzone to trigger the file picker dialog.
   * Note: This won't open an actual dialog in headless tests.
   * Use uploadFile() or uploadFiles() instead for actual file upload.
   */
  async clickToUpload(): Promise<void> {
    await this.dropzone().click();
  }

  /**
   * Check if the dropzone is in uploading state.
   */
  async isUploading(): Promise<boolean> {
    const className = await this.dropzone().getAttribute('class');
    return className?.includes('upload-zone-uploading') ?? false;
  }

  /**
   * Check if an error message is displayed.
   */
  async hasError(): Promise<boolean> {
    return await this.errorMessage().isVisible();
  }

  /**
   * Get the error message text if displayed.
   */
  async getErrorText(): Promise<string | null> {
    const isVisible = await this.hasError();
    if (!isVisible) {
      return null;
    }
    return await this.errorMessage().textContent();
  }

  /**
   * Dismiss the error message by clicking the dismiss button.
   */
  async dismissError(): Promise<void> {
    await this.errorMessage().locator('.upload-zone-error-dismiss').click();
  }

  /**
   * Wait for upload to complete.
   * Waits for the uploading state to clear.
   */
  async waitForUploadComplete(options?: { timeout?: number }): Promise<void> {
    await this.page.waitForFunction(() => {
      const zone = document.querySelector('.upload-zone');
      return zone && !zone.classList.contains('upload-zone-uploading');
    }, options);
  }

  /**
   * Get the upload zone text.
   * Returns "Uploading...", "Drop files here", or "Drag files here or click to upload".
   */
  async getZoneText(): Promise<string> {
    return (await this.dropzone().locator('.upload-zone-text').textContent()) ?? '';
  }

  /**
   * Simulate drag-drop file upload.
   * Note: This is more complex and less reliable than setInputFiles.
   * Prefer uploadFile() for tests.
   *
   * @param filePath - Path to file to upload
   */
  async dragDropFile(filePath: string): Promise<void> {
    // For Playwright, we can't truly simulate drag-drop from OS.
    // Instead, we'll use the file input method which is more reliable.
    // This method exists for API compatibility but delegates to uploadFile.
    await this.uploadFile(filePath);
  }
}
