/**
 * Barrel export for all page objects.
 *
 * Provides a single import point for tests to access all page objects.
 *
 * @example
 * ```typescript
 * import { FileListPage, ConfirmDialogPage, LoginPage } from './page-objects';
 * ```
 */

// Base page objects
export { BasePage } from './base.page';
export { LoginPage } from './login.page';
// File browser page objects
export { FileListPage, ContextMenuPage, UploadZonePage } from './file-browser';

// Dialog page objects
export { ConfirmDialogPage, RenameDialogPage } from './dialogs';
