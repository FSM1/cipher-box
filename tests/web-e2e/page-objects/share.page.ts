import { expect, type Locator, type Page } from '@playwright/test';

/**
 * The share dialog a folder row raises: the grant list, the contact import
 * step, and the invite-link panel.
 *
 * Every surface here is the engine's own read — the dialog re-reads after each
 * command rather than mirroring what it sent — so a wait on a row or a panel is
 * a wait on the engine, not on an optimistic render.
 */
export class SharePage {
  constructor(readonly page: Page) {}

  get dialog(): Locator {
    return this.page.getByTestId('share-dialog');
  }

  /** The dialog's single refusal surface: the engine's words, verbatim. */
  get error(): Locator {
    return this.page.getByTestId('dialog-error');
  }

  get grantRows(): Locator {
    return this.page.getByTestId('share-grant-row');
  }

  get noGrants(): Locator {
    return this.page.getByTestId('share-no-grants');
  }

  /** No read reached the folder, which is not the same as nothing granted. */
  get standingUnknown(): Locator {
    return this.page.getByTestId('share-standing-unknown');
  }

  get noContacts(): Locator {
    return this.page.getByTestId('share-no-contacts');
  }

  get grantButton(): Locator {
    return this.page.getByTestId('share-grant');
  }

  get mintButton(): Locator {
    return this.page.getByTestId('share-mint-link');
  }

  /**
   * The two refusals the engine returns in place of an offer. Each carries the
   * check that refused on `data-check`; assert that, not the copy.
   */
  get noGrant(): Locator {
    return this.page.getByTestId('share-no-grant');
  }

  get noMint(): Locator {
    return this.page.getByTestId('share-no-mint');
  }

  /** The panel a scope that already carries a link shows in the mint's place. */
  get liveLink(): Locator {
    return this.page.getByTestId('share-live-link');
  }

  get liveLinkExpiry(): Locator {
    return this.page.getByTestId('share-live-link-expiry');
  }

  get convertClaimsButton(): Locator {
    return this.page.getByTestId('share-convert-claims');
  }

  get revokeLinkButton(): Locator {
    return this.page.getByTestId('share-revoke-link');
  }

  /** The just-minted link, shown once and only to the tab that minted it. */
  get mintedLink(): Locator {
    return this.page.getByTestId('invite-link');
  }

  get bearerNote(): Locator {
    return this.page.getByTestId('invite-link-bearer');
  }

  get closeButton(): Locator {
    return this.page.getByTestId('share-close');
  }

  /** The modal's dismissal control, which a shown link holds shut. */
  get dismiss(): Locator {
    return this.page.getByLabel('close');
  }

  /** Raises the dialog from a folder row's action menu. */
  async open(folder: string): Promise<void> {
    await this.page.getByRole('button', { name: `actions for ${folder}`, exact: true }).click();
    await this.page
      .getByTestId('context-menu')
      .getByRole('menuitem', { name: 'share...', exact: true })
      .click();
    await expect(this.dialog).toBeVisible();
  }

  async close(): Promise<void> {
    await this.closeButton.click();
    await expect(this.dialog).toHaveCount(0);
  }

  /** The permission badge one grant row carries. */
  get permission(): Locator {
    return this.page.getByTestId('share-grant-permission');
  }

  /**
   * Mints a link and returns the URL the dialog shows. The link is shown once,
   * so the caller keeps it.
   */
  async mintLink(lifetime?: string): Promise<URL> {
    if (lifetime !== undefined) {
      await this.page.getByLabel('link expires').selectOption(lifetime);
    }
    await this.mintButton.click();
    await expect(this.mintedLink).toBeVisible();
    const shown = await this.mintedLink.locator('.details-copyable-text').textContent();
    expect(shown, 'the dialog showed no minted link').not.toBeNull();
    return new URL(shown!);
  }

  /** Steps into the contact import, which replaces the dialog's body. */
  async openImport(): Promise<void> {
    await this.page.getByTestId('share-import-contact').click();
    await expect(this.importForm).toBeVisible();
  }

  get importForm(): Locator {
    return this.page.getByTestId('import-contact-form');
  }

  get contactCode(): Locator {
    return this.page.getByLabel('contact code');
  }

  get importUnreadable(): Locator {
    return this.page.getByTestId('import-contact-unreadable');
  }

  get importConfirm(): Locator {
    return this.page.getByTestId('import-contact-confirm');
  }

  /** Leaves the import step, which retires the refusal it drew. */
  async cancelImport(): Promise<void> {
    await this.page.getByTestId('import-contact-cancel').click();
    await expect(this.dialog).toBeVisible();
  }
}
