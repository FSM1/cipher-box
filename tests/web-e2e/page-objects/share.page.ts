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

  /**
   * Reopens the dialog until `count` grant rows show: the owner's tick converts
   * a claim in the background, and the dialog reads the grants only when it opens.
   */
  async openUntilGranted(folder: string, count: number, timeout = 90_000): Promise<void> {
    await expect(async () => {
      if ((await this.dialog.count()) > 0) await this.close();
      await this.open(folder);
      await expect(this.grantRows).toHaveCount(count);
    }).toPass({ timeout });
  }

  /** The permission badge one grant row carries. */
  get permission(): Locator {
    return this.page.getByTestId('share-grant-permission');
  }

  /** Cuts one recipient's grant. */
  get revoke(): Locator {
    return this.page.getByTestId('share-revoke');
  }

  /** Takes a write grant back down to read. There is no way back up. */
  get downgrade(): Locator {
    return this.page.getByTestId('share-downgrade');
  }

  /** Clicks the downgrade and waits for the engine's re-read to report `read`. */
  async downgradeToRead(timeout = 60_000): Promise<void> {
    await this.downgrade.click();
    await expect(this.permission).toHaveText('read', { timeout });
  }

  /** What a grant or a mint would carry: `read` or `write`. */
  get permissionChoice(): Locator {
    return this.page.getByLabel('permission');
  }

  /** The imported contacts this member can grant to. */
  get recipientChoice(): Locator {
    return this.page.getByLabel('contact');
  }

  /**
   * Imports `code` and grants the folder to it. The picker lists contacts by
   * their identity key, so the freshly imported one is the only entry beside
   * the placeholder.
   */
  async grantTo(code: string, permission: 'read' | 'write'): Promise<void> {
    await this.importContact(code);

    await this.recipientChoice.selectOption({ index: 1 });
    await this.permissionChoice.selectOption(permission);
    await this.grantButton.click();
    // A grant re-wraps the scope key and publishes it, so against a real record
    // plane the row lands well after the click.
    await expect(this.grantRows).toHaveCount(1, { timeout: 180_000 });
    await expect(this.permission).toHaveText(permission);
  }

  /**
   * Imports `code` into this member's contact book, without granting. A grant
   * is delivered over the mailbox, and the recipient drops an item whose sender
   * its own book does not anchor, so both sides import before either grants.
   */
  async importContact(code: string): Promise<void> {
    await this.openImport();
    await this.contactCode.fill(code);
    await this.importConfirm.click();
    await expect(this.importForm).toHaveCount(0);
  }

  /** This member's own code, read off the import step it is shown beside. */
  async readOwnContactCode(): Promise<string> {
    await this.openImport();
    const shown = await this.ownContactCode.locator('.details-copyable-text').textContent();
    expect(shown, 'the import step showed no contact code').not.toBeNull();
    await this.cancelImport();
    return shown!.trim();
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
    // A mint publishes the link's own record, so it lands well after the click
    // against a real record plane.
    await expect(this.mintedLink).toBeVisible({ timeout: 180_000 });
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

  /**
   * The paste field. Exact, because the step also offers this member's own code
   * and `copy your contact code` answers a loose match on the same words.
   */
  get contactCode(): Locator {
    return this.page.getByLabel('their contact code', { exact: true });
  }

  /** The code this member hands over, which the step shows beside the paste. */
  get ownContactCode(): Locator {
    return this.page.getByTestId('own-contact-code');
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
