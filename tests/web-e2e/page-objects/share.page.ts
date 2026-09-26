import { expect, type Locator, type Page } from '@playwright/test';

const DAY_MS = 86_400_000;

/** What a mint carries beyond its lifetime; an absent field keeps the dialog's default. */
export interface LinkTerms {
  permission?: 'read' | 'write';
  /** The owner's label, which the preview leads with once it verifies. */
  ownerName?: string;
}

/**
 * The share dialog a folder row raises: the people table, the link row and
 * its chips, and the contact-code path under "advanced".
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

  /** One chip per link the scope carries, this session's mint or not. */
  get linkChips(): Locator {
    return this.page.getByTestId('share-link-chip');
  }

  /** The chips of the links that grant `permission`. */
  linkChipsFor(permission: 'read' | 'write'): Locator {
    const label = permission === 'write' ? 'edit' : 'view';
    return this.linkChips.filter({
      has: this.page.getByTestId('share-link-summary').filter({ hasText: `${label} · ` }),
    });
  }

  /** Cuts the first link, through the confirmation its chip raises. */
  async revokeFirstLink(): Promise<void> {
    await this.askToRevoke(this.linkChips.first());
    await this.confirmLinkRevoke();
  }

  /**
   * The confirmation's "also remove the people who joined through it" choice,
   * which cuts them with the link (ADR 0025 D1).
   */
  get removeGrantees(): Locator {
    return this.page.getByTestId('share-link-remove-grantees');
  }

  /** Raises the revoke confirmation of the link `chip` names. */
  async askToRevoke(chip: Locator): Promise<void> {
    await chip.getByTestId('share-revoke-link').click();
    await expect(this.page.getByTestId('share-link-revoke-prompt')).toBeVisible();
  }

  /** Confirms the raised link revoke and waits for the cut to land. */
  async confirmLinkRevoke(): Promise<void> {
    await this.page.getByTestId('share-link-revoke-confirm').click();
    await expect(this.page.getByTestId('share-link-revoke-prompt')).toHaveCount(0, {
      timeout: 180_000,
    });
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
   * Opens the dialog until `count` grant rows show. The owner's tick and each
   * opening convert the claims that wait on the folder's links, and the dialog
   * reads the grants only when it opens.
   */
  async openUntilGranted(folder: string, count: number, timeout = 180_000): Promise<void> {
    await this.openUntil(folder, this.grantRows, count, timeout);
  }

  /**
   * Opens the dialog until `count` link chips show. An owner device's own
   * tick and the sweep of another device move the links, and the dialog reads
   * them only when it opens.
   */
  async openUntilLinks(folder: string, count: number, timeout = 180_000): Promise<void> {
    await this.openUntil(folder, this.linkChips, count, timeout);
  }

  private async openUntil(
    folder: string,
    rows: Locator,
    count: number,
    timeout: number
  ): Promise<void> {
    await expect(async () => {
      if ((await this.dialog.count()) > 0) await this.close();
      await this.open(folder);
      await expect(rows).toHaveCount(count, { timeout: 30_000 });
    }).toPass({ timeout });
  }

  /** The access control one grant row carries; its value is `read` or `write`. */
  get permission(): Locator {
    return this.page.getByTestId('share-grant-permission');
  }

  /** Cuts the one recipient's grant, through the confirmation the row raises. */
  async revokeGrantee(): Promise<void> {
    await this.page.getByTestId('share-revoke').click();
    await this.page.getByTestId('share-revoke-confirm').click();
  }

  /** Takes a write grant down to read and waits for the engine's re-read to report it. */
  async downgradeToRead(timeout = 60_000): Promise<void> {
    await this.permission.selectOption('read');
    await expect(this.permission).toHaveValue('read', { timeout });
    await expect(this.permission).toBeEnabled({ timeout });
  }

  /** What a minted link would carry: `read` or `write`. */
  get permissionChoice(): Locator {
    return this.page.getByLabel('link permission');
  }

  /** What a contact grant would carry: `read` or `write`. */
  get grantPermissionChoice(): Locator {
    return this.page.getByLabel('contact permission');
  }

  /** The imported contacts this member can grant to. */
  get recipientChoice(): Locator {
    return this.page.getByLabel('contact', { exact: true });
  }

  /** Unfolds the contact-code path, which the dialog keeps collapsed. */
  async expandAdvanced(): Promise<void> {
    const advanced = this.page.getByTestId('share-advanced');
    if ((await advanced.getAttribute('open')) === null) {
      await advanced.locator('summary').click();
    }
  }

  /**
   * Imports `code` and grants the folder to it. The picker lists contacts by
   * their identity key, so the freshly imported one is the only entry beside
   * the placeholder.
   */
  async grantTo(code: string, permission: 'read' | 'write'): Promise<void> {
    await this.importContact(code);

    await this.expandAdvanced();
    await this.recipientChoice.selectOption({ index: 1 });
    await this.grantPermissionChoice.selectOption(permission);
    await this.grantButton.click();
    // A grant re-wraps the scope key and publishes it, so against a real record
    // plane the row lands well after the click.
    await expect(this.grantRows).toHaveCount(1, { timeout: 180_000 });
    await expect(this.permission).toHaveValue(permission);
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
  async mintLink(lifetime?: string, terms: LinkTerms = {}): Promise<URL> {
    if (lifetime !== undefined) {
      await this.page.getByLabel('link expires').selectOption(lifetime);
    }
    if (terms.permission !== undefined) {
      await this.permissionChoice.selectOption(terms.permission);
    }
    if (terms.ownerName !== undefined) {
      await this.page.getByTestId('share-owner-name').fill(terms.ownerName);
    }
    await this.mintButton.click();
    // A mint publishes the link's own record, so it lands well after the click
    // against a real record plane.
    await expect(this.mintedLink).toBeVisible({ timeout: 180_000 });
    const shown = await this.mintedLink.locator('.details-copyable-text').textContent();
    expect(shown, 'the dialog showed no minted link').not.toBeNull();
    return new URL(shown!);
  }

  /**
   * Mints a link whose deadline falls `inMs` after the click, which may be
   * negative. The dialog offers days, so the tab's `Date.now` runs back by the
   * shortest lifetime less `inMs` for the mint. The engine reads its own clock
   * in its worker, which does not move.
   */
  async mintExpiringIn(inMs: number): Promise<void> {
    await this.page.evaluate(
      (by) => {
        const real = Date.now;
        Date.now = () => real() + by;
        (window as unknown as { restoreNow: () => void }).restoreNow = () => {
          Date.now = real;
        };
      },
      inMs - 7 * DAY_MS
    );
    try {
      await this.mintLink('7 days');
    } finally {
      await this.page.evaluate(() =>
        (window as unknown as { restoreNow: () => void }).restoreNow()
      );
    }
  }

  /** Steps into the contact import, which replaces the dialog's body. */
  async openImport(): Promise<void> {
    await this.expandAdvanced();
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
