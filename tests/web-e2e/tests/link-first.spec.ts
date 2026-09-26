/**
 * The link-first flow across two owner devices (ADR 0023-0028): device A mints,
 * a holder reads at once, and device B converts the claim on its own tick.
 *
 * Each device is a browser context of its own over one held login secret
 * (`devices.ts`). A device that must not act goes offline, so each conversion,
 * cut and sweep below has exactly one owner device that can run it. The step
 * numbers are the steps of the link-first flow in `tests/web-e2e/README.md`.
 */

import type { Page } from '@playwright/test';
import { Device, freshLogin, type Login, type Tab } from '../devices';
import { expect, test as base } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import type { InvitePage } from '../page-objects/invite.page';
import { SharedPage, type RowStanding } from '../page-objects/shared.page';
import { VaultPage } from '../page-objects/vault.page';
import { claimHere } from '../sharing';
import { nodeOf, refreshedUntil } from '../vault';

const FOLDER = 'link-first';
const NOTE = 'notes.txt';
const SUBFOLDER = 'photos';
const OWNER_NAME = 'dana';
const WRITTEN = 'from-the-writer.bin';
const AFTER_REKEY = 'after-the-rekey.txt';

/** The CI profile ticks every second, so a `/shared` verdict moves within a few. */
const PASS = { timeout: 60_000, intervals: [1_000] };

const heldByLink = (row: RowStanding) => row !== 'gone' && row.viaLink;
const granted = (row: RowStanding) =>
  row !== 'gone' && row.resolution === 'granted' && !row.viaLink;
const revoked = (row: RowStanding) => row !== 'gone' && row.resolution === 'revocation-signal';

/** Opens a device the test closes when it ends; a fresh account without `login`. */
type OpenDevice = (login?: Login) => Promise<Device>;

const test = base.extend<{ device: OpenDevice }>({
  device: async ({ browser }, use) => {
    const opened: Device[] = [];
    await use(async (login = freshLogin()) => {
      const device = await Device.open(browser, login);
      opened.push(device);
      return device;
    });
    for (const device of opened) await device.close();
  },
});

/** The two owner devices, the folder they share, and the holder of the read link. */
interface Flow {
  readonly a: Device;
  readonly b: Device;
  /** Device B's tab, online since it converted the read claim. */
  readonly bTab: Tab;
  readonly scope: string;
  readonly reader: Device;
  readonly readerPage: Page;
}

/** The claims `tab`'s engine converted on `scope`, by the events it emitted. */
async function joins(tab: Tab, scope: string): Promise<number> {
  const events = await tab.vault.events();
  return events.filter((event) => event.kind === 'granteeJoined' && event.scopeRoot === scope)
    .length;
}

/** Waits until `tab`'s engine converted one claim on `scope` past `before`. */
async function converted(tab: Tab, scope: string, before: number): Promise<void> {
  await expect
    .poll(() => joins(tab, scope), { timeout: 60_000, intervals: [1_000] })
    .toBe(before + 1);
}

/** Spends `link` on `holder`'s page under `name`, and lands on the shared folder. */
async function holderJoins(
  holder: Device,
  link: URL,
  name: string,
  beforeJoin?: (invite: InvitePage) => Promise<void>
): Promise<Page> {
  const page = await holder.page();
  await claimHere(page, link, {
    account: holder.login.accountId,
    start: () => holder.signIn(page),
    name,
    beforeJoin,
  });
  return page;
}

/** Steps 1-3: A mints, the holder reads at once, and B converts the claim on its tick. */
async function readLinkOverTwoDevices(device: OpenDevice): Promise<Flow> {
  const owner = freshLogin();
  const [a, b, reader] = await Promise.all([device(owner), device(owner), device()]);

  const { scope, link } =
    await test.step('1. device A mints a read link with the owner name on a folder of two entries', async () => {
      const { files, vault, share } = await a.online();
      await files.createFolder(FOLDER);
      const scope = nodeOf((await vault.settled()).view, FOLDER);
      await files.open(FOLDER);
      await files.upload(NOTE, new TextEncoder().encode('read before any conversion'));
      await expect(files.row(NOTE)).toBeVisible();
      await files.createFolder(SUBFOLDER);
      await expect(files.row(SUBFOLDER)).toBeVisible();
      await files.published();
      await files.openFromSidebar();

      await share.open(FOLDER);
      const link = await share.mintLink({ ownerName: OWNER_NAME });
      await share.close();
      await a.offline();
      return { scope, link };
    });

  const readerPage =
    await test.step('2. the holder previews owner and folder, joins, and reads both entries at once', async () => {
      const page = await holderJoins(reader, link, 'reader', async (invite) => {
        await expect(invite.headline).toHaveText(`${OWNER_NAME} shared ${FOLDER} with you`);
        await expect(invite.entries).toHaveCount(2);
      });
      const files = new FilesPage(page);
      await expect(files.row(NOTE)).toBeVisible({ timeout: 60_000 });
      await expect(files.row(SUBFOLDER)).toBeVisible();
      // ADR 0024: the holder reads through the link's keys.
      await new SharedPage(page).awaitStandingOf(scope, heldByLink, PASS);
      return page;
    });

  const bTab =
    await test.step("3. device B converts the claim on its tick, and the holder's row turns to a grant", async () => {
      const tab = await b.online();
      await converted(tab, scope, 0);

      await tab.share.openUntilGranted(FOLDER, 1);
      await expect(tab.share.grantRows).toContainText('reader');
      await expect(tab.share.grantRows.getByTestId('share-got-in')).toHaveText('via link');
      await expect(tab.share.permission).toHaveValue('read');
      await tab.share.close();

      await new SharedPage(readerPage).awaitStandingOf(scope, granted, PASS);
      return tab;
    });

  return { a, b, bTab, scope, reader, readerPage };
}

/**
 * Step 4's first half: A mints a write link and goes offline, a second holder
 * joins it, and B converts the claim.
 */
async function writeLinkConvertedOnB(flow: Flow, device: OpenDevice): Promise<Page> {
  const aTab = await flow.a.online();
  await aTab.share.open(FOLDER);
  const link = await aTab.share.mintLink({ permission: 'write' });
  await aTab.share.close();
  await flow.a.offline();

  const writer = await device();
  const before = await joins(flow.bTab, flow.scope);
  const writerPage = await holderJoins(writer, link, 'writer');
  await converted(flow.bTab, flow.scope, before);
  const shared = new SharedPage(writerPage);
  await shared.awaitStandingOf(flow.scope, granted, PASS);
  await expect(shared.row(flow.scope).getByTestId('shared-permission')).toHaveText('write');
  return writerPage;
}

test('a link minted on device A is read at once and converted on device B', async ({ device }) => {
  await readLinkOverTwoDevices(device);
});

test('@full a write link holder writes after device B converts, and device A reads the write', async ({
  device,
}) => {
  test.setTimeout(180_000);
  const flow = await readLinkOverTwoDevices(device);

  await test.step('4. the write link holder writes after device B converts, and device A reads the write', async () => {
    // The session that joined through the link writes, with no new sign-in.
    const writerPage = await writeLinkConvertedOnB(flow, device);
    const files = new FilesPage(writerPage);
    await new SharedPage(writerPage).openShare(flow.scope);
    await refreshedUntil(new VaultPage(writerPage), files.newFolderButton, 1, 60_000);
    await files.upload(WRITTEN, new Uint8Array(2_048).fill(7));
    await expect(files.row(WRITTEN)).toBeVisible();
    await files.published();

    const aTab = await flow.a.online();
    await aTab.files.open(FOLDER);
    await refreshedUntil(aTab.vault, aTab.files.row(WRITTEN));
  });
});

test('@full device A revokes the write link with its joiners: the writer fails closed and the reader keeps access', async ({
  device,
}) => {
  test.setTimeout(180_000);
  const flow = await readLinkOverTwoDevices(device);
  const writerPage = await writeLinkConvertedOnB(flow, device);

  await test.step('5. device A revokes the write link with its joiners; the writer fails closed and the reader keeps access', async () => {
    const aTab = await flow.a.online();
    await aTab.share.openUntilLinks(FOLDER, 2, 60_000);
    await aTab.share.askToRevoke(aTab.share.writeLinkChips);
    await expect(aTab.share.removeGrantees.locator('..')).toHaveText(
      'also remove the 1 person who joined through it'
    );
    await aTab.share.removeGrantees.check();
    await aTab.share.confirmLinkRevoke();
    await expect(aTab.share.linkChips).toHaveCount(1);
    await expect(aTab.share.grantRows).toHaveCount(1);
    await expect(aTab.share.grantRows).toContainText('reader');
    await aTab.share.close();

    await new SharedPage(writerPage).awaitStandingOf(
      flow.scope,
      (row) => row === 'gone' || revoked(row),
      PASS
    );
    await new SharedPage(flow.readerPage).awaitStandingOf(flow.scope, granted, PASS);
  });
});

test('@full a reader admitted again survives the next re-key on device B, and the sweep on B cuts an expired link', async ({
  device,
}) => {
  test.setTimeout(240_000);
  const { a, b, bTab, scope, reader, readerPage } = await readLinkOverTwoDevices(device);
  const readerShared = new SharedPage(readerPage);

  const bAgain =
    await test.step('6. device B cuts the reader, the reader joins again through a new link that device A converts, and the next re-key on B serves it (ADR 0025 D3, E4)', async () => {
      await bTab.share.open(FOLDER);
      await bTab.share.revokeGrantee();
      await expect(bTab.share.noGrants).toBeVisible({ timeout: 180_000 });
      // A person revoke also cuts the link that admitted the person (ADR 0024 D3).
      await expect(bTab.share.linkChips).toHaveCount(0);
      await bTab.share.close();
      await readerShared.awaitStandingOf(scope, revoked, PASS);
      await b.offline();

      // A person the owner cut joins again through a new link, and device A
      // converts the claim (ADR 0025 E4).
      const aTab = await a.online();
      await aTab.share.open(FOLDER);
      const again = await aTab.share.mintLink();
      await aTab.share.close();
      const before = await joins(aTab, scope);
      await holderJoins(reader, again, 'reader');
      await converted(aTab, scope, before);
      await readerShared.awaitStandingOf(scope, granted, PASS);
      await a.offline();

      // The re-key: B revokes the link the reader joined through again, which
      // cuts the folder's read plane and keeps the reader's grant.
      const tab = await b.online();
      await tab.share.openUntilGranted(FOLDER, 1);
      await tab.share.close();
      await tab.share.openUntilLinks(FOLDER, 1);
      await tab.share.revokeFirstLink();
      await expect(tab.share.linkChips).toHaveCount(0);
      await expect(tab.share.grantRows).toHaveCount(1);
      await tab.share.close();

      // Content sealed after the re-key reaches the reader only if B served it.
      await tab.files.open(FOLDER);
      await tab.files.upload(AFTER_REKEY, new TextEncoder().encode('sealed after the re-key'));
      await expect(tab.files.row(AFTER_REKEY)).toBeVisible();
      await tab.files.published();
      await tab.files.openFromSidebar();

      await readerShared.awaitStandingOf(scope, granted, PASS);
      await readerShared.openShare(scope);
      await refreshedUntil(new VaultPage(readerPage), new FilesPage(readerPage).row(AFTER_REKEY));
      return tab;
    });

  await test.step('7. the sweep on device B cuts an expired link, and its chip leaves device A', async () => {
    const aTab = await a.online();
    await aTab.share.open(FOLDER);
    const clicked = Date.now();
    await aTab.share.mintExpiringIn(20_000);
    await expect(aTab.share.linkChips).toHaveCount(1);
    await aTab.share.close();
    await a.offline();
    // Device A's own sweep cuts the link no sooner than its deadline.
    expect(Date.now() - clicked, 'device A stayed online past the deadline').toBeLessThan(20_000);

    // B reads the link first, so its absence afterwards is a cut, not a read
    // that predates the mint.
    await bAgain.share.openUntilLinks(FOLDER, 1, 15_000);
    await bAgain.share.openUntilLinks(FOLDER, 0, 120_000);
    await bAgain.share.close();
    await b.offline();

    const aLater = await a.online();
    await aLater.share.openUntilLinks(FOLDER, 0, 60_000);
    await expect(aLater.share.grantRows).toHaveCount(1);
  });
});
