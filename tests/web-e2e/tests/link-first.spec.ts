/**
 * The link-first flow across two owner devices (ADR 0023-0028): device A mints,
 * a holder reads at once, and device B converts the claim on its own tick.
 *
 * Each device is a browser context of its own over one held login secret
 * (`devices.ts`). A device that must not act goes offline, so each conversion,
 * cut and sweep below has exactly one owner device that can run it.
 */

import type { Page } from '@playwright/test';
import { Device, freshLogin, type Login, type Tab } from '../devices';
import { expect, test as base } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { VaultPage } from '../page-objects/vault.page';
import { nodeOf } from '../vault';

const FOLDER = 'link-first';
const NOTE = 'notes.txt';
const SUBFOLDER = 'photos';
const OWNER_NAME = 'dana';
const WRITTEN = 'from-the-writer.bin';
const AFTER_REKEY = 'after-the-rekey.txt';
const READER_FOLDER = 'reader-own';

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
  readonly readerPage: Page;
}

/** The claims `tab`'s engine converted on `scope`, by the events it emitted. */
async function joins(tab: Tab, scope: string): Promise<number> {
  const events = await tab.vault.events();
  return events.filter((event) => event.kind === 'granteeJoined' && event.scopeRoot === scope)
    .length;
}

/** Waits until `tab`'s engine converted `count` claims on `scope`. */
async function converted(tab: Tab, scope: string, count: number): Promise<void> {
  await expect.poll(() => joins(tab, scope), { timeout: 120_000, intervals: [1_000] }).toBe(count);
}

/** How a holder's `/shared` row for `scope` stands after one nocache pass. */
async function standing(page: Page, scope: string): Promise<string> {
  await new VaultPage(page).refreshed();
  return new SharedPage(page).standingOf(scope);
}

/** Re-reads a holder's `/shared` row until its standing matches `expected`. */
async function awaitStanding(page: Page, scope: string, expected: RegExp): Promise<void> {
  const shared = new SharedPage(page);
  if ((await shared.panel.count()) === 0) await shared.open();
  await expect
    .poll(() => standing(page, scope), { timeout: 120_000, intervals: [2_000] })
    .toMatch(expected);
}

/** Refreshes `page` until its open folder lists `name` exactly `count` times. */
async function listsUntil(page: Page, name: string, count: number): Promise<void> {
  const files = new FilesPage(page);
  await expect
    .poll(
      async () => {
        await new VaultPage(page).refresh();
        return files.row(name).count();
      },
      { timeout: 120_000, intervals: [2_000] }
    )
    .toBe(count);
}

/**
 * Spends `link` on `holder` under the name `name`, and lands on the shared
 * folder. A document load ends a session, so the tab signs in again on the
 * claim route.
 */
async function join(holder: Device, link: URL, name: string): Promise<Page> {
  const page = await holder.page();
  const invite = new InvitePage(page);
  const vault = new VaultPage(page);
  await invite.open(link);
  await vault.ready();
  await vault.signInHeld(holder.login.accountId);
  await invite.expectState('joinable');
  await invite.name.fill(name);
  await invite.join();
  await invite.expectFolderOpened();
  return page;
}

/** Steps 1-3: A mints, the holder reads at once, and B converts the claim on its tick. */
async function readLinkOverTwoDevices(device: OpenDevice): Promise<Flow> {
  const owner = freshLogin();
  const a = await device(owner);
  const b = await device(owner);
  const reader = await device();

  let scope = '';
  let link!: URL;
  await test.step('1. device A mints a read link with the owner name on a folder of two entries', async () => {
    const { files, vault, share } = await a.online();
    await files.createFolder(FOLDER);
    scope = nodeOf((await vault.settled()).view, FOLDER);
    await files.open(FOLDER);
    await files.upload(NOTE, new TextEncoder().encode('read before any conversion'));
    await expect(files.row(NOTE)).toBeVisible();
    await files.createFolder(SUBFOLDER);
    await expect(files.row(SUBFOLDER)).toBeVisible();
    await files.published();
    await files.openFromSidebar();

    await share.open(FOLDER);
    link = await share.mintLink(undefined, { ownerName: OWNER_NAME });
    await share.close();
    await a.offline();
  });

  let readerPage!: Page;
  await test.step('2. the holder previews owner and folder, joins, and reads both entries at once', async () => {
    readerPage = await reader.page();
    const invite = new InvitePage(readerPage);
    const vault = new VaultPage(readerPage);
    await invite.open(link);
    await vault.ready();
    await vault.signInHeld(reader.login.accountId);
    await invite.expectState('joinable');
    await expect(invite.headline).toHaveText(`${OWNER_NAME} shared ${FOLDER} with you`);
    await expect(invite.entries).toHaveCount(2);
    await invite.name.fill('reader');
    await invite.join();
    await invite.expectFolderOpened();

    // No owner device is online, so no claim is converted: the holder reads
    // through the link's keys (ADR 0024).
    const files = new FilesPage(readerPage);
    await expect(files.row(NOTE)).toBeVisible({ timeout: 60_000 });
    await expect(files.row(SUBFOLDER)).toBeVisible();
    await awaitStanding(readerPage, scope, /via-link=true$/);
  });

  let bTab!: Tab;
  await test.step("3. device B converts the claim on its tick, and the holder's row turns to a grant", async () => {
    bTab = await b.online();
    // Nothing on B opened the share dialog yet, so the conversion is the tick's.
    await converted(bTab, scope, 1);

    await bTab.share.openUntilGranted(FOLDER, 1);
    await expect(bTab.share.grantRows).toContainText('reader');
    await expect(bTab.share.grantRows.getByTestId('share-got-in')).toHaveText('via link');
    await expect(bTab.share.permission).toHaveValue('read');
    await bTab.share.close();

    await awaitStanding(readerPage, scope, /^granted via-link=false$/);
  });

  return { a, b, bTab, scope, readerPage };
}

/**
 * Step 4's first half: A mints a write link and goes offline, a second holder
 * joins it, and B converts the claim.
 */
async function writeLinkConvertedOnB(
  flow: Flow,
  device: OpenDevice
): Promise<{ writer: Device; writerPage: Page }> {
  const aTab = await flow.a.online();
  await aTab.share.open(FOLDER);
  const link = await aTab.share.mintLink(undefined, { permission: 'write' });
  await aTab.share.close();
  await flow.a.offline();

  const writer = await device();
  const writerPage = await join(writer, link, 'writer');
  await converted(flow.bTab, flow.scope, 2);
  await awaitStanding(writerPage, flow.scope, /^granted via-link=false$/);
  const row = new SharedPage(writerPage).row(flow.scope);
  await expect(row.getByTestId('shared-permission')).toHaveText('write');
  return { writer, writerPage };
}

test('a link minted on device A is read at once and converted on device B', async ({ device }) => {
  test.setTimeout(300_000);
  await readLinkOverTwoDevices(device);
});

test('@full a write link holder writes after device B converts, and device A reads the write', async ({
  device,
}) => {
  test.setTimeout(600_000);
  const flow = await readLinkOverTwoDevices(device);

  await test.step('4. the write link holder writes after device B converts, and device A reads the write', async () => {
    const { writer } = await writeLinkConvertedOnB(flow, device);
    // The session that joined through the link keeps a read view of the
    // folder after the conversion, so the writer signs in again.
    const { page: writerPage } = await writer.online();
    const shared = new SharedPage(writerPage);
    await shared.open();
    await shared.openShare(flow.scope);
    const files = new FilesPage(writerPage);
    const vault = new VaultPage(writerPage);
    await expect
      .poll(
        async () => {
          await vault.refresh();
          return files.newFolderButton.count();
        },
        { timeout: 60_000, intervals: [2_000] }
      )
      .toBe(1);
    await files.upload(WRITTEN, new Uint8Array(2_048).fill(7));
    await expect(files.row(WRITTEN)).toBeVisible();
    await files.published();

    const aTab = await flow.a.online();
    await aTab.files.open(FOLDER);
    await listsUntil(aTab.page, WRITTEN, 1);
  });
});

test('@full device A revokes the write link with its joiners: the writer fails closed and the reader keeps access', async ({
  device,
}) => {
  test.fail(
    true,
    "device A reads no sharing state for the folder after device B's write-scope cut moved its root"
  );
  test.setTimeout(600_000);
  const flow = await readLinkOverTwoDevices(device);
  const { writerPage } = await writeLinkConvertedOnB(flow, device);

  await test.step('5. device A revokes the write link with its joiners; the writer fails closed and the reader keeps access', async () => {
    const aTab = await flow.a.online();
    await aTab.share.openUntilLinks(FOLDER, 2, 60_000);
    await aTab.share.askToRevoke(aTab.share.linkChipsFor('write'));
    await expect(aTab.share.removeGrantees.locator('..')).toHaveText(
      'also remove the 1 person who joined through it'
    );
    await aTab.share.removeGrantees.check();
    await aTab.share.confirmLinkRevoke();
    await expect(aTab.share.linkChips).toHaveCount(1);
    await expect(aTab.share.grantRows).toHaveCount(1);
    await expect(aTab.share.grantRows).toContainText('reader');
    await aTab.share.close();

    await awaitStanding(writerPage, flow.scope, /^(gone|revocation-signal .*)$/);
    await awaitStanding(flow.readerPage, flow.scope, /^granted via-link=false$/);
  });
});

test('@full a reader that device B cut and device A admitted again survives the next re-key on B', async ({
  device,
}) => {
  test.setTimeout(600_000);
  const { a, b, bTab, scope, readerPage } = await readLinkOverTwoDevices(device);

  await test.step('6. device B cuts the reader, device A admits it again, and the next re-key on B serves it (ADR 0025 D3)', async () => {
    await bTab.share.open(FOLDER);
    await bTab.share.revokeGrantee();
    await expect(bTab.share.noGrants).toBeVisible({ timeout: 180_000 });
    // A person revoke also cuts the link that admitted the person (ADR 0024 D3).
    await expect(bTab.share.linkChips).toHaveCount(0);
    await bTab.share.close();
    await awaitStanding(readerPage, scope, /^revocation-signal /);
    await b.offline();

    // The invite page offers a person the owner cut only "open folder", so
    // device A admits the reader again by a direct grant.
    const aTab = await a.online();
    await aTab.share.open(FOLDER);
    const ownerCode = await aTab.share.readOwnContactCode();
    const readerFiles = new FilesPage(readerPage);
    await readerFiles.openFromSidebar();
    await readerFiles.createFolder(READER_FOLDER);
    await readerFiles.published();
    const readerShare = new SharePage(readerPage);
    await readerShare.open(READER_FOLDER);
    await readerShare.importContact(ownerCode);
    const readerCode = await readerShare.readOwnContactCode();
    await readerShare.close();
    await aTab.share.grantTo(readerCode, 'read');
    await aTab.share.close();
    await awaitStanding(readerPage, scope, /^granted via-link=false$/);
    await a.offline();

    // The re-key: a link revoke on B, which cuts the folder's read plane.
    const bAgain = await b.online();
    await bAgain.share.openUntilGranted(FOLDER, 1);
    await bAgain.share.mintLink();
    await bAgain.share.close();
    await bAgain.share.open(FOLDER);
    await bAgain.share.revokeFirstLink();
    await expect(bAgain.share.linkChips).toHaveCount(0);
    await expect(bAgain.share.grantRows).toHaveCount(1);
    await bAgain.share.close();

    // Content sealed after the re-key reaches the reader only if B served it.
    await bAgain.files.open(FOLDER);
    await bAgain.files.upload(AFTER_REKEY, new TextEncoder().encode('sealed after the re-key'));
    await expect(bAgain.files.row(AFTER_REKEY)).toBeVisible();
    await bAgain.files.published();

    await awaitStanding(readerPage, scope, /^granted via-link=false$/);
    await new SharedPage(readerPage).openShare(scope);
    await listsUntil(readerPage, AFTER_REKEY, 1);
  });
});

test('@full the sweep on device B cuts an expired link, and its chip leaves device A', async ({
  device,
}) => {
  test.setTimeout(600_000);
  const { a, b, bTab } = await readLinkOverTwoDevices(device);

  await test.step('7. the sweep on device B cuts an expired link, and its chip leaves device A', async () => {
    const aTab = await a.online();
    await aTab.share.open(FOLDER);
    // Device A goes offline before the deadline and the sweep grace pass, so
    // only device B's sweep can cut the link.
    await aTab.share.mintExpiringIn(20_000);
    await expect(aTab.share.linkChips).toHaveCount(2);
    await aTab.share.close();
    await a.offline();

    await bTab.share.openUntilLinks(FOLDER, 1, 120_000);
    await bTab.share.close();
    await b.offline();

    // A reads cache-first, so its first read after sign-in can predate B's cut.
    const aLater = await a.online();
    await aLater.share.openUntilLinks(FOLDER, 1, 60_000);
    await expect(aLater.share.linkChips).not.toContainText('expired');
  });
});
