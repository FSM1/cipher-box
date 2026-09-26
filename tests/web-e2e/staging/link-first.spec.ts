/**
 * Profile: link-first sharing across two owner devices (ADR 0023-0028). Device
 * A mints, a holder reads at once, and device B converts the claim; then the
 * re-key rule of ADR 0025 D3, a write link, and the expired-link sweep.
 *
 * Device B is a second context on the owner's wallet. A device goes offline on
 * `about:blank`, which stops its engine, and comes back on a load that resumes
 * its session, so each conversion, cut and sweep has one owner device that can
 * run it. The profile runs at production cadences, hence the long budgets.
 */

import type { Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage } from '../page-objects/shared.page';
import { expect, published, signIn, signInWithWallet, test } from './fixtures';

const FOLDER = 'link-first';
const NOTE = 'notes.txt';
const SUBFOLDER = 'photos';
const OWNER_NAME = 'dana';
const WRITTEN = 'from-the-writer.bin';
const AFTER_REKEY = 'after-the-rekey.txt';
const READER_FOLDER = 'reader-own';
const DAY_MS = 86_400_000;

/** One sync pass on the record plane, at production cadence. */
const PASS_MS = 600_000;

async function offline(page: Page): Promise<void> {
  await page.goto('about:blank');
}

/** Loads the vault again; the session resumes, and a fresh engine starts. */
async function online(page: Page): Promise<FilesPage> {
  await page.goto('/files');
  const files = new FilesPage(page);
  await expect(files.browser).toBeVisible({ timeout: 180_000 });
  return files;
}

/** Re-reads a holder's `/shared` row, one nudged pass per turn, until it matches. */
async function awaitStanding(page: Page, scope: string, expected: RegExp): Promise<void> {
  const shared = new SharedPage(page);
  if ((await shared.panel.count()) === 0) await shared.open();
  await expect
    .poll(
      async () => {
        await page.getByTestId('status-indicator').click();
        return shared.standingOf(scope);
      },
      { timeout: PASS_MS, intervals: [5_000] }
    )
    .toMatch(expected);
}

/** Nudges `page`'s pass until its open folder lists `name`. */
async function listed(page: Page, name: string): Promise<void> {
  const files = new FilesPage(page);
  await expect
    .poll(
      async () => {
        await files.status.click();
        return files.row(name).count();
      },
      { timeout: PASS_MS, intervals: [5_000] }
    )
    .toBe(1);
}

/** Spends `link` in `page` under `name`: sign-in on the claim route, then the join. */
async function join(page: Page, link: URL, name: string): Promise<InvitePage> {
  const invite = new InvitePage(page);
  await invite.open(link);
  await invite.expectState('waiting', 180_000);
  await signInWithWallet(page, invite.joinButton);
  await invite.expectState('joinable');
  await invite.name.fill(name);
  await invite.join();
  await invite.expectFolderOpened(180_000);
  return invite;
}

test('the link-first flow runs across two owner devices', async ({
  page,
  wallet,
  secondContext,
}) => {
  test.setTimeout(2_400_000);
  const ownerFiles = new FilesPage(page);
  const ownerShare = new SharePage(page);
  let scope = '';
  let link!: URL;

  await test.step('1. device A mints a read link with the owner name on a folder of two entries', async () => {
    await signIn(page);
    await ownerFiles.createFolder(FOLDER);
    await expect(ownerFiles.row(FOLDER)).toBeVisible();
    await published(page);
    await ownerFiles.open(FOLDER);
    await ownerFiles.upload(NOTE, new TextEncoder().encode('read before any conversion'));
    await expect(ownerFiles.row(NOTE)).toBeVisible({ timeout: 180_000 });
    await ownerFiles.createFolder(SUBFOLDER);
    await expect(ownerFiles.row(SUBFOLDER)).toBeVisible();
    await published(page);
    await ownerFiles.openFromSidebar();

    await ownerShare.open(FOLDER);
    link = await ownerShare.mintLink(undefined, { ownerName: OWNER_NAME });
    await ownerShare.close();
    await offline(page);
  });

  const { page: reader } = await secondContext();
  await test.step('2. the holder previews owner and folder, joins, and reads both entries at once', async () => {
    const invite = new InvitePage(reader);
    await invite.open(link);
    await invite.expectState('waiting', 180_000);
    await signInWithWallet(reader, invite.joinButton);
    await invite.expectState('joinable');
    await expect(invite.headline).toHaveText(`${OWNER_NAME} shared ${FOLDER} with you`);
    await expect(invite.entries).toHaveCount(2);
    await invite.name.fill('reader');
    await invite.join();
    await invite.expectFolderOpened(180_000);
    // The join lands on the folder's scope root, which names its `/shared` row.
    scope = new URL(reader.url()).pathname.split('/').pop()!;

    const files = new FilesPage(reader);
    await expect(files.row(NOTE)).toBeVisible({ timeout: 180_000 });
    await expect(files.row(SUBFOLDER)).toBeVisible();
    await awaitStanding(reader, scope, /via-link=true$/);
  });

  const { page: deviceB } = await secondContext(wallet.privateKey);
  const bFiles = new FilesPage(deviceB);
  const bShare = new SharePage(deviceB);
  await test.step("3. device B converts the claim, and the holder's row turns to a grant", async () => {
    await signIn(deviceB);
    await bShare.openUntilGranted(FOLDER, 1, PASS_MS);
    await expect(bShare.grantRows).toContainText('reader');
    await expect(bShare.grantRows.getByTestId('share-got-in')).toHaveText('via link');
    await bShare.close();
    await awaitStanding(reader, scope, /^granted via-link=false$/);
  });

  await test.step('6. device B cuts the reader, device A admits it again, and the next re-key on B serves it (ADR 0025 D3)', async () => {
    await bShare.open(FOLDER);
    await bShare.revokeGrantee();
    await expect(bShare.noGrants).toBeVisible({ timeout: 180_000 });
    await expect(bShare.linkChips).toHaveCount(0);
    await bShare.close();
    await awaitStanding(reader, scope, /^revocation-signal /);
    await offline(deviceB);

    // The invite page offers a person the owner cut only "open folder", so
    // device A admits the reader again by a direct grant.
    await online(page);
    await ownerShare.open(FOLDER);
    const ownerCode = await ownerShare.readOwnContactCode();
    const readerFiles = new FilesPage(reader);
    await readerFiles.openFromSidebar();
    await readerFiles.createFolder(READER_FOLDER);
    await expect(readerFiles.row(READER_FOLDER)).toBeVisible();
    await published(reader);
    const readerShare = new SharePage(reader);
    await readerShare.open(READER_FOLDER);
    await readerShare.importContact(ownerCode);
    const readerCode = await readerShare.readOwnContactCode();
    await readerShare.close();
    await ownerShare.grantTo(readerCode, 'read');
    await ownerShare.close();
    await awaitStanding(reader, scope, /^granted via-link=false$/);
    await offline(page);

    // The re-key: a link revoke on B, which cuts the folder's read plane.
    await online(deviceB);
    await bShare.openUntilGranted(FOLDER, 1, PASS_MS);
    await bShare.mintLink();
    await bShare.close();
    await bShare.open(FOLDER);
    await bShare.revokeFirstLink();
    await expect(bShare.linkChips).toHaveCount(0);
    await expect(bShare.grantRows).toHaveCount(1);
    await bShare.close();

    await bFiles.open(FOLDER);
    await bFiles.upload(AFTER_REKEY, new TextEncoder().encode('sealed after the re-key'));
    await expect(bFiles.row(AFTER_REKEY)).toBeVisible({ timeout: 180_000 });
    await published(deviceB);
    await bFiles.openFromSidebar();

    await awaitStanding(reader, scope, /^granted via-link=false$/);
    await new SharedPage(reader).openShare(scope);
    await listed(reader, AFTER_REKEY);
  });

  await test.step('4. a write link holder writes after device B converts, and device A reads the write', async () => {
    await online(page);
    await ownerShare.open(FOLDER);
    const writeLink = await ownerShare.mintLink(undefined, { permission: 'write' });
    await ownerShare.close();
    await offline(page);

    const { page: writer } = await secondContext();
    await join(writer, writeLink, 'writer');
    await bShare.openUntilGranted(FOLDER, 2, PASS_MS);
    await bShare.close();
    await awaitStanding(writer, scope, /^granted via-link=false$/);

    // The session that joined through the link keeps a read view of the
    // folder after the conversion, so the writer loads a fresh session.
    const writerFiles = await online(writer);
    await new SharedPage(writer).open();
    await new SharedPage(writer).openShare(scope);
    await expect
      .poll(
        async () => {
          await writerFiles.status.click();
          return writerFiles.newFolderButton.count();
        },
        { timeout: PASS_MS, intervals: [5_000] }
      )
      .toBe(1);
    await writerFiles.upload(WRITTEN, new Uint8Array(2_048).fill(7));
    await expect(writerFiles.row(WRITTEN)).toBeVisible({ timeout: 180_000 });
    await published(writer);

    await online(page);
    await ownerFiles.open(FOLDER);
    await listed(page, WRITTEN);
  });
});

test('7. the sweep on device B cuts an expired link, and its chip leaves device A', async ({
  page,
  wallet,
  secondContext,
}) => {
  // Device B's first sweep runs one link-sweep cadence after its sign-in.
  test.setTimeout(1_800_000);
  const files = new FilesPage(page);
  const share = new SharePage(page);

  await signIn(page);
  await files.createFolder(FOLDER);
  await expect(files.row(FOLDER)).toBeVisible();
  await published(page);
  await share.open(FOLDER);
  // Past its deadline and the sweep grace at the mint, and device A goes
  // offline before its own first sweep, so only device B's sweep can cut it.
  await share.mintExpiringIn(-DAY_MS);
  await expect(share.linkChips).toHaveCount(1);
  await share.close();
  await offline(page);

  const { page: deviceB } = await secondContext(wallet.privateKey);
  await signIn(deviceB);
  await new SharePage(deviceB).openUntilLinks(FOLDER, 0, 1_200_000);

  await online(page);
  await share.openUntilLinks(FOLDER, 0, PASS_MS);
});
