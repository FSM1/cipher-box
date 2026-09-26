/**
 * Profile: link-first sharing across two owner devices (ADR 0023-0028), the
 * staging leg of `tests/link-first.spec.ts`. The step numbers are the steps of
 * the link-first flow in `tests/web-e2e/README.md`; they run here in the order
 * 1, 2, 3, 6, 4, 5, 7, so device B's sweep clock already runs at step 7.
 *
 * Device B is a second context on the owner's wallet. A device goes offline on
 * `about:blank`, which stops its engine, and comes back on a load that resumes
 * its session, so each conversion, cut and sweep has one owner device that can
 * run it.
 */

import type { Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { InvitePage } from '../page-objects/invite.page';
import { SharePage } from '../page-objects/share.page';
import { SharedPage, type RowStanding } from '../page-objects/shared.page';
import { expect, nudgedUntil, published, signIn, signInWithWallet, test } from './fixtures';

const FOLDER = 'link-first';
const EXPIRED_FOLDER = 'link-first-expired';
const NOTE = 'notes.txt';
const SUBFOLDER = 'photos';
const OWNER_NAME = 'dana';
const WRITTEN = 'from-the-writer.bin';
const AFTER_REKEY = 'after-the-rekey.txt';
const DAY_MS = 86_400_000;

/** The ceiling on one wait for a sync pass on the record plane. */
const PASS_MS = 600_000;
const PASS = { timeout: PASS_MS };

/** The production `link_sweep_cadence`: a session sweeps first this long after its start. */
const SWEEP_CADENCE_MS = 600_000;

const heldByLink = (row: RowStanding) => row !== 'gone' && row.viaLink;
const granted = (row: RowStanding) =>
  row !== 'gone' && row.resolution === 'granted' && !row.viaLink;
const revoked = (row: RowStanding) => row !== 'gone' && row.resolution === 'revocation-signal';

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

/** Spends `link` in `page` under `name`: sign-in on the claim route, then the join. */
async function join(
  page: Page,
  link: URL,
  name: string,
  beforeJoin?: (invite: InvitePage) => Promise<void>
): Promise<void> {
  const invite = new InvitePage(page);
  await invite.open(link);
  await invite.expectState('waiting', 180_000);
  await signInWithWallet(page, invite.joinButton);
  await invite.expectState('joinable');
  await beforeJoin?.(invite);
  await invite.name.fill(name);
  await invite.join();
  await invite.expectFolderOpened(180_000);
  expect(new URL(page.url()).hash).toBe('');
}

test('the link-first flow runs across two owner devices', async ({
  page,
  wallet,
  secondContext,
}) => {
  // About 26 min expected from the invite, sharing and writable-share profiles
  // plus one sweep cadence; the ceiling keeps the run inside its step budget.
  test.setTimeout(2_400_000);
  const ownerFiles = new FilesPage(page);
  const ownerShare = new SharePage(page);

  const link =
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
      const minted = await ownerShare.mintLink({ ownerName: OWNER_NAME });
      await ownerShare.close();
      await offline(page);
      return minted;
    });

  const { page: reader } = await secondContext();
  const readerShared = new SharedPage(reader);
  const scope =
    await test.step('2. the holder previews owner and folder, joins, and reads both entries at once', async () => {
      await join(reader, link, 'reader', async (invite) => {
        await expect(invite.headline).toHaveText(`${OWNER_NAME} shared ${FOLDER} with you`);
        await expect(invite.entries).toHaveCount(2);
      });
      // The join lands on the folder's scope root, which names its `/shared` row.
      const root = new URL(reader.url()).pathname.split('/').pop()!;
      const files = new FilesPage(reader);
      await expect(files.row(NOTE)).toBeVisible({ timeout: 180_000 });
      await expect(files.row(SUBFOLDER)).toBeVisible();
      await readerShared.awaitStandingOf(root, heldByLink, PASS);
      return root;
    });

  const { page: deviceB } = await secondContext(wallet.privateKey);
  const bFiles = new FilesPage(deviceB);
  const bShare = new SharePage(deviceB);
  await test.step("3. device B converts the claim on its tick, and the holder's row turns to a grant", async () => {
    await signIn(deviceB);
    await readerShared.awaitStandingOf(scope, granted, PASS);

    await bShare.openUntilGranted(FOLDER, 1, PASS_MS);
    await expect(bShare.grantRows).toContainText('reader');
    await expect(bShare.grantRows.getByTestId('share-got-in')).toHaveText('via link');
    await bShare.close();
  });

  await test.step('6. device B cuts the reader, the reader joins again through a new link that device A converts, and the next re-key on B serves it (ADR 0025 D3, E4)', async () => {
    await bShare.open(FOLDER);
    await bShare.revokeGrantee();
    await expect(bShare.noGrants).toBeVisible({ timeout: 180_000 });
    await expect(bShare.linkChips).toHaveCount(0);
    await bShare.close();
    await readerShared.awaitStandingOf(scope, revoked, PASS);
    await offline(deviceB);

    // The reader's session resumes on the invite load, so the page offers the
    // join at once.
    await online(page);
    await ownerShare.open(FOLDER);
    const again = await ownerShare.mintLink();
    await ownerShare.close();
    const invite = new InvitePage(reader);
    await invite.open(again);
    await invite.expectState('joinable', 180_000);
    await invite.name.fill('reader');
    await invite.join();
    await invite.expectFolderOpened(180_000);
    await readerShared.awaitStandingOf(scope, granted, PASS);
    await offline(page);

    await online(deviceB);
    await bShare.openUntilGranted(FOLDER, 1, PASS_MS);
    await bShare.close();
    await bShare.openUntilLinks(FOLDER, 1, PASS_MS);
    await bShare.revokeFirstLink();
    await expect(bShare.linkChips).toHaveCount(0);
    await expect(bShare.grantRows).toHaveCount(1);
    await bShare.close();

    await bFiles.open(FOLDER);
    await bFiles.upload(AFTER_REKEY, new TextEncoder().encode('sealed after the re-key'));
    await expect(bFiles.row(AFTER_REKEY)).toBeVisible({ timeout: 180_000 });
    await published(deviceB);
    await bFiles.openFromSidebar();

    await readerShared.awaitStandingOf(scope, granted, PASS);
    await readerShared.openShare(scope);
    const readerFiles = new FilesPage(reader);
    await nudgedUntil(readerFiles, readerFiles.row(AFTER_REKEY), 1, PASS_MS);
  });

  const writerView =
    await test.step('4. a write link holder writes after device B converts, and device A reads the write', async () => {
      await online(page);
      await ownerShare.open(FOLDER);
      const writeLink = await ownerShare.mintLink({ permission: 'write' });
      await ownerShare.close();
      await offline(page);

      const { page: writer } = await secondContext();
      const writerShared = new SharedPage(writer);
      await join(writer, writeLink, 'writer');
      await writerShared.awaitStandingOf(scope, granted, PASS);
      await bShare.openUntilGranted(FOLDER, 2, PASS_MS);
      await bShare.close();

      // The session that joined through the link writes, with no new sign-in.
      const writerFiles = new FilesPage(writer);
      await writerShared.open();
      await writerShared.openShare(scope);
      await nudgedUntil(writerFiles, writerFiles.newFolderButton, 1, PASS_MS);
      await writerFiles.upload(WRITTEN, new Uint8Array(2_048).fill(7));
      await expect(writerFiles.row(WRITTEN)).toBeVisible({ timeout: 180_000 });
      await published(writer);

      await online(page);
      await ownerFiles.open(FOLDER);
      await nudgedUntil(ownerFiles, ownerFiles.row(WRITTEN), 1, PASS_MS);
      await ownerFiles.openFromSidebar();
      return writerShared;
    });

  await test.step('5. device A revokes the write link with its joiners; the writer fails closed and the reader keeps access', async () => {
    // Step 6 left no read link, so the write link stands alone.
    await ownerShare.openUntilLinks(FOLDER, 1, PASS_MS);
    await ownerShare.askToRevoke(ownerShare.writeLinkChips);
    await expect(ownerShare.removeGrantees.locator('..')).toHaveText(
      'also remove the 1 person who joined through it'
    );
    await ownerShare.removeGrantees.check();
    await ownerShare.confirmLinkRevoke();
    await expect(ownerShare.linkChips).toHaveCount(0);
    await expect(ownerShare.grantRows).toHaveCount(1);
    await expect(ownerShare.grantRows).toContainText('reader');
    await ownerShare.close();

    await writerView.awaitStandingOf(scope, (row) => row === 'gone' || revoked(row), PASS);
    await readerShared.awaitStandingOf(scope, granted, PASS);
  });

  await test.step('7. the sweep on device B cuts an expired link, and its chip leaves device A', async () => {
    // A fresh session on device A, so its first sweep is a cadence away.
    await offline(page);
    await online(page);
    const started = Date.now();
    await ownerFiles.createFolder(EXPIRED_FOLDER);
    await expect(ownerFiles.row(EXPIRED_FOLDER)).toBeVisible();
    await published(page);
    await ownerShare.open(EXPIRED_FOLDER);
    await ownerShare.mintExpiringIn(-DAY_MS);
    await expect(ownerShare.linkChips).toContainText('expired');
    await ownerShare.close();
    await offline(page);
    expect(Date.now() - started, 'device A stayed online into its own first sweep').toBeLessThan(
      SWEEP_CADENCE_MS
    );

    // A fresh session on device B too: its first sweep is a cadence after this
    // load, so B reads the link before it cuts it, and its absence afterwards
    // is a cut, not a read that predates the mint.
    await offline(deviceB);
    await online(deviceB);
    await bShare.openUntilLinks(EXPIRED_FOLDER, 1, PASS_MS);
    await bShare.openUntilLinks(EXPIRED_FOLDER, 0, SWEEP_CADENCE_MS + PASS_MS);
    await bShare.close();

    await online(page);
    await ownerShare.openUntilLinks(EXPIRED_FOLDER, 0, PASS_MS);
  });
});
