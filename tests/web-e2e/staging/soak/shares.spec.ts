/**
 * The two share folders of the owner vault, both read links (blueprint/testing.md
 * staging soak): `soak/shared` reads every night through one long-running link
 * with its read epoch flat, and `soak/cycle` runs a mint, holder read, claim,
 * conversion, person revoke and revoked-link check in one night. The waits
 * copy the staging invite spec: 6 minutes for the conversion, 10 for the
 * standing.
 */

import type { Page } from '@playwright/test';
import { FilesPage } from '../../page-objects/files.page';
import { InvitePage } from '../../page-objects/invite.page';
import { SharePage } from '../../page-objects/share.page';
import { SharedPage, type RowStanding } from '../../page-objects/shared.page';
import { nudgedUntil } from '../fixtures';
import { check, expect, fact, test } from './fixtures';
import { utcDay } from './ledger';
import { markerFile } from './markers';
import {
  CYCLE_FOLDER,
  cycleEpochStepped,
  linkPrefix,
  LONG_RUNNING_MS,
  markerDates,
  parseEpochs,
  SHARED_FOLDER,
  SHARED_MARKER_CAP,
  sharedEpochHeld,
  sharedOverCap,
  sharedLink,
  withSharedLink,
  type Epochs,
} from './shares';
import {
  ensureMarker,
  listed,
  openLedger,
  readMarkers,
  synced,
  toLedgerFolder,
  writeLedger,
} from './vault';

/** Owner sign-in 18, folder 12, mint 5, grantee sign-in 18, join 6, reads 10, epoch 3. */
const SHARED_TEST_MS = 4_200_000;
/** The above, plus leftover grants 6, conversion 6, standing 10, revoke 6, sign-in 18. */
const CYCLE_TEST_MS = 6_600_000;
const PAGE_MS = 180_000;
const LISTING_MS = 300_000;
const READS_MS = 600_000;
const CONVERSION_MS = 360_000;
const STANDING_MS = 600_000;
const EPOCH_MS = 180_000;

const HOLDER_NAME = 'soak grantee';
const FOLDER_PATH = /^\/files\/([0-9a-f]{32})$/;

const granted = (row: RowStanding) =>
  row !== 'gone' && row.resolution === 'granted' && !row.viaLink;

/**
 * Makes `folder` in `soak/` with today's marker in it, moves the markers past
 * `cap` to the bin, then goes back to `soak/`.
 */
async function readyFolder(
  files: FilesPage,
  folder: string,
  today: string,
  cap = Infinity
): Promise<void> {
  await toLedgerFolder(files, 'owner');
  await synced(files);
  if (!(await listed(files, folder))) {
    await files.createFolder(folder);
    await files.published();
  }
  await files.open(folder);
  await synced(files);
  await ensureMarker(files, today);
  const leaving = sharedOverCap(markerDates(await files.names()), cap);
  for (const date of leaving) {
    await files.remove(markerFile(date));
    await expect(files.row(markerFile(date))).toHaveCount(0);
  }
  if (leaving.length > 0) await files.published();
  await toLedgerFolder(files, 'owner');
}

async function readEpochs(share: SharePage): Promise<Epochs> {
  const row = share.page.getByTestId('share-epochs');
  await expect(row).toBeVisible({ timeout: 60_000 });
  return parseEpochs((await row.textContent()) ?? '');
}

/**
 * A document load of `link`, through the page and not `page.goto`: a goto step
 * title and its call log print the URL, and the fragment is a bearer capability.
 */
async function openLink(page: Page, link: URL): Promise<InvitePage> {
  await page.evaluate((href) => window.location.assign(href), link.href);
  const invite = new InvitePage(page);
  await expect(invite.panel).toBeVisible({ timeout: PAGE_MS });
  return invite;
}

/**
 * Opens `link` in a signed-in grantee page and joins. The preview must list
 * today's marker first: it reads through the link's own grant blob, which a
 * person grant from an earlier night does not stand in for. Answers the scope
 * root the join opened, once its listing shows today's marker.
 */
async function join(
  page: Page,
  link: URL,
  today: string
): Promise<{ held: FilesPage; scope: string }> {
  const invite = await openLink(page, link);
  await invite.expectState('joinable', PAGE_MS);
  await expect(invite.entries.filter({ hasText: markerFile(today) })).toHaveCount(1);
  await invite.name.fill(HOLDER_NAME);
  await invite.join();
  let scope: string | undefined;
  await expect
    .poll(() => (scope = FOLDER_PATH.exec(new URL(page.url()).pathname)?.[1]), {
      timeout: PAGE_MS,
    })
    .toBeDefined();
  const held = new FilesPage(page);
  await nudgedUntil(held, held.row(markerFile(today)), 1, LISTING_MS);
  return { held, scope: scope! };
}

test('the long-running link reads every marker with its read epoch flat', async ({
  owner,
  grantee,
}) => {
  test.setTimeout(SHARED_TEST_MS);
  const files = new FilesPage(owner);
  const share = new SharePage(owner);
  const today = utcDay(new Date());
  const opened = await check('owner share ledger', 'ledger-unreadable', async () => {
    const read = await openLedger(files, 'owner');
    return { read, link: sharedLink(read) };
  });
  let link = opened.link;
  await check('shared folder marker', 'share-folder-unready', () =>
    readyFolder(files, SHARED_FOLDER, today, SHARED_MARKER_CAP)
  );

  if (link === null) {
    link = await check('shared link mint', 'link-unminted', async () => {
      await share.open(SHARED_FOLDER);
      const url = await share.mintExpiringIn(LONG_RUNNING_MS, { permission: 'read' });
      const minted = { readEpoch: (await readEpochs(share)).read, url };
      await share.close();
      await writeLedger(files, withSharedLink(opened.read, minted));
      return minted;
    });
    await fact('shared link', `minted ${linkPrefix(link.url)} at read epoch ${link.readEpoch}`);
  }

  const url = link.url;
  const dates = await check('shared holder read', 'holder-read-failed', async () => {
    const { held } = await join(await grantee(), url, today);
    const shown = markerDates(await held.names());
    await readMarkers(held, shown, READS_MS, 'holder-read-failed');
    return shown;
  });
  await fact('shared holder markers', `${dates.length} opened, oldest ${dates[0]}`);

  const recorded = link.readEpoch;
  await check('shared link epoch', 'shared-epoch-stepped', async () => {
    await share.open(SHARED_FOLDER);
    const shown = (await readEpochs(share)).read;
    await share.close();
    sharedEpochHeld(recorded, shown);
  });
  await fact('shared read epoch', String(recorded));
});

test('the cycle folder mints, converts and revokes a read link in one night', async ({
  owner,
  grantee,
}) => {
  test.setTimeout(CYCLE_TEST_MS);
  const files = new FilesPage(owner);
  const share = new SharePage(owner);
  const today = utcDay(new Date());
  await check('cycle folder marker', 'share-folder-unready', () =>
    readyFolder(files, CYCLE_FOLDER, today)
  );

  // A failed night can leave the grantee granted, which would hold the next join off a claim.
  await check('cycle leftover grants', 'cycle-epoch-flat', async () => {
    await share.open(CYCLE_FOLDER);
    const people = share.page.getByTestId('share-people');
    await expect(people.or(share.page.getByTestId('share-grants-unavailable'))).toBeVisible({
      timeout: PAGE_MS,
    });
    for (let left = await share.grantRows.count(); left > 0; left -= 1) {
      await share.grantRows.first().getByTestId('share-revoke').click();
      await share.page.getByTestId('share-revoke-confirm').click();
      await expect(share.grantRows).toHaveCount(left - 1, { timeout: PAGE_MS });
    }
    await share.close();
  });

  const { url, before } = await check('cycle link mint', 'link-unminted', async () => {
    await share.open(CYCLE_FOLDER);
    const minted = await share.mintLink({ lifetime: '30 days', permission: 'read' });
    const epoch = (await readEpochs(share)).read;
    await share.close();
    return { url: minted, before: epoch };
  });
  await fact('cycle link', `minted ${linkPrefix(url)} at read epoch ${before}`);

  const { page, scope } = await check('cycle holder read', 'holder-read-failed', async () => {
    const opened = await grantee();
    const { held, scope: root } = await join(opened, url, today);
    await readMarkers(held, [today], READS_MS, 'holder-read-failed');
    return { page: opened, scope: root };
  });

  await check('cycle conversion', 'claim-unconverted', async () => {
    await share.openUntilGranted(CYCLE_FOLDER, 1, CONVERSION_MS);
    await share.close();
    await new SharedPage(page).awaitStandingOf(scope, granted, { timeout: STANDING_MS });
  });

  const after = await check('cycle revoke', 'cycle-epoch-flat', async () => {
    await share.open(CYCLE_FOLDER);
    await share.revokeGrantee();
    await expect(share.noGrants).toBeVisible({ timeout: PAGE_MS });
    let shown = before;
    // The dialog shows the epoch its last read found, so a new opening reads the cut.
    await expect(async () => {
      if ((await share.dialog.count()) > 0) await share.close();
      await share.open(CYCLE_FOLDER);
      shown = (await readEpochs(share)).read;
      expect(shown).not.toBe(before);
    })
      .toPass({ timeout: EPOCH_MS })
      .catch(() => undefined);
    if ((await share.dialog.count()) > 0) await share.close();
    cycleEpochStepped(before, shown);
    return shown;
  });
  await fact('cycle read epoch', `${before} to ${after}`);

  await check('cycle link revoked', 'link-not-revoked', async () => {
    const invite = await openLink(await grantee(), url);
    await invite.expectState('revoked', PAGE_MS);
    await expect(invite.entries).toHaveCount(0);
  });
});
