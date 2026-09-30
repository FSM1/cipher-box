/**
 * The vault checks of the owner web leg, from an empty profile: the markers
 * open, their names hold their sequences on the public routing path, today's
 * marker advances `soak/` by one, and the cap and the purge keep the bin.
 */

import { setTimeout as sleep } from 'node:timers/promises';
import type { Page } from '@playwright/test';
import type { IpnsRecordReading } from '@cipherbox/client';
import { BinPage } from '../../page-objects/bin.page';
import { FilesPage } from '../../page-objects/files.page';
import { SOAK_FOLDER } from './bootstrap';
import { check, expect, fact, test } from './fixtures';
import { appendMarker, markers, utcDay, type Ledger } from './ledger';
import {
  binLine,
  binMarkers,
  binnedMarkers,
  byDate,
  dropBinned,
  freshValidity,
  inPool,
  markerBytes,
  markerFile,
  oldestMarkerLine,
  overCap,
  purgeDue,
  purgeWaiting,
  rebinMarkers,
  republishDue,
  sequencesLine,
  strandedBinned,
  unreadLine,
  type SequenceReading,
} from './markers';
import { SoakFailure } from './reasons';
import { resolveUntil } from './recordReader';
import {
  binRetention,
  download,
  LEDGER_FILE,
  openLedger,
  toLedgerFolder,
  writeLedger,
} from './vault';

/**
 * Each wait below ends inside this, so a slow night fails with its own reason.
 * The first test: sign-in 15, ledger 13, opens 20, names 10, resolves 15, republish 10.
 */
const TEST_MS = 5_400_000;
/** A name the ledger holds was published a night ago or more. */
const RESOLVE_MS = 120_000;
const OPENS_MS = 1_200_000;
const DOWNLOAD_MS = 60_000;
/** The dialog reads of every ledger name, and then their resolves, 25 in total. */
const NAMES_MS = 600_000;
const RESOLVES_MS = 900_000;
const RESOLVE_WIDTH = 4;
const PUBLISH_MS = 300_000;
/** The session-start renewal publishes, then the public path takes it up. */
const RENEWAL_MS = 600_000;
/** Bin expiry queues a due purge on the poll tick, and the queue drains it. */
const PURGE_MS = 600_000;
/** Two reads this far apart let a late publish of the night before land. */
const SETTLE_MS = 65_000;

/** The bin retention the owner saved in Settings. A scheduled night writes no settings. */
async function savedRetention(page: Page): Promise<number> {
  const { origin, days } = await binRetention(page);
  if (origin === 'defaults' || !Number.isInteger(days) || days <= 0) {
    throw new SoakFailure(
      'settings-unread',
      `the settings read as ${origin} with a bin retention of ${days} days`
    );
  }
  return days;
}

/** Reads the name of today's marker off its row, resolves it, and appends its ledger line. */
async function recordMarker(files: FilesPage, ledger: Ledger, today: string): Promise<Ledger> {
  const ipnsName = await files.ipnsName(markerFile(today));
  const reading = await resolveUntil(ipnsName, () => true, PUBLISH_MS);
  const next = appendMarker(ledger, {
    date: today,
    ipnsName,
    sequence: Number(reading.sequence),
  });
  await writeLedger(files, next);
  return next;
}

test('the owner markers open byte for byte and hold their sequences', async ({ owner }) => {
  test.setTimeout(TEST_MS);
  const files = new FilesPage(owner);
  const today = utcDay(new Date());
  const ledger = await check('owner marker ledger', 'ledger-unreadable', () =>
    openLedger(files, 'owner')
  );
  const list = byDate(markers(ledger));

  await check('owner markers open', 'marker-unreadable', async () => {
    const deadline = Date.now() + OPENS_MS;
    for (const [index, marker] of list.entries()) {
      if (Date.now() >= deadline) {
        const unread = list.slice(index).map((m) => m.date);
        throw new SoakFailure('marker-unreadable', `no time to open ${unreadLine(unread)}`);
      }
      const bytes = await download(files, markerFile(marker.date), DOWNLOAD_MS);
      if (!Buffer.from(bytes).equals(Buffer.from(markerBytes(marker.date)))) {
        throw new SoakFailure(
          'marker-unreadable',
          `the marker of ${marker.date} opened other bytes`
        );
      }
    }
  });
  const oldest = list[0];
  await fact('owner oldest marker', oldestMarkerLine(oldest, today));

  const readings = await check('owner marker sequences', 'sequence-regressed', async () => {
    const namesBy = Date.now() + NAMES_MS;
    for (const [index, marker] of list.entries()) {
      if (Date.now() >= namesBy) {
        const unread = list.slice(index).map((m) => m.date);
        throw new SoakFailure('name-unread', `no time to read the names of ${unreadLine(unread)}`);
      }
      if ((await files.ipnsName(markerFile(marker.date))) !== marker.ipnsName) {
        throw new SoakFailure(
          'sequence-regressed',
          `the marker of ${marker.date} shows a new name`
        );
      }
    }
    const deadline = Date.now() + RESOLVES_MS;
    const left = (): number => deadline - Date.now();
    const out: SequenceReading[] = [];
    await inPool(list, RESOLVE_WIDTH, async (marker) => {
      if (left() <= 0) return;
      const floor = BigInt(marker.sequence);
      const reading = await resolveUntil(
        marker.ipnsName,
        (r) => r.sequence >= floor,
        Math.min(RESOLVE_MS, left())
      );
      if (reading.sequence < floor) {
        throw new SoakFailure(
          'sequence-regressed',
          `the marker of ${marker.date} resolved at ${reading.sequence}, ledger ${floor}`
        );
      }
      out.push({ date: marker.date, ledger: marker.sequence, resolved: reading.sequence });
    });
    const read = new Set(out.map((reading) => reading.date));
    const unread = list.filter((marker) => !read.has(marker.date)).map((m) => m.date);
    if (unread.length > 0) {
      throw new SoakFailure(
        'routing-unavailable',
        `the resolve budget ended before ${unreadLine(unread)}`
      );
    }
    return out;
  });
  await fact('owner marker sequences', sequencesLine(readings));

  if (oldest !== undefined && republishDue(oldest, today)) {
    await check('oldest marker republished', 'republish-missed', async () => {
      const next = BigInt(oldest.sequence) + 1n;
      const renewed = (r: IpnsRecordReading) =>
        r.sequence >= next && freshValidity(r.validUntil, Date.now());
      const reading = await resolveUntil(oldest.ipnsName, renewed, RENEWAL_MS);
      if (reading.sequence !== next || !freshValidity(reading.validUntil, Date.now())) {
        throw new SoakFailure(
          'republish-missed',
          `the marker of ${oldest.date} resolved at ${reading.sequence}, valid to ${reading.validity}; expected ${next}`
        );
      }
      await fact(
        'owner republished marker',
        `${oldest.date} at ${reading.sequence} (ledger ${oldest.sequence}), valid to ${reading.validity}`
      );
    });
  }
});

test("today's marker advances soak/ by one, and the bin holds the cap", async ({
  owner,
  freshOwner,
}) => {
  test.setTimeout(TEST_MS);
  const files = new FilesPage(owner);
  const today = utcDay(new Date());
  const file = markerFile(today);
  let ledger = await check('owner marker ledger', 'ledger-unreadable', () =>
    openLedger(files, 'owner')
  );

  if (markers(ledger).some((marker) => marker.date === today)) {
    await fact("today's marker", `${today} is in the ledger already`);
  } else if ((await files.row(file).count()) > 0) {
    // An earlier run of today wrote the marker and missed its ledger line.
    ledger = await check("today's marker", 'sequence-not-advanced', () =>
      recordMarker(files, ledger, today)
    );
    await fact("today's marker", `${today} was listed before its ledger line; no +1 check`);
  } else {
    const folder = await check('soak/ sequence', 'sequence-not-advanced', async () => {
      await files.toRoot();
      const ipnsName = await files.ipnsName(SOAK_FOLDER);
      const first = await resolveUntil(ipnsName, () => true, RESOLVE_MS);
      await sleep(SETTLE_MS);
      const second = await resolveUntil(ipnsName, () => true, RESOLVE_MS);
      await files.open(SOAK_FOLDER);
      const before = first.sequence > second.sequence ? first.sequence : second.sequence;
      return { ipnsName, before };
    });

    ledger = await check("today's marker", 'sequence-not-advanced', async () => {
      await files.upload(file, markerBytes(today));
      await expect(files.row(file)).toBeVisible({ timeout: 180_000 });
      await files.published();
      return recordMarker(files, ledger, today);
    });

    const cold = new FilesPage(await freshOwner());
    await check("today's marker re-resolves", 'sequence-not-advanced', async () => {
      await expect(cold.row(SOAK_FOLDER)).toBeVisible({ timeout: 180_000 });
      const shown = await cold.ipnsName(SOAK_FOLDER);
      if (shown !== folder.ipnsName) {
        throw new SoakFailure('sequence-not-advanced', `${SOAK_FOLDER}/ shows a new name`);
      }
      const expected = folder.before + 1n;
      const reading = await resolveUntil(shown, (r) => r.sequence >= expected, PUBLISH_MS);
      if (reading.sequence !== expected) {
        throw new SoakFailure(
          'sequence-not-advanced',
          `${SOAK_FOLDER}/ resolved at ${reading.sequence}, not ${expected}`
        );
      }
      await cold.open(SOAK_FOLDER);
      await expect(cold.row(file)).toBeVisible({ timeout: 180_000 });
      await fact("today's marker", `${today}; ${SOAK_FOLDER}/ ${folder.before} to ${expected}`);
    });
  }

  const retentionDays = await check('owner bin retention', 'settings-unread', () =>
    savedRetention(owner)
  );
  const bin = new BinPage(owner);

  ledger = await check('owner marker cap', 'cap-missed', async () => {
    await toLedgerFolder(files, 'owner');
    await expect(files.row(LEDGER_FILE)).toBeVisible({ timeout: 180_000 });
    const stranded = strandedBinned(binnedMarkers(ledger), await files.names()).map(
      (entry) => entry.date
    );
    const fresh = overCap(markers(ledger)).map((marker) => marker.date);
    const leaving = [...stranded, ...fresh];
    if (leaving.length === 0) return ledger;
    // The ledger goes first: a marker it lists must open, so it never lists one in the bin.
    const next = rebinMarkers(binMarkers(ledger, fresh, today), stranded, today);
    await writeLedger(files, next);
    for (const date of leaving) {
      await files.remove(markerFile(date));
      await expect(files.row(markerFile(date))).toHaveCount(0);
    }
    await files.published();
    await bin.open();
    for (const date of leaving) await bin.appeared(markerFile(date));
    return next;
  });

  await check('owner bin purge', 'purge-missed', async () => {
    const binned = binnedMarkers(ledger);
    const due = binned.filter((entry) => purgeDue(entry, retentionDays, today));
    if (binned.length > 0) {
      await bin.open();
      for (const entry of binned) {
        if (due.includes(entry)) await bin.gone(markerFile(entry.date), PURGE_MS);
        else if (purgeWaiting(entry, retentionDays, today)) {
          await bin.appeared(markerFile(entry.date));
        }
      }
    }
    if (due.length > 0) {
      await toLedgerFolder(files, 'owner');
      for (const entry of due) await expect(files.row(markerFile(entry.date))).toHaveCount(0);
      await writeLedger(
        files,
        dropBinned(
          ledger,
          due.map((entry) => entry.date)
        )
      );
    }
    await fact('owner bin', binLine(binned.length, due.length, retentionDays));
  });
});
