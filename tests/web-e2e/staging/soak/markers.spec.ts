/**
 * The vault checks of the owner web leg, from an empty profile: the markers
 * open, their names hold their sequences on the public routing path, today's
 * marker advances `soak/` by one, and the cap and the purge keep the bin.
 */

import { readFile } from 'node:fs/promises';
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
  markerBytes,
  markerFile,
  oldestMarkerLine,
  overCap,
  purgeDue,
  republishDue,
  sequencesLine,
  type SequenceReading,
} from './markers';
import { SoakFailure } from './reasons';
import { resolveUntil } from './recordReader';
import { inspectVault, ledgerPath, readLedger, SETTINGS_MS, writeLedger } from './vault';

/** Each wait below ends inside this, so a slow night fails with its own reason. */
const TEST_MS = 5_400_000;
/** A name the ledger holds was published a night ago or more. */
const RESOLVE_MS = 120_000;
const PUBLISH_MS = 300_000;
/** The session-start renewal publishes, then the public path takes it up. */
const RENEWAL_MS = 600_000;
/** Bin expiry queues a due purge on the poll tick, and the queue drains it. */
const PURGE_MS = 600_000;
/** Two reads this far apart let a late publish of the night before land. */
const SETTLE_MS = 65_000;

async function openLedger(files: FilesPage): Promise<Ledger> {
  const found = await inspectVault(files, 'owner');
  if (!found.ledger) {
    throw new SoakFailure(
      'unbootstrapped-or-wiped',
      `the owner vault has no ${ledgerPath('owner')}`
    );
  }
  return readLedger(files);
}

async function toSoak(files: FilesPage): Promise<void> {
  await files.openFromSidebar();
  await files.toRoot();
  await files.open(SOAK_FOLDER);
}

async function opened(files: FilesPage, name: string): Promise<Uint8Array> {
  const download = await files.save(name);
  return new Uint8Array(await readFile(await download.path()));
}

/** The bin retention the owner saved in Settings. A scheduled night writes no settings. */
async function savedRetention(page: Page): Promise<number> {
  const bin = new BinPage(page);
  await bin.open();
  await expect(bin.retention).toHaveAttribute('data-origin', /.+/, { timeout: SETTINGS_MS });
  const origin = await bin.retention.getAttribute('data-origin');
  const days = Number(await bin.retention.getAttribute('data-days'));
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
  const ledger = await check('owner marker ledger', 'ledger-unreadable', () => openLedger(files));
  const list = byDate(markers(ledger));

  await check('owner markers open', 'marker-unreadable', async () => {
    for (const marker of list) {
      const bytes = await opened(files, markerFile(marker.date));
      if (!Buffer.from(bytes).equals(Buffer.from(markerBytes(marker.date)))) {
        throw new SoakFailure(
          'marker-unreadable',
          `the marker of ${marker.date} opened other bytes`
        );
      }
    }
  });
  await fact('owner oldest marker', oldestMarkerLine(list[0], today));

  const readings = await check('owner marker sequences', 'sequence-regressed', async () => {
    const out: SequenceReading[] = [];
    for (const marker of list) {
      const shown = await files.ipnsName(markerFile(marker.date));
      if (shown !== marker.ipnsName) {
        throw new SoakFailure(
          'sequence-regressed',
          `the marker of ${marker.date} shows a new name`
        );
      }
      const floor = BigInt(marker.sequence);
      const reading = await resolveUntil(shown, (r) => r.sequence >= floor, RESOLVE_MS);
      if (reading.sequence < floor) {
        throw new SoakFailure(
          'sequence-regressed',
          `the marker of ${marker.date} resolved at ${reading.sequence}, ledger ${floor}`
        );
      }
      out.push({ date: marker.date, ledger: marker.sequence, resolved: reading.sequence });
    }
    return out;
  });
  await fact('owner marker sequences', sequencesLine(readings));

  const oldest = list[0];
  if (oldest !== undefined && republishDue(oldest, today)) {
    await check('oldest marker republished', 'republish-missed', async () => {
      const next = BigInt(oldest.sequence) + 1n;
      const renewed = (r: IpnsRecordReading) =>
        r.sequence >= next && freshValidity(r.validUntil, Date.now());
      const reading = await resolveUntil(oldest.ipnsName, renewed, RENEWAL_MS);
      if (!renewed(reading) || reading.sequence !== next) {
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
  let ledger = await check('owner marker ledger', 'ledger-unreadable', () => openLedger(files));

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
      await new Promise((resolve) => setTimeout(resolve, SETTLE_MS));
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
    const leaving = overCap(markers(ledger)).map((marker) => marker.date);
    if (leaving.length === 0) return ledger;
    await toSoak(files);
    // The ledger goes first: a marker it lists must open, so it never lists one in the bin.
    const next = binMarkers(ledger, leaving, today);
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
        else await bin.appeared(markerFile(entry.date));
      }
    }
    if (due.length > 0) {
      await toSoak(files);
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
