/**
 * The vault checks of the owner web leg, from an empty profile: the markers
 * open, their names hold their sequences on the public routing path, today's
 * marker advances `soak/` by one, and the cap and the purge keep the bin.
 */

import { readFile } from 'node:fs/promises';
import type { Page } from '@playwright/test';
import { BinPage } from '../../page-objects/bin.page';
import { FilesPage } from '../../page-objects/files.page';
import { SettingsPage } from '../../page-objects/settings.page';
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
import { inspectVault, ledgerPath, readLedger, writeLedger } from './vault';

const TEST_MS = 1_800_000;
/** A name the ledger holds was published a night ago or more. */
const RESOLVE_MS = 120_000;
const PUBLISH_MS = 300_000;
/** The session-start renewal publishes, then the public path takes it up. */
const RENEWAL_MS = 600_000;
/** Bin expiry queues a due purge on the poll tick, and the queue drains it. */
const PURGE_MS = 600_000;

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

/**
 * The bin retention the owner saved in Settings. Bin expiry runs only on a
 * saved retention, so a vault that reads the defaults saves them once.
 */
async function savedRetention(page: Page): Promise<number> {
  const bin = new BinPage(page);
  await bin.open();
  await expect(bin.retention).toHaveAttribute('data-origin', /.+/, { timeout: 180_000 });
  if ((await bin.retention.getAttribute('data-origin')) === 'defaults') {
    const settings = new SettingsPage(page);
    await settings.open();
    await expect(settings.binRetention).not.toHaveValue('', { timeout: 180_000 });
    await settings.save();
    await expect(settings.savedMark).toBeVisible({ timeout: 180_000 });
    await bin.open();
    await expect(bin.retention).toHaveAttribute('data-origin', 'resolved', { timeout: 180_000 });
  }
  const days = Number(await bin.retention.getAttribute('data-days'));
  if (!Number.isInteger(days) || days <= 0) {
    throw new SoakFailure('purge-missed', `the saved bin retention is ${days} days, so no bin`);
  }
  return days;
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
      if (reading === null || reading.sequence < floor) {
        throw new SoakFailure(
          'sequence-regressed',
          `the marker of ${marker.date} resolved at ${reading?.sequence ?? 'no record'}, ledger ${floor}`
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
      const renewed = (r: { sequence: bigint; validUntil: bigint | null }) =>
        r.sequence >= next && freshValidity(r.validUntil, Date.now());
      const reading = await resolveUntil(oldest.ipnsName, renewed, RENEWAL_MS);
      if (reading === null || !renewed(reading)) {
        throw new SoakFailure(
          'republish-missed',
          `the marker of ${oldest.date} resolved at ${reading?.sequence ?? 'no record'}, valid to ${reading?.validity ?? '-'}; ledger ${oldest.sequence}`
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
  let ledger = await check('owner marker ledger', 'ledger-unreadable', () => openLedger(files));

  if (markers(ledger).some((marker) => marker.date === today)) {
    await fact("today's marker", `${today} is in the ledger already`);
  } else {
    const folder = await check('soak/ sequence', 'sequence-not-advanced', async () => {
      await files.toRoot();
      const ipnsName = await files.ipnsName(SOAK_FOLDER);
      const reading = await resolveUntil(ipnsName, () => true, RESOLVE_MS);
      if (reading === null) {
        throw new SoakFailure('sequence-not-advanced', `${SOAK_FOLDER}/ resolved no record`);
      }
      await files.open(SOAK_FOLDER);
      return { ipnsName, before: reading.sequence };
    });

    ledger = await check("today's marker", 'sequence-not-advanced', async () => {
      const file = markerFile(today);
      await files.upload(file, markerBytes(today));
      await expect(files.row(file)).toBeVisible({ timeout: 180_000 });
      await files.published();
      const ipnsName = await files.ipnsName(file);
      const reading = await resolveUntil(ipnsName, () => true, PUBLISH_MS);
      if (reading === null) {
        throw new SoakFailure('sequence-not-advanced', `the marker of ${today} resolved no record`);
      }
      const next = appendMarker(ledger, {
        date: today,
        ipnsName,
        sequence: Number(reading.sequence),
      });
      await writeLedger(files, next);
      return next;
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
      if (reading?.sequence !== expected) {
        throw new SoakFailure(
          'sequence-not-advanced',
          `${SOAK_FOLDER}/ resolved at ${reading?.sequence ?? 'no record'}, not ${expected}`
        );
      }
      await cold.open(SOAK_FOLDER);
      await expect(cold.row(markerFile(today))).toBeVisible({ timeout: 180_000 });
      await fact("today's marker", `${today}; ${SOAK_FOLDER}/ ${folder.before} to ${expected}`);
    });
  }

  const retentionDays = await check('owner bin retention', 'purge-missed', () =>
    savedRetention(owner)
  );

  ledger = await check('owner marker cap', 'purge-missed', async () => {
    const leaving = overCap(markers(ledger));
    if (leaving.length === 0) return ledger;
    await toSoak(files);
    // The ledger goes first: a marker it lists must open, so it never lists one in the bin.
    const next = binMarkers(
      ledger,
      leaving.map((marker) => marker.date),
      today
    );
    await writeLedger(files, next);
    for (const marker of leaving) {
      await files.remove(markerFile(marker.date));
      await expect(files.row(markerFile(marker.date))).toHaveCount(0);
    }
    await files.published();
    return next;
  });

  await check('owner bin purge', 'purge-missed', async () => {
    const binned = binnedMarkers(ledger);
    const due = binned.filter((entry) => purgeDue(entry, retentionDays, today));
    if (due.length > 0) {
      const bin = new BinPage(owner);
      await bin.open();
      for (const entry of due) await bin.gone(markerFile(entry.date), PURGE_MS);
      await toSoak(files);
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
