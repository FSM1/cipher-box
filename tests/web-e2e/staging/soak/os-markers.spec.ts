/**
 * The grantee web leg: the browser opens every OS marker the desktop legs
 * wrote into the grantee vault, and writes the browser marker the legs read
 * the next night.
 */

import { FilesPage } from '../../page-objects/files.page';
import {
  MARKER_LEGS,
  markersToRead,
  readLine,
  recordMarker,
  type LegMarker,
  type MarkerLeg,
} from './grantee';
import { check, fact, test } from './fixtures';
import { utcDay } from './ledger';
import { markerBytes, markerFile, unreadLine } from './markers';
import { SoakFailure } from './reasons';
import {
  download,
  ensureMarker,
  listed,
  openLedger,
  synced,
  toLedgerFolder,
  writeLedger,
} from './vault';

/** Sign-in 18, ledger 8, listings 5, opens 20, write 9. */
const TEST_MS = 3_600_000;
const OPENS_MS = 1_200_000;
const DOWNLOAD_MS = 60_000;

const OS_LEGS = MARKER_LEGS.filter((leg) => leg !== 'web');

/** Opens `soak/desktop/<leg>/`; `false` when the listing never shows it. */
async function openLeg(files: FilesPage, leg: MarkerLeg): Promise<boolean> {
  await toLedgerFolder(files, 'grantee');
  await synced(files);
  if (!(await listed(files, leg))) return false;
  await files.open(leg);
  await synced(files);
  return true;
}

test('the grantee web leg opens the OS markers and writes a browser marker', async ({
  grantee,
}) => {
  test.setTimeout(TEST_MS);
  const files = new FilesPage(await grantee());
  const today = utcDay(new Date());
  const ledger = await check('grantee desktop ledger', 'ledger-unreadable', () =>
    openLedger(files, 'grantee')
  );

  const read: LegMarker[] = [];
  await check('OS markers open in the browser', 'desktop-marker-missing', async () => {
    const listings: Partial<Record<MarkerLeg, string[]>> = {};
    for (const leg of OS_LEGS) {
      if (await openLeg(files, leg)) listings[leg] = [...(await files.names())];
    }
    const due = markersToRead(ledger, listings, 'web');
    const deadline = Date.now() + OPENS_MS;
    for (const leg of OS_LEGS) {
      const ofLeg = due.filter((marker) => marker.leg === leg);
      if (ofLeg.length === 0) continue;
      if (!(await openLeg(files, leg))) {
        throw new SoakFailure('desktop-marker-missing', `soak/desktop/${leg}/ is not listed`);
      }
      for (const marker of ofLeg) {
        if (Date.now() >= deadline) {
          const left = due.filter((known) => !read.includes(known));
          throw new SoakFailure(
            'desktop-marker-missing',
            `no time to open ${unreadLine(left.map((m) => `${m.leg} ${m.date}`))}`
          );
        }
        const bytes = await download(files, markerFile(marker.date), DOWNLOAD_MS);
        if (!Buffer.from(bytes).equals(Buffer.from(markerBytes(marker.date)))) {
          throw new SoakFailure(
            'desktop-marker-missing',
            `the ${leg} marker of ${marker.date} opened other bytes`
          );
        }
        read.push(marker);
      }
    }
  });
  await fact('OS markers opened in the browser', readLine(read));

  await check('browser marker', 'browser-marker-unwritten', async () => {
    if (!(await openLeg(files, 'web'))) {
      await files.createFolder('web');
      await files.published();
      await files.open('web');
    }
    await ensureMarker(files, today);
    const next = recordMarker(ledger, { leg: 'web', date: today });
    if (next !== ledger) {
      await toLedgerFolder(files, 'grantee');
      await writeLedger(files, next);
    }
  });
  await fact('browser marker', `${today} under soak/desktop/web/`);
});
