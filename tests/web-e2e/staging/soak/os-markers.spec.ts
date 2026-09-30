/**
 * The grantee web leg: the browser opens every OS marker the desktop legs
 * wrote into the grantee vault, and writes the browser marker the legs read
 * the next night.
 */

import { FilesPage } from '../../page-objects/files.page';
import {
  appendDesktopMarker,
  DESKTOP_FOLDER,
  desktopMarkerBytes,
  desktopMarkers,
  osMarkersLine,
  type DesktopMarker,
} from './desktop';
import { check, expect, fact, test } from './fixtures';
import { utcDay } from './ledger';
import { markerFile, unreadLine } from './markers';
import { SoakFailure } from './reasons';
import { download, listed, openLedger, synced, toLedgerFolder, writeLedger } from './vault';

/** Sign-in 18, ledger 8, opens 20, write 10. */
const TEST_MS = 3_600_000;
const OPENS_MS = 1_200_000;
const DOWNLOAD_MS = 60_000;
const PAGE_MS = 180_000;

/** Opens `soak/desktop/<origin>/`; `false` when the listing never shows it. */
async function openOrigin(files: FilesPage, origin: string): Promise<boolean> {
  await toLedgerFolder(files, 'grantee');
  await synced(files);
  if (!(await listed(files, origin))) return false;
  await files.open(origin);
  await synced(files);
  return true;
}

test('the grantee web leg opens the OS markers and writes a browser marker', async ({
  grantee,
}) => {
  test.setTimeout(TEST_MS);
  const files = new FilesPage(await grantee());
  const today = utcDay(new Date());
  let ledger = await check('grantee desktop ledger', 'ledger-unreadable', () =>
    openLedger(files, 'grantee')
  );
  const all = await check('grantee desktop markers', 'ledger-unparsable', async () =>
    desktopMarkers(ledger)
  );
  const os = all.filter((marker) => marker.origin !== 'web');

  const opened: DesktopMarker[] = [];
  await check('OS markers open in the browser', 'desktop-marker-missing', async () => {
    const deadline = Date.now() + OPENS_MS;
    for (const origin of new Set(os.map((marker) => marker.origin))) {
      if (!(await openOrigin(files, origin))) {
        throw new SoakFailure(
          'desktop-marker-missing',
          `${DESKTOP_FOLDER}/${origin}/ is not listed`
        );
      }
      for (const marker of os.filter((known) => known.origin === origin)) {
        if (Date.now() >= deadline) {
          const left = os.filter((known) => !opened.includes(known));
          throw new SoakFailure(
            'desktop-marker-missing',
            `no time to open ${unreadLine(left.map((m) => `${m.origin} ${m.date}`))}`
          );
        }
        const bytes = await download(files, markerFile(marker.date), DOWNLOAD_MS);
        if (!Buffer.from(bytes).equals(Buffer.from(desktopMarkerBytes(marker)))) {
          throw new SoakFailure(
            'desktop-marker-missing',
            `the ${origin} marker of ${marker.date} opened other bytes`
          );
        }
        opened.push(marker);
      }
    }
  });
  await fact('OS markers opened in the browser', osMarkersLine(opened));

  const browser: DesktopMarker = { origin: 'web', date: today };
  if (all.some((marker) => marker.origin === 'web' && marker.date === today)) {
    await fact('browser marker', `${today} is in the ledger already`);
    return;
  }
  await check('browser marker', 'browser-marker-unwritten', async () => {
    const file = markerFile(today);
    if (!(await openOrigin(files, 'web'))) {
      await files.createFolder('web');
      await files.published();
      await files.open('web');
    }
    if (!(await listed(files, file))) {
      await files.upload(file, desktopMarkerBytes(browser));
      await expect(files.row(file)).toBeVisible({ timeout: PAGE_MS });
      await files.published();
    }
    await toLedgerFolder(files, 'grantee');
    ledger = appendDesktopMarker(ledger, browser);
    await writeLedger(files, ledger);
  });
  await fact('browser marker', `${today} written under ${DESKTOP_FOLDER}/web/`);
});
