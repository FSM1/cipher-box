/**
 * Profile: media. Each fixture kind uploaded, previewed, and asserted on the
 * surface its kind renders. The two video files carry the ranged reads the
 * stream pipe makes through the real front.
 */

import type { Page } from '@playwright/test';
import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { mediaFixtures, mediaPath } from './media';

/** The same-origin path the media pipe serves a ticket under. */
const STREAM_PATH = '/stream/';

/** One window of the plaintext, read back through the ticket. */
async function readWindow(page: Page, url: string, first: number, last: number) {
  return page.evaluate(
    async ([ticket, range]) => {
      const response = await fetch(ticket, { headers: { range } });
      return {
        status: response.status,
        bytes: Array.from(new Uint8Array(await response.arrayBuffer())),
      };
    },
    [url, `bytes=${first}-${last}`] as const
  );
}

/** What the player element points at, once the dialog mounted it. */
async function streamUrl(page: Page, testId: string): Promise<string> {
  const element = page.getByTestId(testId);
  await expect(element).toBeVisible({ timeout: 120_000 });
  const url = await element.evaluate((node) => (node as HTMLMediaElement).src);
  // A ticket is a bearer token, so the origin is part of the assertion: a
  // `/stream/` path on a foreign origin would hand the ticket away.
  const ticket = new URL(url);
  expect(ticket.origin, `${testId} origin ${url}`).toBe(new URL(page.url()).origin);
  expect(ticket.pathname.startsWith(STREAM_PATH), `${testId} src ${url}`).toBe(true);
  return url;
}

test('every fixture kind previews on the surface its kind renders', async ({ page }) => {
  const files = new FilesPage(page);
  const fixtures = mediaFixtures();
  await signIn(page);

  const all = Object.values(fixtures);
  await page.getByLabel('Choose files to upload').setInputFiles(all.map(mediaPath));
  for (const fixture of all) {
    await expect(files.row(fixture.name)).toBeVisible({ timeout: 300_000 });
  }
  await published(page);

  // The PNG is a 64-pixel square, so a decoded image reports its own side and a
  // broken one reports zero.
  await files.openPreview(fixtures.image.name);
  const image = page.getByTestId('preview-image');
  await expect(image).toBeVisible({ timeout: 120_000 });
  await expect
    .poll(() => image.evaluate((node) => (node as HTMLImageElement).naturalWidth), {
      timeout: 60_000,
    })
    .toBe(64);
  await files.closePreview();

  // A PDF never streams: the dialog hands the viewer a buffered blob.
  await files.openPreview(fixtures.document.name);
  const pdf = page.getByTestId('preview-pdf');
  await expect(pdf).toBeVisible({ timeout: 120_000 });
  await expect(pdf).toHaveAttribute('src', /^blob:/);
  await files.closePreview();

  // One second of 8 kHz mono, so a decoded WAV reports about one second.
  await files.openPreview(fixtures.audio.name);
  const audio = page.getByTestId('media-player-audio');
  await expect(audio).toBeVisible({ timeout: 120_000 });
  await expect
    .poll(() => audio.evaluate((node) => (node as HTMLAudioElement).duration), { timeout: 60_000 })
    .toBeCloseTo(1, 1);
  await expect(page.getByTestId('media-player-error')).toHaveCount(0);
  await files.closePreview();

  // The video containers carry no decodable track, so the assertion is on the
  // ranged read the pipe makes rather than on playback.
  for (const fixture of [fixtures.videoSmall, fixtures.videoLarge]) {
    await files.openPreview(fixture.name);
    const url = await streamUrl(page, 'media-player-video');

    const head = await readWindow(page, url, 0, 15);
    expect(head.status, `${fixture.name} head`).toBe(206);
    expect(new Uint8Array(head.bytes)).toEqual(fixture.bytes.subarray(0, 16));

    // Past the pipe's first read window, so the offset arithmetic is exercised
    // rather than a single whole-file read.
    if (fixture.bytes.length > 1_500_016) {
      const deep = await readWindow(page, url, 1_500_000, 1_500_015);
      expect(deep.status, `${fixture.name} deep window`).toBe(206);
      expect(new Uint8Array(deep.bytes)).toEqual(fixture.bytes.subarray(1_500_000, 1_500_016));
    }
    await files.closePreview();
  }
});
