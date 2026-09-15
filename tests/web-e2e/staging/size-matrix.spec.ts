/**
 * Profile: size matrix. Real Kubo ingest and a real gateway read through the
 * CDN, asserted byte for byte at each size.
 */

import { readFile } from 'node:fs/promises';
import { FilesPage } from '../page-objects/files.page';
import { expect, published, signIn, test } from './fixtures';
import { filler } from './media';

const SIZES = [
  100,
  1_024,
  5 * 1_024,
  10 * 1_024,
  50 * 1_024,
  100 * 1_024,
  250 * 1_024,
  500 * 1_024,
];

test('every size reads back byte for byte', async ({ page }) => {
  const files = new FilesPage(page);
  await signIn(page);

  const sent = new Map<string, Uint8Array>();
  for (const size of SIZES) {
    const name = `size-${size}.bin`;
    const bytes = filler(size);
    sent.set(name, bytes);
    await files.upload(name, bytes);
    await expect(files.row(name)).toBeVisible({ timeout: 180_000 });
  }
  await published(page);

  for (const [name, bytes] of sent) {
    const download = await files.save(name);
    const saved = await download.path();
    expect(new Uint8Array(await readFile(saved)), `${name} read back`).toEqual(bytes);
  }
  await expect(page.getByTestId('vault-action-error')).toHaveCount(0);
});
