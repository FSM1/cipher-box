import { test as setup, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { mediaFixtures, mediaPath, writeMediaFixtures } from './media';

setup('the fixture media is on disk', async () => {
  await writeMediaFixtures();
  for (const fixture of Object.values(mediaFixtures())) {
    expect(new Uint8Array(await readFile(mediaPath(fixture)))).toEqual(fixture.bytes);
  }
});
