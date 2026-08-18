/**
 * The write half of the smoke slice (blueprint/testing.md "E2E"): folder CRUD
 * and an upload read back off the network, driven through the shipped chrome
 * against the live stack. Every case asserts on a drained queue carrying no
 * dead letter — a refused block store answers 503, which the drain charges as
 * a spent attempt and abandons the op, so "the row is on screen" alone would
 * pass over a write that never published.
 */

import { readFile } from 'node:fs/promises';
import { expect, test } from '../fixtures';
import { coldStart, drained, PAYLOAD } from '../vault';

test('a created folder publishes and is listed', async ({ page }) => {
  const { vault, files } = await coldStart(page);

  await files.createFolder('reports');

  await expect(files.row('reports')).toBeVisible();
  expect(await drained(files, vault)).toEqual(['folder reports']);
});

test('a renamed folder publishes under its new name', async ({ page }) => {
  const { vault, files } = await coldStart(page);
  await files.createFolder('drafts');
  await vault.settledNow();

  await files.rename('drafts', 'final');

  await expect(files.row('final')).toBeVisible();
  await expect(files.row('drafts')).toHaveCount(0);
  expect(await drained(files, vault)).toEqual(['folder final']);
});

test('a moved folder leaves the root and lists under its new parent', async ({ page }) => {
  const { vault, files } = await coldStart(page);
  await files.createFolder('archive');
  await files.createFolder('notes');
  await vault.settledNow();

  await files.move('notes', 'archive');

  await expect(files.row('notes')).toHaveCount(0);
  expect(await drained(files, vault)).toEqual(['folder archive']);

  await files.open('archive');
  await expect(files.breadcrumbs).toContainText('archive');
  await expect(files.row('notes')).toBeVisible();
});

test('a deleted folder leaves the listing', async ({ page }) => {
  const { vault, files } = await coldStart(page);
  await files.createFolder('scratch');
  await vault.settledNow();

  await files.remove('scratch');

  await expect(files.row('scratch')).toHaveCount(0);
  expect(await drained(files, vault)).toEqual([]);
});

test('an uploaded file reads back byte for byte', async ({ page }) => {
  const { vault, files } = await coldStart(page);

  const bytes = new TextEncoder().encode(PAYLOAD);
  await files.upload('notes.txt', bytes);

  await expect(files.row('notes.txt')).toBeVisible();
  expect(await drained(files, vault)).toEqual(['file notes.txt']);

  // The one route that both leaves the tab and keeps the bytes exact, so it is
  // what settles the round trip.
  const saved = await files.save('notes.txt');
  expect(new Uint8Array(await readFile(await saved.path()))).toEqual(bytes);

  // A save reads in ranges; this is the whole-file read, which is a separate
  // engine path, and the preview is the third way the chrome shows a file.
  expect(await vault.read('notes.txt')).toEqual(bytes);
  expect(await files.preview('notes.txt')).toBe(PAYLOAD);
});
