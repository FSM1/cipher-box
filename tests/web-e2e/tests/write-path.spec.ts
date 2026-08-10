/**
 * The write half of the smoke slice (blueprint/testing.md "E2E"): folder CRUD
 * and an upload read back off the network, driven through the shipped chrome
 * against the live stack. Every case asserts on a drained queue carrying no
 * dead letter — a refused block store answers 503, which the drain charges as
 * a spent attempt and abandons the op, so "the row is on screen" alone would
 * pass over a write that never published.
 */

import type { Page } from '@playwright/test';
import { expect, test } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { VaultPage } from '../page-objects/vault.page';

/** Multi-byte and multi-line, so no transfer that mangles either passes. */
const PAYLOAD = 'ciphertext round trip\n\tédition — 中文\r\nlast line without a newline';

const PROBE = 'probe';

async function coldStart(page: Page): Promise<{ vault: VaultPage; files: FilesPage }> {
  const vault = new VaultPage(page);
  const files = new FilesPage(page);
  await vault.open();
  await vault.coldStart();
  await vault.settled();
  await expect(files.browser).toBeVisible();
  return { vault, files };
}

/**
 * The root's published children, once the queue has drained past the write
 * under test. That write is followed by a probe folder because the queue is
 * strict FIFO: the probe's pending mark clears only after everything ahead of
 * it published, and a write that takes its own row off the root — a delete, a
 * move out — otherwise leaves a settle nothing to wait on.
 */
async function drained(files: FilesPage, vault: VaultPage): Promise<string[]> {
  await files.createFolder(PROBE);
  const { view } = await vault.settledNow();
  expect(view.deadLetters).toEqual([]);
  return view.children
    .filter((child) => child.name !== PROBE)
    .map((child) => `${child.kind} ${child.name}`)
    .sort();
}

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

  // The preview proves the read path renders; only the saved bytes prove the
  // round trip preserved them, since decoding folds a BOM and normalises.
  expect(await files.preview('notes.txt')).toBe(PAYLOAD);
  expect(await files.downloadShown()).toEqual(bytes);
});
