/**
 * A cold start over a vault that already holds files paints each file row's
 * size and modified cells, at the root, inside a subfolder, and inside a
 * folder the owner shared, with no manual refresh. A second owner device is
 * the cold start: a new browser context has empty stores, so every child
 * record it lists comes off the network.
 */

import type { Page } from '@playwright/test';
import { deviceTest as test, freshLogin, type Login, type OpenDevice, type Tab } from '../devices';
import { expect } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { VaultPage } from '../page-objects/vault.page';
import { drained } from '../vault';

const ROOT_FILE = 'root.bin';
const FOLDER = 'deep';
const DEEP_FILE = 'deep.bin';
const DEEPER = 'deeper';
const DEEPER_FILE = 'deeper.bin';
const SHARED = 'shared';
const SHARED_FILE = 'shared.bin';
const BYTES = new Uint8Array(2048);
const SIZE = '2 KB';
const UNRESOLVED = '...';

const CELLS = { timeout: 60_000, intervals: [1_000] };

/**
 * Device A runs `write`, waits until the root's published children are
 * `children`, and goes offline. Answers with what `write` answers.
 */
async function seed<T>(
  device: OpenDevice,
  login: Login,
  children: string[],
  write: (tab: Tab) => Promise<T>
): Promise<T> {
  const a = await device(login);
  const tab = await a.online();
  const result = await write(tab);
  await tab.files.toRoot();
  expect(await drained(tab.files, tab.vault)).toEqual(children);
  await a.offline();
  return result;
}

const NESTED = [`file ${ROOT_FILE}`, `folder ${FOLDER}`];

/** A file at the root and one in a subfolder. Answers with the subfolder's route. */
async function nested({ files }: Tab): Promise<string> {
  await files.upload(ROOT_FILE, BYTES);
  await files.createFolder(FOLDER);
  await expect(files.row(FOLDER)).toBeVisible();
  const deep = await files.row(FOLDER).getAttribute('data-node-id');
  expect(deep).toBeTruthy();

  await files.open(FOLDER);
  await files.upload(DEEP_FILE, BYTES);
  await expect(files.row(DEEP_FILE)).toBeVisible();
  await files.published();
  return `/files/${deep}`;
}

/** A folder inside a folder, with one file. Answers with the inner folder's route. */
async function twiceNested({ files }: Tab): Promise<string> {
  await files.createFolder(FOLDER);
  await files.open(FOLDER);
  await files.createFolder(DEEPER);
  await expect(files.row(DEEPER)).toBeVisible();
  const deeper = await files.row(DEEPER).getAttribute('data-node-id');
  expect(deeper).toBeTruthy();

  await files.open(DEEPER);
  await files.upload(DEEPER_FILE, BYTES);
  await expect(files.row(DEEPER_FILE)).toBeVisible();
  await files.published();
  return `/files/${deeper}`;
}

/** A folder with one file, shared by a read link. */
async function shared({ files, share }: Tab): Promise<void> {
  await files.createFolder(SHARED);
  await files.open(SHARED);
  await files.upload(SHARED_FILE, BYTES);
  await expect(files.row(SHARED_FILE)).toBeVisible();
  await files.published();

  await files.toRoot();
  // The mint cuts the folder into its own scope, which is the state under test.
  await share.open(SHARED);
  await share.mintLink({ permission: 'read' });
  await share.close();
}

/**
 * An in-app navigation: the session is in-memory, so a document load would
 * land the tab back on the front door.
 */
async function visit(page: Page, path: string): Promise<void> {
  await page.evaluate((target) => {
    window.history.pushState(null, '', target);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

/**
 * A cold device signed in on `login`, with no wait for its root to settle: a
 * first route lands as early as the sign-in allows.
 */
async function signedInUnsettled(
  device: OpenDevice,
  login: Login
): Promise<{ page: Page; files: FilesPage }> {
  const c = await device(login);
  const page = await c.page();
  const vault = new VaultPage(page);
  await vault.open();
  await vault.controlled();
  await c.signIn(page);
  await page.waitForURL('**/files');
  return { page, files: new FilesPage(page) };
}

/** Waits until `name`'s row paints its size and a resolved modified date. */
async function painted(files: FilesPage, name: string): Promise<void> {
  await expect(files.row(name)).toBeVisible();
  await expect(async () => {
    const cells = await files.cells(name);
    expect(cells.size).toBe(SIZE);
    expect(cells.modified).not.toBe(UNRESOLVED);
  }).toPass(CELLS);
}

test('a cold start paints file sizes and dates at the root and in a subfolder', async ({
  device,
}) => {
  const login = freshLogin();
  const deep = await seed(device, login, NESTED, nested);

  const b = await device(login);
  const { page, files } = await b.online();
  await test.step('root cells', () => painted(files, ROOT_FILE));

  await visit(page, deep);
  await files.at(FOLDER);
  await test.step('subfolder cells', () => painted(files, DEEP_FILE));
});

test('a cold start whose first route is a subfolder paints its file cells', async ({ device }) => {
  const login = freshLogin();
  const deep = await seed(device, login, NESTED, nested);

  const { page, files } = await signedInUnsettled(device, login);
  // No wait for the root to settle: the navigation lands as early as the sign-in
  // allows. The engine suite pins the order where the focus lands before the first pass.
  await visit(page, deep);
  await files.at(FOLDER);
  await test.step('subfolder cells', () => painted(files, DEEP_FILE));

  await files.toRoot();
  await test.step('root cells', () => painted(files, ROOT_FILE));
});

test('a cold start whose first route is two folders down shows that folder and its trail', async ({
  device,
}) => {
  const login = freshLogin();
  const deeper = await seed(device, login, [`folder ${FOLDER}`], twiceNested);

  const { page, files } = await signedInUnsettled(device, login);
  // The cold-start base holds the root's own children alone, as after a reload.
  await visit(page, deeper);
  await files.at(DEEPER);
  await expect(files.breadcrumbs).toContainText(`~/root/${FOLDER}/${DEEPER}`);
  await test.step('inner folder cells', () => painted(files, DEEPER_FILE));
});

test('a cold start paints the file cells of a folder the owner shared', async ({ device }) => {
  const login = freshLogin();
  await seed(device, login, [`folder ${SHARED}`], shared);

  const b = await device(login);
  const { files } = await b.online();
  await expect(files.row(SHARED)).toBeVisible();
  await files.open(SHARED);
  await test.step('shared folder cells', () => painted(files, SHARED_FILE));
});
