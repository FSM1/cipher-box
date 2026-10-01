/**
 * A cold start over a vault that already holds files paints each file row's
 * size and modified cells, at the root, inside a subfolder, and inside a
 * folder the owner shared, with no manual refresh. A second owner device is the cold start: a new browser context has
 * empty stores, so every child record it lists comes off the network.
 */

import type { Page } from '@playwright/test';
import { Device, freshLogin, type Login, type Tab } from '../devices';
import { expect, test as base } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { VaultPage } from '../page-objects/vault.page';
import { drained } from '../vault';

const ROOT_FILE = 'root.bin';
const FOLDER = 'deep';
const DEEP_FILE = 'deep.bin';
const SHARED = 'shared';
const SHARED_FILE = 'shared.bin';
const BYTES = new Uint8Array(2048);
const SIZE = '2 KB';
const UNRESOLVED = '...';

const CELLS = { timeout: 60_000, intervals: [1_000] };

type OpenDevice = (login: Login) => Promise<Device>;

const test = base.extend<{ device: OpenDevice }>({
  device: async ({ browser }, use) => {
    const opened: Device[] = [];
    await use(async (login) => {
      const device = await Device.open(browser, login);
      opened.push(device);
      return device;
    });
    for (const device of opened) await device.close();
  },
});

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
  await expect(files.breadcrumbs.locator('[aria-current="page"]')).toHaveText(FOLDER);
  await test.step('subfolder cells', () => painted(files, DEEP_FILE));
});

test('a cold start whose first route is a subfolder paints its file cells', async ({ device }) => {
  const login = freshLogin();
  const deep = await seed(device, login, NESTED, nested);

  const c = await device(login);
  const page = await c.page();
  const vault = new VaultPage(page);
  const files = new FilesPage(page);
  await vault.open();
  await vault.controlled();
  await c.signIn(page);
  await page.waitForURL('**/files');
  // Before the root settles, so the subfolder is the first listing this device reads.
  await visit(page, deep);
  await expect(files.breadcrumbs.locator('[aria-current="page"]')).toHaveText(FOLDER);
  await test.step('subfolder cells', () => painted(files, DEEP_FILE));

  await files.toRoot();
  await test.step('root cells', () => painted(files, ROOT_FILE));
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
