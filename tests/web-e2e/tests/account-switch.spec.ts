/**
 * Owner-local state across account switches on one browser profile: signing a
 * second account in reclaims only the first one's snapshot cache, and a forget
 * erases only the account that asked for it (blueprint/web-client.md "Logout").
 *
 * Two owner accounts share one browser context, so one origin's stores; the
 * recipient claims from a context of its own. The step numbers are the five
 * steps of the account-switch check this spec automates.
 */

import type { Browser, BrowserContext, Page } from '@playwright/test';
import { freshLogin, type Login } from '../devices';
import { expect, test } from '../fixtures';
import { LoginPage } from '../page-objects/login.page';
import { SettingsPage } from '../page-objects/settings.page';
import { SharePage } from '../page-objects/share.page';
import { claim } from '../sharing';
import { coldStart } from '../vault';

const FOLDER_A = 'minted-by-a';
const FOLDER_B = 'minted-by-b';

/** The binding a profile answers with the held secret of the account it names. */
const SECRET_BINDING = '__cipherboxE2eAccountSecret';

/** One browser profile that holds two owner logins, so both open their stores on one origin. */
async function sharedProfile(browser: Browser, logins: readonly Login[]): Promise<BrowserContext> {
  const context = await browser.newContext();
  await context.exposeFunction(SECRET_BINDING, (accountId: string) => {
    const login = logins.find((held) => held.accountId === accountId);
    if (login === undefined) throw new Error(`the profile holds no login for ${accountId}`);
    return login.secret;
  });
  return context;
}

/** Signs `page` in as `login` through the held secret, and waits for the settled vault. */
async function signInAs(page: Page, login: Login) {
  return coldStart(page, async () => {
    await page.evaluate(
      async ({ account, binding }) => {
        const held = (window as unknown as Record<string, (id: string) => Promise<string>>)[
          binding
        ];
        await window.__CIPHERBOX_ENGINE__!.signIn(await held(account), account);
      },
      { account: login.accountId, binding: SECRET_BINDING }
    );
    await page.waitForURL('**/files');
    return login.accountId;
  });
}

/** What one account's containers on this origin hold, read off the public storage surface. */
interface AccountStores {
  /** The store suffix of each IndexedDB database the account names. */
  readonly databases: string[];
  /** The store suffix of each OPFS directory the account names. */
  readonly directories: string[];
  /** The staged records in the account's staging directory; temps excluded. */
  readonly staged: number;
  /** The ops in the account's op queue. */
  readonly queued: number;
}

async function storesOf(page: Page, accountId: string): Promise<AccountStores> {
  return page.evaluate(
    async ({ infix }) => {
      // Containers are `<dbPrefix>-<accountId>-<suffix>`, and an account id is
      // a fresh UUID, so the infix alone names this account's containers.
      const named = (name: string | undefined): name is string =>
        name !== undefined && name.includes(infix);
      const suffix = (name: string) => name.slice(name.indexOf(infix) + infix.length);
      const names = (await indexedDB.databases()).map((database) => database.name).filter(named);
      const databases = names.map(suffix).sort();
      const request = <T>(req: IDBRequest<T>) =>
        new Promise<T>((resolve, reject) => {
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
      // Opened only when listed: an open of an absent name would create it.
      const queue = names.find((name) => suffix(name) === 'staging');
      let queued = 0;
      if (queue !== undefined) {
        const db = await request(indexedDB.open(queue));
        try {
          if (db.objectStoreNames.contains('ops')) {
            queued = await request(db.transaction('ops').objectStore('ops').count());
          }
        } finally {
          db.close();
        }
      }
      const root = await navigator.storage.getDirectory();
      const directories: string[] = [];
      let staged = 0;
      for await (const [name, handle] of root.entries()) {
        if (!named(name) || handle.kind !== 'directory') continue;
        directories.push(suffix(name));
        if (suffix(name) !== 'staging-staged') continue;
        for await (const key of (handle as FileSystemDirectoryHandle).keys()) {
          if (!key.startsWith('.cbtmp.')) staged += 1;
        }
      }
      return { databases, directories: directories.sort(), staged, queued };
    },
    { infix: `-${accountId}-` }
  );
}

/** Polls `accountId`'s stores until `check` passes; the sweeps behind them run detached. */
async function storesUntil(
  page: Page,
  accountId: string,
  check: (stores: AccountStores) => void
): Promise<AccountStores> {
  let latest!: AccountStores;
  await expect(async () => {
    latest = await storesOf(page, accountId);
    check(latest);
  }).toPass({ timeout: 30_000, intervals: [500] });
  return latest;
}

/** Cold-starts `login`'s vault, publishes `folder`, mints a link on it, and signs out. */
async function mintAndSignOut(page: Page, login: Login, folder: string): Promise<URL> {
  const { files, vault } = await signInAs(page, login);
  await files.createFolder(folder);
  await vault.settled();
  const share = new SharePage(page);
  await share.open(folder);
  const link = await share.mintLink();
  await expect(share.linkChips).toHaveCount(1);
  await share.close();
  await files.signOut();
  await expect(page).toHaveURL(/\/$/);
  return link;
}

test('@full owner-local state survives an account switch, and a forget erases only its own account', async ({
  browser,
}) => {
  test.setTimeout(300_000);
  const a = freshLogin();
  const b = freshLogin();
  const profile = await sharedProfile(browser, [a, b]);
  const page = await profile.newPage();

  const link = await test.step('1. account A mints an invite link and signs out', async () => {
    return mintAndSignOut(page, a, FOLDER_A);
  });
  const aBefore = await storesOf(page, a.accountId);
  expect(aBefore.databases).toContain('staging');
  expect(aBefore.directories).toEqual(['staging-staged']);
  expect(aBefore.staged).toBeGreaterThan(0);

  const bBefore =
    await test.step('2. account B signs in on the same profile, mints a link, and signs out', async () => {
      await mintAndSignOut(page, b, FOLDER_B);
      // B's sign-in reclaims A's snapshot cache and nothing else of A's.
      await storesUntil(page, a.accountId, (stores) => {
        expect(stores.databases).not.toContain('snapshot-cache');
        expect(stores.databases).toEqual(
          aBefore.databases.filter((name) => name !== 'snapshot-cache')
        );
        expect(stores.directories).toEqual(aBefore.directories);
        expect(stores.staged).toBe(aBefore.staged);
        expect(stores.queued).toBe(aBefore.queued);
      });
      return storesOf(page, b.accountId);
    });

  const recipient = await test.step('3. the recipient claims the link of A', async () => {
    return claim(browser, link);
  });

  await test.step('4. account A signs back in, still holds its link, and converts the claim', async () => {
    await signInAs(page, a);
    const share = new SharePage(page);
    await share.openUntilLinks(FOLDER_A, 1);
    await share.openUntilGranted(FOLDER_A, 1);
    await expect(share.permission).toHaveValue('read');
    await expect(share.error).toHaveCount(0);
    await share.close();
  });

  await test.step('5. forgetting the device as A erases A only, and B signs in over its own state', async () => {
    const settings = new SettingsPage(page);
    await settings.open();
    await expect(settings.accountId).toHaveText(a.accountId);
    await settings.forgetDevice();
    await expect(page).toHaveURL(/\/$/);
    await expect(new LoginPage(page).googleButton).toBeVisible();

    await storesUntil(page, a.accountId, (stores) => {
      expect(stores.databases).toEqual([]);
      expect(stores.directories).toEqual([]);
    });
    // A's sign-in in step 4 reclaimed B's snapshot cache; the rest of B stays.
    const bAfter = await storesOf(page, b.accountId);
    expect(bAfter.databases).toEqual(bBefore.databases.filter((name) => name !== 'snapshot-cache'));
    expect(bAfter.directories).toEqual(bBefore.directories);
    expect(bAfter.staged).toBe(bBefore.staged);
    expect(bAfter.queued).toBe(bBefore.queued);

    await signInAs(page, b);
    const share = new SharePage(page);
    await share.openUntilLinks(FOLDER_B, 1);
    await expect(share.error).toHaveCount(0);
    await share.close();
  });

  await recipient.context().close();
  await profile.close();
});
