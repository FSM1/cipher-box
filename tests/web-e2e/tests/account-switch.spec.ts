/**
 * Owner-local state across account switches on one browser profile. A sign-in
 * reclaims only another account's snapshot cache (`RECLAIMED_DATABASES` in
 * `packages/client/src/accountStores.ts`), and a forget erases only its own
 * account (`eraseAccountStores`).
 *
 * The two owner accounts are one device, so one origin's stores. The recipient
 * claims from a context of its own: a claim must come from another session.
 */

import type { Page } from '@playwright/test';
import { Device, freshLogin, type Login } from '../devices';
import { expect, test } from '../fixtures';
import { FilesPage } from '../page-objects/files.page';
import { LoginPage } from '../page-objects/login.page';
import { SettingsPage } from '../page-objects/settings.page';
import { claim, mint } from '../sharing';

const DRAFT = 'draft';
const FOLDER_A = 'shared-by-a';
const FOLDER_B = 'shared-by-b';

/** The suffixes of the containers one account names (`accountStores.ts`, `stagingStore.ts`). */
const SNAPSHOT_CACHE = 'snapshot-cache';
const STAGING = 'staging';
const DATABASES = ['floors', SNAPSHOT_CACHE, STAGING] as const;
const STAGED_DIRECTORY = 'staging-staged';
const OPS_STORE = 'ops';
const TEMP_PREFIX = '.cbtmp.';

/** One account's containers on this origin, read off the public storage surface. */
interface AccountStores {
  /** Which of {@link DATABASES} exist. */
  readonly databases: string[];
  readonly stagedDirectory: boolean;
  /** The staged records in the staged directory; in-flight temps excluded. */
  readonly staged: number;
  readonly queued: number;
}

async function storesOf(page: Page, accountId: string): Promise<AccountStores> {
  return page.evaluate(
    async ({ accountId, suffixes, stagingSuffix, stagedSuffix, opsStore, tempPrefix }) => {
      const spelled = (suffix: string) => `-${accountId}-${suffix}`;
      const listed = (await indexedDB.databases()).flatMap(({ name }) => (name ? [name] : []));
      const databases = suffixes.filter((suffix) =>
        listed.some((name) => name.endsWith(spelled(suffix)))
      );

      let queued = 0;
      const stagingDb = listed.find((name) => name.endsWith(spelled(stagingSuffix)));
      if (stagingDb !== undefined) {
        // An erase can land between the listing and this open, and an open of
        // an absent name must not create it again.
        const db = await new Promise<IDBDatabase | null>((resolve, reject) => {
          const open = indexedDB.open(stagingDb);
          open.onupgradeneeded = () => open.transaction!.abort();
          open.onsuccess = () => resolve(open.result);
          open.onerror = () =>
            open.error?.name === 'AbortError' ? resolve(null) : reject(open.error);
        });
        if (db !== null) {
          try {
            if (db.objectStoreNames.contains(opsStore)) {
              queued = await new Promise<number>((resolve, reject) => {
                const count = db.transaction(opsStore).objectStore(opsStore).count();
                count.onsuccess = () => resolve(count.result);
                count.onerror = () => reject(count.error);
              });
            }
          } finally {
            db.close();
          }
        }
      }

      let stagedDirectory = false;
      let staged = 0;
      const root = await navigator.storage.getDirectory();
      for await (const [name, handle] of root.entries()) {
        if (handle.kind !== 'directory' || !name.endsWith(spelled(stagedSuffix))) continue;
        stagedDirectory = true;
        for await (const key of (handle as FileSystemDirectoryHandle).keys()) {
          if (!key.startsWith(tempPrefix)) staged += 1;
        }
      }
      return { databases, stagedDirectory, staged, queued };
    },
    {
      accountId,
      suffixes: DATABASES,
      stagingSuffix: STAGING,
      stagedSuffix: STAGED_DIRECTORY,
      opsStore: OPS_STORE,
      tempPrefix: TEMP_PREFIX,
    }
  );
}

/**
 * Polls `accountId`'s stores until `check` passes on two reads in a row: the
 * sweeps and the erase run detached from the route change.
 */
async function storesUntil(
  page: Page,
  accountId: string,
  check: (stores: AccountStores) => void
): Promise<AccountStores> {
  let latest!: AccountStores;
  await expect(async () => {
    const first = await storesOf(page, accountId);
    check(first);
    latest = await storesOf(page, accountId);
    expect(latest).toEqual(first);
  }).toPass({ timeout: 30_000, intervals: [500] });
  return latest;
}

/** What a sign-in of another account leaves of `stores`. */
function reclaimed(stores: AccountStores): AccountStores {
  return { ...stores, databases: stores.databases.filter((name) => name !== SNAPSHOT_CACHE) };
}

/**
 * Mints a link on `folder` as `login`, and signs out over a drained queue. The
 * rename takes the kept create out of the queue (ADR 0069 D2), so only
 * owner-local records hold the account's staging.
 */
async function mintAndSignOut(device: Device, login: Login, folder: string): Promise<URL> {
  const page = await device.page();
  const link = await mint(page, DRAFT, () => device.online(login));
  const files = new FilesPage(page);
  await files.rename(DRAFT, folder);
  await files.published();
  await storesUntil(page, login.accountId, (stores) => expect(stores.queued).toBe(0));
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
  const profile = await Device.open(browser, a, b);
  const page = await profile.page();

  const link = await test.step('1. account A mints an invite link and signs out', () =>
    mintAndSignOut(profile, a, FOLDER_A));
  const aBefore = await storesUntil(page, a.accountId, (stores) => {
    expect(stores.databases).toEqual(DATABASES);
    expect(stores.stagedDirectory).toBe(true);
    expect(stores.staged).toBeGreaterThan(0);
    expect(stores.queued).toBe(0);
  });

  const bBefore =
    await test.step('2. account B signs in on the same profile, mints a link, and signs out', async () => {
      await mintAndSignOut(profile, b, FOLDER_B);
      await storesUntil(page, a.accountId, (stores) => expect(stores).toEqual(reclaimed(aBefore)));
      return storesUntil(page, b.accountId, (stores) => {
        expect(stores.databases).toEqual(DATABASES);
        expect(stores.staged).toBeGreaterThan(0);
      });
    });

  const recipient = await test.step('3. the recipient claims the link of A', () =>
    claim(browser, link));

  await test.step('4. account A signs back in, still holds its link, and converts the claim', async () => {
    const { share } = await profile.online(a);
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

    await storesUntil(page, a.accountId, (stores) =>
      expect(stores).toEqual({ databases: [], stagedDirectory: false, staged: 0, queued: 0 })
    );
    await storesUntil(page, b.accountId, (stores) => expect(stores).toEqual(reclaimed(bBefore)));

    const tab = await profile.online(b);
    await tab.share.openUntilLinks(FOLDER_B, 1);
    await expect(tab.share.error).toHaveCount(0);
    await tab.share.close();
  });

  await recipient.context().close();
  await profile.close();
});
