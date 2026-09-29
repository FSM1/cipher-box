/**
 * The ledger in the vault, through the shipped UI only (ADR 0049 D3): the
 * listing finds it, the text editor reads and rewrites it, and the bootstrap
 * builds the folders it lives in.
 */

import { expect, type Page } from '@playwright/test';
import { FilesPage } from '../../page-objects/files.page';
import type { SoakRole } from './accounts';
import { archiveName, planRun, SOAK_FOLDER } from './bootstrap';
import { emptyLedger, formatLedger, parseLedger, type Ledger } from './ledger';
import { SoakFailure } from './reasons';

export const LEDGER_FILE = 'ledger.txt';

/** The folders from the vault root to the ledger. The grantee ledger lists the OS markers. */
export const LEDGER_FOLDERS: Readonly<Record<SoakRole, readonly string[]>> = {
  owner: [SOAK_FOLDER],
  grantee: [SOAK_FOLDER, 'desktop'],
};

/** How long a listing gets to show a row before the row counts as absent. */
const LISTED_WITHIN_MS = 60_000;

/**
 * Leaves `page` in the ledger folder and returns the ledger. With `bootstrap`,
 * it first archives an existing `soak/` folder and builds a new one around an
 * empty ledger; without it, a vault with no ledger fails as
 * `unbootstrapped-or-wiped` before any write.
 */
export async function openLedger(
  page: Page,
  role: SoakRole,
  bootstrap: boolean,
  day: string
): Promise<Ledger> {
  const files = new FilesPage(page);
  const folders = LEDGER_FOLDERS[role];
  await synced(files);

  const soakFolder = await listed(files, SOAK_FOLDER);
  const rootNames = await listedNames(files);
  let ledger = soakFolder;
  for (const folder of folders) {
    if (!ledger || !(await listed(files, folder))) {
      ledger = false;
      break;
    }
    await files.open(folder);
    await synced(files);
  }
  ledger = ledger && (await listed(files, LEDGER_FILE));

  const plan = planRun(bootstrap, { soakFolder, ledger });
  if (plan.kind === 'refuse') {
    throw new SoakFailure(
      plan.reason,
      `the ${role} vault has no ${folders.join('/')}/${LEDGER_FILE}`
    );
  }
  if (plan.kind === 'bootstrap') {
    await toRoot(files);
    if (plan.archive) {
      await files.rename(SOAK_FOLDER, archiveName(day, rootNames));
      await files.published();
    }
    for (const folder of folders) {
      await files.createFolder(folder);
      await files.published();
      await files.open(folder);
    }
    await files.upload(LEDGER_FILE, new TextEncoder().encode(formatLedger(emptyLedger())));
    await expect(files.row(LEDGER_FILE)).toBeVisible({ timeout: 180_000 });
    await files.published();
  }
  return readLedger(files);
}

/** Reads the ledger in the folder on screen, through the editor, and closes it unchanged. */
export async function readLedger(files: FilesPage): Promise<Ledger> {
  const field = await files.openEditor(LEDGER_FILE);
  const text = await field.inputValue();
  await files.cancelEditor();
  return parseLedger(text);
}

/** Rewrites the ledger in the folder on screen, in place, and waits for the publish. */
export async function writeLedger(files: FilesPage, ledger: Ledger): Promise<void> {
  const text = formatLedger(ledger);
  const field = await files.openEditor(LEDGER_FILE);
  await field.fill(text);
  await files.saveEditor();
  await files.published();
}

async function synced(files: FilesPage): Promise<void> {
  await expect(files.status).toHaveAttribute('data-staleness', 'fresh', { timeout: 180_000 });
}

async function listed(files: FilesPage, name: string): Promise<boolean> {
  return files
    .row(name)
    .waitFor({ state: 'visible', timeout: LISTED_WITHIN_MS })
    .then(
      () => true,
      () => false
    );
}

async function listedNames(files: FilesPage): Promise<Set<string>> {
  const labels = await files.browser
    .getByTestId('file-list-item')
    .getByRole('checkbox')
    .evaluateAll((boxes) => boxes.map((box) => box.getAttribute('aria-label') ?? ''));
  return new Set(labels.map((label) => label.replace(/^select /, '')));
}

async function toRoot(files: FilesPage): Promise<void> {
  await files.page.getByRole('button', { name: 'root', exact: true }).click();
  await expect(files.breadcrumbs.locator('[aria-current="page"]')).toHaveText('root');
}
