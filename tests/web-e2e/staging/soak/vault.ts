/**
 * The ledger in the vault, through the shipped UI only (ADR 0049 D3): the
 * listing finds it, the text editor reads and rewrites it, and the bootstrap
 * builds the folders it lives in.
 */

import { expect } from '@playwright/test';
import type { FilesPage } from '../../page-objects/files.page';
import type { SoakRole } from './accounts';
import { archiveName, SOAK_FOLDER, soakFolderListed, type VaultState } from './bootstrap';
import { emptyLedger, formatLedger, parseLedger, type Ledger } from './ledger';

export const LEDGER_FILE = 'ledger.txt';

/** The folders from the vault root to the ledger. The grantee ledger lists the OS markers. */
export const LEDGER_FOLDERS: Readonly<Record<SoakRole, readonly string[]>> = {
  owner: [SOAK_FOLDER],
  grantee: [SOAK_FOLDER, 'desktop'],
};

/** How long a listing gets to show a row before the row counts as absent. */
const LISTED_WITHIN_MS = 60_000;

export interface FoundVault extends VaultState {
  /** The root names, which the archive name must not take. */
  readonly rootNames: ReadonlySet<string>;
}

/** Walks from the root towards the ledger, writes nothing, and reports what it found. */
export async function inspectVault(files: FilesPage, role: SoakRole): Promise<FoundVault> {
  await synced(files);
  const rowShown = await listed(files, SOAK_FOLDER);
  await synced(files);
  const rootNames = await files.names();
  const soakFolder = soakFolderListed(rowShown, rootNames);

  let ledgerFound = soakFolder;
  for (const folder of LEDGER_FOLDERS[role]) {
    if (!ledgerFound || !(await listed(files, folder))) {
      ledgerFound = false;
      break;
    }
    await files.open(folder);
    await synced(files);
  }
  ledgerFound = ledgerFound && (await listed(files, LEDGER_FILE));
  return { soakFolder, ledger: ledgerFound, rootNames };
}

/** Archives an existing `soak/`, then builds the folders and an empty ledger. */
export async function bootstrapVault(
  files: FilesPage,
  role: SoakRole,
  found: FoundVault,
  day: string
): Promise<void> {
  await files.toRoot();
  if (found.soakFolder) {
    await files.rename(SOAK_FOLDER, archiveName(day, found.rootNames));
    await files.published();
  }
  for (const folder of LEDGER_FOLDERS[role]) {
    await files.createFolder(folder);
    await files.published();
    await files.open(folder);
  }
  await files.upload(LEDGER_FILE, new TextEncoder().encode(formatLedger(emptyLedger())));
  await expect(files.row(LEDGER_FILE)).toBeVisible({ timeout: 180_000 });
  await files.published();
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

export function ledgerPath(role: SoakRole): string {
  return [...LEDGER_FOLDERS[role], LEDGER_FILE].join('/');
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
