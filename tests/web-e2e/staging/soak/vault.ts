/**
 * The ledger in the vault, through the shipped UI only (ADR 0049 D3): the
 * listing finds it, the text editor reads and rewrites it, and the bootstrap
 * builds the folders it lives in.
 */

import { expect, type Page } from '@playwright/test';
import { BinPage } from '../../page-objects/bin.page';
import type { FilesPage } from '../../page-objects/files.page';
import { SettingsPage } from '../../page-objects/settings.page';
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

/** How long the settings read and save get. */
const SETTINGS_MS = 60_000;

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
  if (!soakFolder) return { soakFolder, ledger: false, rootNames };

  for (const folder of LEDGER_FOLDERS[role]) {
    if (!(await listed(files, folder))) return { soakFolder, ledger: false, rootNames };
    await files.open(folder);
    await synced(files);
  }
  return { soakFolder, ledger: await listed(files, LEDGER_FILE), rootNames };
}

/** Archives an existing `soak/`, then builds the folders and an empty ledger. */
export async function bootstrapVault(
  files: FilesPage,
  role: SoakRole,
  found: FoundVault,
  day: string
): Promise<void> {
  if (role === 'owner') {
    await saveDefaultSettings(files.page);
    await files.openFromSidebar();
  }
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

/**
 * Saves the Settings form once when the vault reads the default settings: bin
 * expiry runs only on a saved retention, and only a dispatch writes settings.
 */
async function saveDefaultSettings(page: Page): Promise<void> {
  if ((await binRetention(page)).origin !== 'defaults') return;
  const settings = new SettingsPage(page);
  await settings.open();
  await expect(settings.binRetention).not.toHaveValue('', { timeout: SETTINGS_MS });
  await settings.save();
  await expect(settings.savedMark).toBeVisible({ timeout: SETTINGS_MS });
}

/** The bin retention as the bin page shows it, once the settings read lands. */
export async function binRetention(page: Page): Promise<{ origin: string | null; days: number }> {
  const bin = new BinPage(page);
  await bin.open();
  await expect(bin.retention).toHaveAttribute('data-origin', /.+/, { timeout: SETTINGS_MS });
  return {
    origin: await bin.retention.getAttribute('data-origin'),
    days: Number(await bin.retention.getAttribute('data-days')),
  };
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
