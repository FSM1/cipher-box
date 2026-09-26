/**
 * The scaffolding the vault specs share: a cold-started tab, and the wait that
 * proves a write reached the network rather than an optimistic overlay.
 */

import type { Locator, Page } from '@playwright/test';
import { expect } from './fixtures';
import { FilesPage } from './page-objects/files.page';
import { VaultPage } from './page-objects/vault.page';

/** Multi-byte and multi-line, so no transfer that mangles either passes. */
export const PAYLOAD = 'ciphertext round trip\n\tédition — 中文\r\nlast line without a newline';

export interface ListedChild {
  readonly id: string;
  readonly name: string;
  readonly kind: string;
}

export interface Listing {
  readonly children: readonly ListedChild[];
}

/**
 * One listed child's node id, by name. A name the listing does not carry is a
 * test defect, so it fails here rather than at whatever read used the id.
 */
export function nodeOf(listing: Listing, name: string): string {
  const found = listing.children.filter((child) => child.name === name);
  if (found.length === 0) {
    throw new Error(`the listing carries no ${name}; it carries ${namesOf(listing).join(', ')}`);
  }
  if (found.length > 1) {
    throw new Error(`the listing carries ${found.length} children named ${name}`);
  }
  return found[0].id;
}

/** Sorted, so a whole-listing assertion does not ride the order a read returns. */
export function namesOf(listing: Listing): string[] {
  return listing.children.map((child) => child.name).sort();
}

const PROBE = 'probe';

/**
 * Signs `page` in and waits for the settled vault root. `signIn` answers with
 * the account id; the default cold-starts a vault nobody else shares.
 */
export async function coldStart(
  page: Page,
  signIn: (vault: VaultPage) => Promise<string> = (vault) => vault.coldStart()
): Promise<{ vault: VaultPage; files: FilesPage; accountId: string }> {
  const vault = new VaultPage(page);
  const files = new FilesPage(page);
  await vault.open();
  await vault.controlled();
  const accountId = await signIn(vault);
  await vault.settled();
  await expect(files.browser).toBeVisible();
  return { vault, files, accountId };
}

/**
 * The root's published children, once the queue has drained past the write
 * under test. That write is followed by a probe folder because the queue is
 * strict FIFO: the probe's pending mark clears only after everything ahead of
 * it published, and a write that takes its own row off the root — a delete, a
 * move out — otherwise leaves a settle nothing to wait on.
 */
export async function drained(files: FilesPage, vault: VaultPage): Promise<string[]> {
  await files.createFolder(PROBE);
  const { view } = await vault.settled();
  expect(view.deadLetters).toEqual([]);
  return view.children
    .filter((child) => child.name !== PROBE)
    .map((child) => `${child.kind} ${child.name}`)
    .sort();
}

/**
 * Runs the nocache refresh on `vault` until `target` counts `count`. A change
 * another client published reaches this tab only on a pass.
 */
export async function refreshedUntil(
  vault: VaultPage,
  target: Locator,
  count = 1,
  timeout = 120_000
): Promise<void> {
  await expect
    .poll(
      async () => {
        await vault.refresh();
        return target.count();
      },
      { timeout, intervals: [1_000] }
    )
    .toBe(count);
}
