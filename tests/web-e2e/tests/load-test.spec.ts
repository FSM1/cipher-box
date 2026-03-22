import { test, expect, Browser, Page } from '@playwright/test';
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { loginViaWallet, createWalletContext } from '../utils/wallet-login-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { BreadcrumbsPage } from '../page-objects/file-browser/breadcrumbs.page';
import { SelectionActionBarPage } from '../page-objects/file-browser/selection-action-bar.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { RenameDialogPage } from '../page-objects/dialogs/rename-dialog.page';
import { ConfirmDialogPage } from '../page-objects/dialogs/confirm-dialog.page';
import { MoveDialogPage } from '../page-objects/dialogs/move-dialog.page';
import { createTestTextFile, createTestBinaryFile, cleanupTestFiles } from '../utils/test-files';

/**
 * Load Test — Concurrent Users Against Staging
 *
 * Each client gets a unique wallet (keypair) injected via EIP-6963 mock provider.
 * Full auth flow: wallet → SIWE sign → Core Kit → key reconstruction → vault init.
 * Then drives ~50+ file operations that each trigger IPNS publishes.
 *
 * Usage:
 *   cd tests/web-e2e
 *   pnpm exec playwright test tests/load-test.spec.ts --config=playwright.load.config.ts
 *
 * Env vars:
 *   LOAD_TEST_CLIENTS=5   Number of concurrent clients (default: 3)
 */

const NUM_CLIENTS = parseInt(process.env.LOAD_TEST_CLIENTS ?? '5', 10);

// Generous timeouts — multiple clients hitting staging concurrently
test.setTimeout(600_000); // 10 minutes

interface LoadClient {
  id: number;
  account: PrivateKeyAccount;
  page: Page;
  context: Awaited<ReturnType<Browser['newContext']>>;
  fileList: FileListPage;
  uploadZone: UploadZonePage;
  contextMenu: ContextMenuPage;
  breadcrumbs: BreadcrumbsPage;
  selectionBar: SelectionActionBarPage;
  createFolderDialog: CreateFolderDialogPage;
  renameDialog: RenameDialogPage;
  confirmDialog: ConfirmDialogPage;
  moveDialog: MoveDialogPage;
}

// Operation timeout — each individual UI action
const OP_TIMEOUT = 30_000;

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Recover page to a known state: dismiss any open modals/menus, navigate to root.
 * Called after a failed op to prevent cascading failures.
 */
async function resetState(client: LoadClient): Promise<void> {
  try {
    // Press Escape a few times to dismiss modals/menus/dialogs
    for (let i = 0; i < 3; i++) {
      await client.page.keyboard.press('Escape');
      await client.page.waitForTimeout(200);
    }
    // Click on an empty area to deselect
    await client.page.mouse.click(0, 0);
    await client.page.waitForTimeout(300);
    // Navigate to root if breadcrumbs are visible
    const breadcrumbVisible = await client.breadcrumbs
      .container()
      .isVisible()
      .catch(() => false);
    if (breadcrumbVisible) {
      await client.breadcrumbs.clickBreadcrumb('my vault').catch(() => {});
      await client.page.waitForTimeout(1000);
    }
  } catch {
    // Best-effort reset — if the page is completely broken, subsequent ops will also fail
  }
}

/** Safe wrapper for operations — logs failures but doesn't abort the run */
async function op(
  client: LoadClient,
  description: string,
  fn: () => Promise<void>
): Promise<boolean> {
  try {
    await fn();
    console.log(`    [C${client.id}] ✓ ${description}`);
    return true;
  } catch (err) {
    console.warn(`    [C${client.id}] ✗ ${description}: ${(err as Error).message.slice(0, 120)}`);
    await resetState(client);
    return false;
  }
}

/** Navigate to root via breadcrumbs */
async function goToRoot(client: LoadClient): Promise<void> {
  await client.breadcrumbs.clickBreadcrumb('my vault');
  await client.page.waitForTimeout(1000);
}

/** Navigate into a subfolder */
async function enterFolder(client: LoadClient, folderName: string): Promise<void> {
  await client.fileList.doubleClickFolder(folderName);
  await client.breadcrumbs.waitForPathToContain(folderName, { timeout: OP_TIMEOUT });
}

/** Create a folder via the UI */
async function createFolder(client: LoadClient, name: string): Promise<void> {
  // Ensure the new folder button is ready
  await client.page
    .locator('.file-browser-new-folder-button')
    .waitFor({ state: 'visible', timeout: 10_000 });
  await client.page.locator('.file-browser-new-folder-button').click();
  await client.createFolderDialog.waitForOpen({ timeout: 5000 });
  await client.createFolderDialog.createFolder(name);
  await client.fileList.waitForItemToAppear(name, { timeout: OP_TIMEOUT });
}

/** Upload a file and wait for it to appear */
async function uploadFile(client: LoadClient, filePath: string, fileName: string): Promise<void> {
  await client.uploadZone.uploadFile(filePath);
  await client.uploadZone.waitForUploadComplete({ timeout: OP_TIMEOUT });
  await client.fileList.waitForItemToAppear(fileName, { timeout: OP_TIMEOUT });
}

/** Right-click → Rename */
async function renameItem(client: LoadClient, oldName: string, newName: string): Promise<void> {
  await client.fileList.rightClickItem(oldName);
  await client.contextMenu.waitForOpen({ timeout: 5000 });
  await client.contextMenu.clickRename();
  await client.renameDialog.waitForOpen({ timeout: 5000 });
  await client.renameDialog.rename(newName);
  await client.fileList.waitForItemToAppear(newName, { timeout: OP_TIMEOUT });
}

/** Right-click → Move to folder */
async function moveItem(client: LoadClient, itemName: string, destFolder: string): Promise<void> {
  await client.fileList.rightClickItem(itemName);
  await client.contextMenu.waitForOpen({ timeout: 5000 });
  await client.contextMenu.clickMove();
  await client.moveDialog.waitForOpen({ timeout: 5000 });
  // Use .first() to avoid strict mode violation when folder names are substrings
  // of other folder names (e.g., "c1-data" matching both "c1-data" and "c1-data-sub")
  await client.moveDialog.getFolderItem(destFolder).first().click();
  await client.moveDialog.clickMove();
  await client.moveDialog.waitForClose();
  await client.fileList.waitForItemToDisappear(itemName, { timeout: OP_TIMEOUT });
}

/** Right-click → Delete (with confirm) */
async function deleteItem(client: LoadClient, itemName: string): Promise<void> {
  await client.fileList.rightClickItem(itemName);
  await client.contextMenu.waitForOpen({ timeout: 5000 });
  await client.contextMenu.clickDelete();
  await client.confirmDialog.waitForOpen({ timeout: 5000 });
  await client.confirmDialog.clickConfirm();
  await client.fileList.waitForItemToDisappear(itemName, { timeout: OP_TIMEOUT });
}

/** Delete account by calling the API from within the page context.
 *  Uses fetch with credentials to send the refresh token cookie,
 *  gets a fresh access token, then calls DELETE /auth/account. */
async function deleteAccount(client: LoadClient): Promise<void> {
  // Discover the API base URL from the app's runtime config
  const apiBase = await client.page.evaluate(() => {
    // Vite injects env vars at build time — read from the same source as apiClient
    return (
      (window as Record<string, string>).__VITE_API_URL ||
      document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
      'https://api-staging.cipherbox.cc'
    );
  });

  const deleted = await client.page.evaluate(async (apiUrl: string) => {
    // Step 1: Refresh to get a fresh access token (uses HTTP-only cookie)
    const refreshRes = await fetch(`${apiUrl}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!refreshRes.ok) return { ok: false, step: 'refresh', status: refreshRes.status };
    const { accessToken } = await refreshRes.json();

    // Step 2: Delete the account
    const deleteRes = await fetch(`${apiUrl}/auth/account`, {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ confirmation: 'DELETE' }),
    });
    return { ok: deleteRes.ok, step: 'delete', status: deleteRes.status };
  }, apiBase);

  if (!deleted.ok) {
    throw new Error(`Account deletion failed at ${deleted.step}: HTTP ${deleted.status}`);
  }
}

/** Multi-select items and batch move */
async function batchMove(
  client: LoadClient,
  itemNames: string[],
  destFolder: string
): Promise<void> {
  // Select first item normally, then Ctrl+click the rest
  await client.fileList.selectItem(itemNames[0]);
  for (let i = 1; i < itemNames.length; i++) {
    await client.fileList.ctrlClickItem(itemNames[i]);
  }
  await client.selectionBar.waitForVisible({ timeout: 5000 });
  await client.selectionBar.clickMove();
  await client.moveDialog.waitForOpen({ timeout: 5000 });
  await client.moveDialog.getFolderItem(destFolder).first().click();
  await client.moveDialog.clickMove();
  await client.moveDialog.waitForClose();
  // Wait for all items to disappear from current view
  for (const name of itemNames) {
    await client.fileList.waitForItemToDisappear(name, { timeout: OP_TIMEOUT });
  }
}

/** Multi-select items and batch delete */
async function batchDelete(client: LoadClient, itemNames: string[]): Promise<void> {
  await client.fileList.selectItem(itemNames[0]);
  for (let i = 1; i < itemNames.length; i++) {
    await client.fileList.ctrlClickItem(itemNames[i]);
  }
  await client.selectionBar.waitForVisible({ timeout: 5000 });
  await client.selectionBar.clickDelete();
  await client.confirmDialog.waitForOpen({ timeout: 5000 });
  await client.confirmDialog.clickConfirm();
  for (const name of itemNames) {
    await client.fileList.waitForItemToDisappear(name, { timeout: OP_TIMEOUT });
  }
}

// ─── Main client workload ──────────────────────────────────────────────────

/**
 * Full workload for a single client. ~50+ operations, each triggering IPNS publish.
 *
 * Structure:
 *   Phase 1: Create folder hierarchy (5 folders + 2 subfolders)     →  7 publishes
 *   Phase 2: Upload small text files (15 files across folders)      → 15 publishes
 *   Phase 3: Upload medium binary files (10 files)                  → 10 publishes
 *   Phase 4: Upload large binary files (5 files, 100KB–500KB)       →  5 publishes
 *   Phase 5: Edit text files (5 edits)                              →  5 publishes
 *   Phase 6: Rename items (8 renames: files + folders)              →  8 publishes
 *   Phase 7: Move items between folders (6 individual moves)        →  6 publishes
 *   Phase 8: Batch move (2 batches of 3 files)                      →  2 publishes
 *   Phase 9: Batch delete (2 batches of 3–4 files)                  →  2 publishes
 *   Phase 10: Individual deletes + cleanup (remaining items)        → ~10 publishes
 *                                                             Total: ~70 publishes
 */
async function runClientWorkload(
  client: LoadClient
): Promise<{ succeeded: number; failed: number }> {
  const { id } = client;
  const prefix = `c${id}`;
  let succeeded = 0;
  let failed = 0;

  const count = (ok: boolean) => {
    if (ok) succeeded++;
    else failed++;
  };

  // ─── Warm-up: first mutation after login races with initial sync polling.
  // Create and delete a dummy folder to let the sync settle.
  await op(client, 'Warm-up folder', async () => {
    await createFolder(client, `${prefix}-warmup`);
    await deleteItem(client, `${prefix}-warmup`);
  });

  // ─── Phase 1: Create folder hierarchy ────────────────────────────────
  console.log(`  [C${id}] Phase 1: Creating folder hierarchy...`);

  const folders = ['docs', 'images', 'data', 'archive', 'temp'];
  const folderNames = folders.map((f) => `${prefix}-${f}`);

  for (const name of folderNames) {
    count(await op(client, `Create folder ${name}`, () => createFolder(client, name)));
  }

  // Create subfolders inside 'docs' and 'data'
  const subfolders = [
    { parent: folderNames[0], name: `${prefix}-docs-sub` },
    { parent: folderNames[2], name: `${prefix}-data-sub` },
  ];
  for (const sub of subfolders) {
    count(
      await op(client, `Create subfolder ${sub.name}`, async () => {
        await enterFolder(client, sub.parent);
        await createFolder(client, sub.name);
        await goToRoot(client);
      })
    );
  }

  // ─── Phase 2: Upload small text files ────────────────────────────────
  console.log(`  [C${id}] Phase 2: Uploading 15 small text files...`);

  const textFiles: { name: string; path: string; folder: string | null }[] = [];
  // 5 files at root
  for (let i = 1; i <= 5; i++) {
    const f = createTestTextFile(
      `${prefix}-note-${i}.txt`,
      `Client ${id} note ${i}. Timestamp: ${Date.now()}. ${'Lorem ipsum dolor sit amet. '.repeat(10)}`
    );
    textFiles.push({ name: f.name, path: f.path, folder: null });
  }
  // 5 files in docs folder
  for (let i = 1; i <= 5; i++) {
    const f = createTestTextFile(
      `${prefix}-doc-${i}.txt`,
      `Document ${i} from client ${id}. ${'Content block. '.repeat(20)}`
    );
    textFiles.push({ name: f.name, path: f.path, folder: folderNames[0] });
  }
  // 5 files in data folder
  for (let i = 1; i <= 5; i++) {
    const f = createTestTextFile(
      `${prefix}-log-${i}.txt`,
      `Log entry ${i}: ${new Date().toISOString()} client=${id} ${'data '.repeat(50)}`
    );
    textFiles.push({ name: f.name, path: f.path, folder: folderNames[2] });
  }

  // Upload root files
  for (const tf of textFiles.filter((f) => !f.folder)) {
    count(await op(client, `Upload ${tf.name}`, () => uploadFile(client, tf.path, tf.name)));
  }
  // Upload into docs
  count(
    await op(client, `Navigate to ${folderNames[0]}`, () => enterFolder(client, folderNames[0]))
  );
  for (const tf of textFiles.filter((f) => f.folder === folderNames[0])) {
    count(await op(client, `Upload ${tf.name}`, () => uploadFile(client, tf.path, tf.name)));
  }
  count(await op(client, 'Back to root', () => goToRoot(client)));

  // Upload into data
  count(
    await op(client, `Navigate to ${folderNames[2]}`, () => enterFolder(client, folderNames[2]))
  );
  for (const tf of textFiles.filter((f) => f.folder === folderNames[2])) {
    count(await op(client, `Upload ${tf.name}`, () => uploadFile(client, tf.path, tf.name)));
  }
  count(await op(client, 'Back to root', () => goToRoot(client)));

  // ─── Phase 3: Upload medium binary files ─────────────────────────────
  console.log(`  [C${id}] Phase 3: Uploading 10 medium binary files (10–50KB)...`);

  const mediumFiles: { name: string; path: string }[] = [];
  for (let i = 1; i <= 10; i++) {
    const sizeKb = 10 + Math.floor(Math.random() * 40); // 10-50KB
    const f = createTestBinaryFile(sizeKb, `${prefix}-medium-${i}.bin`);
    mediumFiles.push({ name: f.name, path: f.path });
  }

  // Upload half to root, half to images folder
  for (const mf of mediumFiles.slice(0, 5)) {
    count(await op(client, `Upload ${mf.name}`, () => uploadFile(client, mf.path, mf.name)));
  }
  count(
    await op(client, `Navigate to ${folderNames[1]}`, () => enterFolder(client, folderNames[1]))
  );
  for (const mf of mediumFiles.slice(5)) {
    count(await op(client, `Upload ${mf.name}`, () => uploadFile(client, mf.path, mf.name)));
  }
  count(await op(client, 'Back to root', () => goToRoot(client)));

  // ─── Phase 4: Upload large binary files ──────────────────────────────
  console.log(`  [C${id}] Phase 4: Uploading 5 large binary files (100–500KB)...`);

  const largeFiles: { name: string; path: string }[] = [];
  const largeSizes = [100, 200, 300, 400, 500];
  for (let i = 0; i < 5; i++) {
    const f = createTestBinaryFile(largeSizes[i], `${prefix}-large-${i + 1}.bin`);
    largeFiles.push({ name: f.name, path: f.path });
  }

  for (const lf of largeFiles) {
    count(
      await op(client, `Upload ${lf.name} (${largeSizes[largeFiles.indexOf(lf)]}KB)`, () =>
        uploadFile(client, lf.path, lf.name)
      )
    );
  }

  // ─── Phase 5: Re-upload files (overwrite triggers IPNS publish) ─────
  // Text editor dialog is unreliable on staging (IPNS resolve for file
  // content hangs). Re-uploading with same filename overwrites the file,
  // which equally triggers metadata update + IPNS publish.
  console.log(`  [C${id}] Phase 5: Re-uploading 5 files (overwrite)...`);

  for (let i = 1; i <= 5; i++) {
    const f = createTestTextFile(
      `${prefix}-note-${i}.txt`,
      `EDITED by client ${id} at ${new Date().toISOString()}. Revision ${i}.\n${'Updated content block. '.repeat(30)}`
    );
    count(await op(client, `Re-upload ${f.name}`, () => uploadFile(client, f.path, f.name)));
  }

  // ─── Phase 6: Rename items ───────────────────────────────────────────
  console.log(`  [C${id}] Phase 6: Renaming 8 items...`);

  // Rename 5 root files
  for (let i = 1; i <= 5; i++) {
    const oldName = `${prefix}-note-${i}.txt`;
    const newName = `${prefix}-renamed-note-${i}.txt`;
    count(
      await op(client, `Rename ${oldName} → ${newName}`, () => renameItem(client, oldName, newName))
    );
  }

  // Rename 2 folders
  count(
    await op(client, `Rename folder ${folderNames[4]}`, () =>
      renameItem(client, folderNames[4], `${prefix}-renamed-temp`)
    )
  );
  count(
    await op(client, `Rename folder ${folderNames[3]}`, () =>
      renameItem(client, folderNames[3], `${prefix}-renamed-archive`)
    )
  );

  // Rename a large file
  count(
    await op(client, `Rename ${largeFiles[0].name}`, () =>
      renameItem(client, largeFiles[0].name, `${prefix}-renamed-large.bin`)
    )
  );

  // ─── Phase 7: Move items between folders ─────────────────────────────
  console.log(`  [C${id}] Phase 7: Moving 6 items individually...`);

  // Move renamed notes into docs folder
  for (let i = 1; i <= 3; i++) {
    const fileName = `${prefix}-renamed-note-${i}.txt`;
    count(
      await op(client, `Move ${fileName} → ${folderNames[0]}`, () =>
        moveItem(client, fileName, folderNames[0])
      )
    );
  }

  // Move medium files into renamed-archive
  for (let i = 1; i <= 3; i++) {
    const fileName = mediumFiles[i - 1].name;
    count(
      await op(client, `Move ${fileName} → ${prefix}-renamed-archive`, () =>
        moveItem(client, fileName, `${prefix}-renamed-archive`)
      )
    );
  }

  // ─── Phase 8: Batch move ─────────────────────────────────────────────
  console.log(`  [C${id}] Phase 8: Batch moving files...`);

  // Batch move remaining medium root files into renamed-temp
  const remainingMedium = mediumFiles.slice(3, 5).map((f) => f.name);
  if (remainingMedium.length >= 2) {
    count(
      await op(client, `Batch move ${remainingMedium.length} files → ${prefix}-renamed-temp`, () =>
        batchMove(client, remainingMedium, `${prefix}-renamed-temp`)
      )
    );
  }

  // Batch move large files (2-4) into data folder
  const largesToMove = largeFiles.slice(1, 4).map((f) => f.name);
  if (largesToMove.length >= 2) {
    count(
      await op(client, `Batch move ${largesToMove.length} large files → ${folderNames[2]}`, () =>
        batchMove(client, largesToMove, folderNames[2])
      )
    );
  }

  // ─── Phase 9: Batch delete ───────────────────────────────────────────
  console.log(`  [C${id}] Phase 9: Batch deleting files...`);

  // Navigate to renamed-archive and batch delete the 3 medium files we moved there
  count(
    await op(client, `Navigate to ${prefix}-renamed-archive`, () =>
      enterFolder(client, `${prefix}-renamed-archive`)
    )
  );
  const archiveFiles = mediumFiles.slice(0, 3).map((f) => f.name);
  if (archiveFiles.length >= 2) {
    count(
      await op(client, `Batch delete ${archiveFiles.length} files from archive`, () =>
        batchDelete(client, archiveFiles)
      )
    );
  }
  count(await op(client, 'Back to root', () => goToRoot(client)));

  // Navigate to data folder and batch delete log files
  count(
    await op(client, `Navigate to ${folderNames[2]}`, () => enterFolder(client, folderNames[2]))
  );
  const dataLogFiles = [`${prefix}-log-1.txt`, `${prefix}-log-2.txt`, `${prefix}-log-3.txt`];
  count(
    await op(client, `Batch delete ${dataLogFiles.length} log files`, () =>
      batchDelete(client, dataLogFiles)
    )
  );
  count(await op(client, 'Back to root', () => goToRoot(client)));

  // ─── Phase 10: Individual cleanup deletes ────────────────────────────
  console.log(`  [C${id}] Phase 10: Cleaning up remaining items...`);

  // Delete remaining root items one by one
  const rootCleanup = [
    `${prefix}-renamed-note-4.txt`,
    `${prefix}-renamed-note-5.txt`,
    `${prefix}-renamed-large.bin`,
    largeFiles[4].name, // large-5 still at root
  ];
  for (const item of rootCleanup) {
    count(await op(client, `Delete ${item}`, () => deleteItem(client, item)));
  }

  // Delete folders (cascading — contents deleted with folder)
  const foldersToDelete = [
    folderNames[0], // docs (has subfolders + files)
    folderNames[1], // images (has medium files)
    folderNames[2], // data (has subfolder + log files + large files)
    `${prefix}-renamed-archive`,
    `${prefix}-renamed-temp`,
  ];
  for (const folder of foldersToDelete) {
    count(await op(client, `Delete folder ${folder}`, () => deleteItem(client, folder)));
  }

  return { succeeded, failed };
}

// ─── Test ──────────────────────────────────────────────────────────────────

test.describe('Load Test — Concurrent Users', () => {
  const clients: LoadClient[] = [];

  test.afterAll(async () => {
    for (const client of clients) {
      await client.context.close().catch(() => {});
    }
    clients.length = 0;
    cleanupTestFiles();
  });

  test(`${NUM_CLIENTS} concurrent clients, ~70 ops each`, async ({ browser }) => {
    const expectedOps = NUM_CLIENTS * 70;
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Load Test: ${NUM_CLIENTS} clients × ~70 operations each`);
    console.log(`Expected IPNS publishes: ~${expectedOps}`);
    console.log(`${'='.repeat(60)}\n`);

    // ─── Phase 1: Create clients with unique wallets ───────────────────
    console.log('Creating clients with unique wallets...');
    const startCreate = Date.now();

    const clientPromises = Array.from({ length: NUM_CLIENTS }, async (_, i) => {
      const account = privateKeyToAccount(generatePrivateKey());
      const { context, page } = await createWalletContext(browser, account);

      return {
        id: i + 1,
        account,
        page,
        context,
        fileList: new FileListPage(page),
        uploadZone: new UploadZonePage(page),
        contextMenu: new ContextMenuPage(page),
        breadcrumbs: new BreadcrumbsPage(page),
        selectionBar: new SelectionActionBarPage(page),
        createFolderDialog: new CreateFolderDialogPage(page),
        renameDialog: new RenameDialogPage(page),
        confirmDialog: new ConfirmDialogPage(page),
        moveDialog: new MoveDialogPage(page),
      } as LoadClient;
    });

    const createdClients = await Promise.all(clientPromises);
    clients.push(...createdClients);
    console.log(`Created ${clients.length} clients in ${Date.now() - startCreate}ms\n`);

    // ─── Phase 2: Login all clients concurrently ───────────────────────
    console.log('Logging in all clients (wallet → SIWE → Core Kit)...');
    const startLogin = Date.now();

    const loginResults = await Promise.allSettled(
      clients.map(async (client) => {
        const start = Date.now();
        const result = await loginViaWallet(client.page, { timeout: 120_000 });
        console.log(`  [C${client.id}] Login: ${result.outcome} (${Date.now() - start}ms)`);
        return result;
      })
    );

    const activeClients = clients.filter((_, i) => {
      const result = loginResults[i];
      return result.status === 'fulfilled' && result.value.outcome === 'success';
    });

    console.log(
      `${activeClients.length}/${NUM_CLIENTS} logins succeeded in ${Date.now() - startLogin}ms\n`
    );
    expect(activeClients.length).toBeGreaterThan(0);

    // Wait for file browser to be ready and initial sync to settle
    await Promise.all(
      activeClients.map(async (client) => {
        await client.page
          .locator('.file-browser-new-folder-button')
          .waitFor({ state: 'visible', timeout: 30_000 });
        // Let initial sync polling complete before first mutation
        await client.page.waitForTimeout(3000);
      })
    );

    // ─── Phase 3: Run workloads concurrently ───────────────────────────
    console.log(`Running workloads on ${activeClients.length} clients concurrently...\n`);
    const startOps = Date.now();

    const workloadResults = await Promise.allSettled(
      activeClients.map((client) => runClientWorkload(client))
    );

    // ─── Summary ───────────────────────────────────────────────────────
    const totalTime = Date.now() - startOps;
    let totalSucceeded = 0;
    let totalFailed = 0;

    console.log(`\n${'='.repeat(60)}`);
    console.log('LOAD TEST RESULTS');
    console.log(`${'='.repeat(60)}`);

    for (let i = 0; i < workloadResults.length; i++) {
      const r = workloadResults[i];
      if (r.status === 'fulfilled') {
        totalSucceeded += r.value.succeeded;
        totalFailed += r.value.failed;
        console.log(
          `  Client ${activeClients[i].id}: ${r.value.succeeded} succeeded, ${r.value.failed} failed`
        );
      } else {
        console.log(`  Client ${activeClients[i].id}: CRASHED — ${r.reason}`);
      }
    }

    const totalOps = totalSucceeded + totalFailed;
    console.log(`${'─'.repeat(60)}`);
    console.log(`Clients:          ${activeClients.length}`);
    console.log(`Total ops:        ${totalOps} (${totalSucceeded} ok, ${totalFailed} failed)`);
    console.log(`Total time:       ${(totalTime / 1000).toFixed(1)}s`);
    console.log(`Ops/second:       ${(totalOps / (totalTime / 1000)).toFixed(2)}`);
    console.log(`IPNS publishes:   ~${totalSucceeded} (one per successful mutation)`);
    console.log(`${'='.repeat(60)}\n`);
    console.log('Fetch histogram data:');
    console.log(`  ssh -i ~/.ssh/ci-deploy-key root@76.13.151.200 \\`);
    console.log(`    'curl -s http://localhost:3000/metrics' | grep cipherbox_ipfs_ipns_duration`);

    // ─── Phase 4: Delete accounts (cleanup) ─────────────────────────
    console.log('\nCleaning up: deleting test accounts...');
    for (const client of activeClients) {
      try {
        await deleteAccount(client);
        console.log(`  [C${client.id}] Account deleted`);
      } catch (err) {
        console.warn(
          `  [C${client.id}] Account deletion failed: ${(err as Error).message.slice(0, 100)}`
        );
      }
    }
  });
});
