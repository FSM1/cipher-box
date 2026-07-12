import { test, expect, Browser, type Route } from '@playwright/test';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { cleanupTestFiles, createTestTextFile } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Descent-vs-Restore Race Regression (SC3c / D-08 item 11)
 *
 * Proves the descent-vs-restore data-integrity race is closed: a fast
 * `navigateUp` (or breadcrumb) click issued while a subfolder descent is still
 * resolving must NOT let the superseded descent repoint the SDK's active
 * shared-folder writeKey/depth. If it does, a write performed at the depth the
 * user is *actually* viewing gets misrouted into the stale descent target
 * (`useSharedNavigationActions.ts::navigateToSubfolder` +
 * `packages/sdk/src/client.ts` `sharedFolderTree` active-depth state).
 *
 * Determinism (NO sleeps / NO poll-timing reliance): the descent's IPNS
 * resolve (`GET /ipns/resolve`, the network hop inside
 * `client.descendSharedChild`) is HELD open via Playwright route interception.
 * While it is held the test issues a breadcrumb restore back to the share root
 * (an in-memory nav-stack replay that takes no network round-trip for its state
 * change and runs synchronously in the app), then RELEASES the held descent.
 * The ordering is therefore fully controlled: the descent always resolves
 * AFTER the restore has already superseded it.
 *
 * Assertions (the write must land at the currently-viewed depth):
 *  - After releasing the descent, the breadcrumb stays at the RESTORED depth
 *    (the share root folder) — the superseded descent does not yank the UI
 *    into the deeper target.
 *  - A file uploaded at the restored depth appears THERE, and is ABSENT from
 *    the descent-target subfolder (proving the active writeKey/depth was not
 *    repointed by the stale descent).
 *
 * This is a PERMANENT regression test. Do NOT `test.skip` / `test.fixme` /
 * defer it — before the two-layer generation-token guard it goes RED (the
 * released descent repoints the active depth and the upload lands in the
 * deeper subfolder), and GREEN once the guard discards the superseded descent.
 *
 * Modeled on the owner+grantee dual-account scaffolding used by
 * writable-shares.spec.ts / shared-folder-desync.spec.ts
 * (utils/multi-account-wallet.ts).
 *
 * Accounts:
 * - owner: creates and write-shares the root folder.
 * - grantee: write-share recipient; builds the nested A/B fixture and drives
 *   the descent-vs-restore race + the disambiguating upload.
 */
test.describe.serial('Descent-vs-Restore Race (SC3c / D-08 item 11)', () => {
  let browser: Browser;
  let owner: WalletTestAccount;
  let grantee: WalletTestAccount;

  // Page objects
  let ownerFileList: FileListPage;
  let ownerContextMenu: ContextMenuPage;
  let ownerCreateFolderDialog: CreateFolderDialogPage;
  let ownerShareDialog: ShareDialogPage;

  let granteeSharedBrowser: SharedFileBrowserPage;

  // Test data - unique per run
  const runId = Date.now().toString();
  const rootFolderName = `descent-root-${runId}`;
  const subfolderA = `descent-a-${runId}`;
  const subfolderB = `descent-b-${runId}`;
  const restoredUploadName = `restored-upload-${runId}.txt`;

  // ============================================
  // grantee helpers
  // ============================================

  async function granteeMkdir(name: string): Promise<void> {
    const mkdirBtn = grantee.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await mkdirBtn.click();
    const folderInput = grantee.page.locator('.shared-inline-input-field');
    await folderInput.waitFor({ state: 'visible', timeout: 5000 });
    await folderInput.fill(name);
    await folderInput.press('Enter');
    await granteeSharedBrowser.getFolderItem(name).waitFor({ state: 'visible', timeout: 60000 });
  }

  // ============================================
  // Setup and Teardown
  // ============================================

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (owner || grantee) {
      await closeWalletTestAccounts([owner, grantee].filter(Boolean));
    }
  });

  // ============================================
  // Phase 1: Account Setup + Write Share
  // ============================================

  test('1.1 Create test accounts (owner, grantee)', async () => {
    test.setTimeout(300_000); // 2 sequential wallet logins (up to 90s each) + vault init
    owner = await createWalletTestAccount(browser, 'owner');
    grantee = await createWalletTestAccount(browser, 'grantee');

    ownerFileList = new FileListPage(owner.page);
    ownerContextMenu = new ContextMenuPage(owner.page);
    ownerCreateFolderDialog = new CreateFolderDialogPage(owner.page);
    ownerShareDialog = new ShareDialogPage(owner.page);

    granteeSharedBrowser = new SharedFileBrowserPage(grantee.page);

    expect(owner.publicKey).not.toBe(grantee.publicKey);
  });

  test('1.2 Owner creates a folder and write-shares it with the grantee', async () => {
    const newFolderButton = owner.page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await ownerCreateFolderDialog.waitForOpen();
    await ownerCreateFolderDialog.createFolder(rootFolderName);
    await ownerFileList.waitForItemToAppear(rootFolderName, { timeout: 30000 });

    await ownerFileList.rightClickItem(rootFolderName);
    await ownerContextMenu.waitForOpen();
    await ownerContextMenu.clickShare();
    await ownerShareDialog.waitForOpen();
    await ownerShareDialog.waitForRecipientsLoaded();

    const writeBtn = owner.page.locator('.share-perm-btn', { hasText: '[ READ-WRITE ]' });
    await writeBtn.click();
    await expect(writeBtn).toHaveClass(/share-perm-btn--active/);

    await ownerShareDialog.shareWithKey(grantee.publicKey);
    const successText = await ownerShareDialog.waitForSuccess({ timeout: 60000 });
    expect(successText).toContain('read-write');

    await ownerShareDialog.close();
  });

  // ============================================
  // Phase 2: Grantee builds the nested A/B fixture
  // ============================================

  test('2.1 Grantee builds root/A/B nesting, then sits at depth 1 (A)', async () => {
    test.setTimeout(120000);

    await navigateToShared(grantee);
    await granteeSharedBrowser.waitForLoaded({ timeout: 30000 });
    await granteeSharedBrowser.waitForSharedItem(rootFolderName, { timeout: 15000 });

    // Enter root (depth 0), create subfolder A there.
    await granteeSharedBrowser.navigateIntoFolder(rootFolderName);
    await granteeMkdir(subfolderA);

    // Descend into A (depth 1, navStack = [root]) and create subfolder B inside.
    await granteeSharedBrowser.navigateIntoSubfolder(subfolderA);
    await granteeMkdir(subfolderB);

    // Confirm we are viewing A (depth 1) with B visible as its child — this is
    // the state from which the race is driven (navStack non-empty, so
    // navigateUp exercises the restore helper, not the shared-root fallback).
    await expect(
      granteeSharedBrowser.breadcrumbs().locator('.breadcrumb-item--current')
    ).toHaveText(subfolderA, { ignoreCase: true, timeout: 15000 });
    await granteeSharedBrowser
      .getFolderItem(subfolderB)
      .waitFor({ state: 'visible', timeout: 15000 });
  });

  // ============================================
  // Phase 3: Descent-vs-Restore race (deterministic via route interception)
  // ============================================

  test('3.1 A navigateUp during an in-flight descent does not misroute the next write (SC3c)', async () => {
    test.setTimeout(120000);

    // HOLD the descent's IPNS resolve so the race window is fully controlled.
    // While `holding`, matching requests are parked (not continued); the test
    // releases them explicitly after the restore has superseded the descent.
    let holding = false;
    const held: Route[] = [];
    const routeGlob = '**/ipns/resolve*';
    await grantee.page.route(routeGlob, async (route) => {
      if (holding) {
        held.push(route);
        return;
      }
      await route.continue();
    });

    // Arm the gate and START the descent into B (depth 1 -> depth 2) WITHOUT
    // awaiting its completion — its IPNS resolve is now parked.
    holding = true;
    await granteeSharedBrowser.doubleClickFolderItem(subfolderB);

    // Deterministically wait until the descent's resolve is actually parked —
    // this replaces any timing sleep.
    await expect.poll(() => held.length, { timeout: 30000 }).toBeGreaterThan(0);

    // While the descent is parked, restore to the share root by clicking its
    // breadcrumb (navigateToBreadcrumb -> the restore helper). The descent has
    // flipped the browser into its loading state, which UNMOUNTS the file list
    // and the [..] parent-dir row — but the breadcrumb nav stays mounted, so
    // the breadcrumb click is the reliable in-flight restore trigger. Restore
    // is a synchronous in-memory nav-stack replay (no network hop for the state
    // change) that bumps the shared-folder seed generation before the descent
    // is ever released.
    await granteeSharedBrowser
      .breadcrumbs()
      .locator('button.breadcrumb-item', { hasText: rootFolderName })
      .click();
    await expect(
      granteeSharedBrowser.breadcrumbs().locator('.breadcrumb-item--current')
    ).toHaveText(rootFolderName, { ignoreCase: true, timeout: 15000 });

    // RELEASE the held descent (and any nav-triggered refresh resolves parked
    // alongside it). The descent now resolves AFTER the restore — a superseded
    // descent must be discarded at both the web hook and the SDK active-depth.
    holding = false;
    for (const route of held) {
      await route.continue().catch(() => {
        /* request may already be aborted by navigation teardown */
      });
    }
    held.length = 0;
    await grantee.page.unroute(routeGlob);

    // The superseded descent must NOT yank the UI into the deeper target: the
    // breadcrumb stays at the restored (share root) depth.
    await expect(
      granteeSharedBrowser.breadcrumbs().locator('.breadcrumb-item--current')
    ).toHaveText(rootFolderName, { ignoreCase: true, timeout: 15000 });

    // The decisive data-integrity assertion: a write issued at the restored
    // depth must land HERE (the share root), not inside the descent target B.
    const uploadBtn = grantee.page.locator('.toolbar-btn', { hasText: '--upload' });
    await expect(uploadBtn).toBeVisible({ timeout: 10000 });
    const testFile = createTestTextFile(
      restoredUploadName,
      'Written at the restored depth after a superseded descent (SC3c)'
    );
    const fileInput = grantee.page.locator('input[type="file"]');
    await fileInput.setInputFiles(testFile.path);

    // The upload appears at the restored depth (share root), and NO write-key /
    // GCM-auth error toast is surfaced.
    await granteeSharedBrowser
      .getFolderItem(restoredUploadName)
      .waitFor({ state: 'visible', timeout: 30000 });
    await expect(grantee.page.locator('.shared-error[role="alert"]')).toHaveCount(0);

    // And it must be ABSENT from the descent target B — descend root -> A -> B
    // and confirm the file did not get misrouted there.
    await granteeSharedBrowser.navigateIntoSubfolder(subfolderA);
    await granteeSharedBrowser.navigateIntoSubfolder(subfolderB);
    await expect(granteeSharedBrowser.getFolderItem(restoredUploadName)).toHaveCount(0);
  });
});
