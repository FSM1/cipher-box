import { test, expect, Browser } from '@playwright/test';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  navigateToFiles,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Shared Folder Desync Regression (SC#5 / SDK-READ-03)
 *
 * Proves the desync bug class is closed: the owner sees a grantee's upload
 * into a shared folder WITHOUT the owner performing any write of their own,
 * and the new file's size/modifiedAt render from the resolved listing
 * (ResolvedChild), not from the pre-fix SealedChildRef mirror. The mirror is
 * only ever populated by the writer, so an owner who never wrote the file
 * would see the em-dash placeholder ('—', FileListItem.tsx) for size/date
 * under the old (buggy) read path.
 *
 * The proof is driven by the deterministic nav-triggered re-resolve (D-03):
 * the owner navigates into the shared folder for the first time after the
 * grantee's upload. This must NOT rely on the 30s IPNS poll -- no test in
 * this spec waits out poll timing.
 *
 * EXPECTED-RED until the web cutover (Phase 68.2 Plans 06-11) rewires
 * folder.store.ts into a pure projection over `folder:updated` /
 * `ResolvedChild[]` events (D-01/D-03). Turns green as part of the Plan 12
 * phase gate (`pnpm --filter @cipherbox/web-e2e test`). Do NOT test.skip or
 * test.fixme this spec -- it is a permanent regression test, not WIP.
 *
 * Modeled on the multi-account owner+grantee scaffolding used by
 * sharing-workflow.spec.ts and writable-shares.spec.ts
 * (utils/multi-account-wallet.ts).
 *
 * Accounts:
 * - owner: creates and shares the folder (never writes into it after sharing)
 * - grantee: write-share recipient, uploads the file the owner must see
 */
test.describe.serial('Shared Folder Desync (SC#5)', () => {
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
  const sharedFolderName = `desync-folder-${runId}`;
  const granteeUploadedFileName = `grantee-upload-${runId}.txt`;
  const granteeUploadedFileContent = 'Uploaded by grantee without the owner writing first (SC#5)';

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
  // Phase 1: Account Setup + Folder Share
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

  test('1.2 Owner creates a folder and shares it with the grantee (write permission)', async () => {
    // Create the folder that will host the grantee's upload.
    const newFolderButton = owner.page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await ownerCreateFolderDialog.waitForOpen();
    await ownerCreateFolderDialog.createFolder(sharedFolderName);
    await ownerFileList.waitForItemToAppear(sharedFolderName, { timeout: 30000 });

    // Share it with the grantee using WRITE permission -- the grantee must be
    // able to upload without the owner co-writing.
    await ownerFileList.rightClickItem(sharedFolderName);
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
  // Phase 2: Grantee Uploads Without Owner Writing
  // ============================================

  test('2.1 Grantee uploads a file into the shared folder', async () => {
    test.setTimeout(60000);

    await navigateToShared(grantee);
    await granteeSharedBrowser.waitForLoaded({ timeout: 30000 });
    await granteeSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
    await granteeSharedBrowser.navigateIntoFolder(sharedFolderName);

    const testFile = createTestTextFile(granteeUploadedFileName, granteeUploadedFileContent);
    const fileInput = grantee.page.locator('input[type="file"]');
    await fileInput.setInputFiles(testFile.path);

    await granteeSharedBrowser.getFolderItem(granteeUploadedFileName).waitFor({
      state: 'visible',
      timeout: 30000,
    });
  });

  // ============================================
  // Phase 3: Owner Sees the Upload via Nav-Triggered Re-Resolve (SC#5 / D-03)
  // ============================================

  test('3.1 Owner sees the grantee upload without writing, size/modifiedAt from the resolved listing', async () => {
    test.setTimeout(60000);

    // The owner has not written into the shared folder at any point in this
    // test. Navigating into the folder for the first time is the SOLE
    // trigger for the owner to see the grantee's upload -- this is the
    // deterministic nav-triggered re-resolve (D-03), not the 30s IPNS poll.
    // navigateToFiles() forces a component remount (see
    // multi-account-wallet.ts), and double-clicking into the folder forces a
    // fresh resolve of its children.
    await navigateToFiles(owner);
    await ownerFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });
    await ownerFileList.doubleClickFolder(sharedFolderName);
    await owner.page
      .locator('.breadcrumb-item', { hasText: sharedFolderName.toLowerCase() })
      .waitFor({ state: 'visible', timeout: 30000 });

    // SC#5: the grantee's file must be visible to the owner without the
    // owner ever writing to the folder.
    const uploadedRow = ownerFileList.getItem(granteeUploadedFileName);
    await uploadedRow.waitFor({ state: 'visible', timeout: 30000 });

    // SDK-READ-03: size/modifiedAt must render from the resolved listing
    // (ResolvedChild), not from the SealedChildRef mirror. The mirror is only
    // ever populated by the writer (the grantee here, not the owner), so the
    // pre-fix read path renders the em-dash placeholder ('—') for size and
    // an epoch fallback (Jan 1 1970) for modifiedAt when the OWNER is the one
    // rendering the row.
    const sizeText =
      (await uploadedRow.locator('.file-list-item-size').textContent())?.trim() ?? '';
    const dateText =
      (await uploadedRow.locator('.file-list-item-date').textContent())?.trim() ?? '';

    expect(sizeText).not.toBe('—');
    expect(sizeText.length).toBeGreaterThan(0);
    // formatBytes() output always starts with a digit (e.g. "58 B", "1.2 KB")
    expect(sizeText).toMatch(/^\d/);

    expect(dateText).not.toBe('—');
    expect(dateText).not.toContain('1970');
  });
});
