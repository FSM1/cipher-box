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
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { InviteLinkTabPage } from '../page-objects/dialogs/invite-link-tab.page';
import { InvitePageObject } from '../page-objects/pages/invite.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Invite Link Sharing Workflow E2E Test Suite
 *
 * Tests the complete invite link lifecycle:
 * - ShareDialog tab bar UI (switching between Direct Share and Invite Link)
 * - Invite link creation (URL generated, copied to clipboard)
 * - Invite landing page (unauthenticated view, error states)
 * - Invite claim (authenticated user auto-claims, redirect to /shared)
 * - Invite management (list active invites, revoke)
 * - Error states (invalid URL, non-existent token, already-claimed, self-claim)
 *
 * Accounts:
 * - Alice: sharer (creates content and invite links)
 * - Dave: primary invite recipient (claims via invite link)
 * - Eve: secondary recipient (for folder invite, already-claimed test)
 *
 * Each test account gets its own browser context (isolated cookies/storage).
 */

/** Parse an invite URL to extract token and ephemeral key */
function parseInviteUrl(url: string): { token: string; ephemeralKey: string } {
  // URL format: http://localhost:5173/#/invite/TOKEN?key=KEY
  const hashPart = url.split('#')[1]; // /invite/TOKEN?key=KEY
  const [path, query] = hashPart.split('?');
  const token = path.split('/invite/')[1];
  const params = new URLSearchParams(query);
  const ephemeralKey = params.get('key')!;
  return { token, ephemeralKey };
}

test.describe.serial('Invite Link Sharing Workflow', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let dave: WalletTestAccount;
  let eve: WalletTestAccount;

  // Page objects for Alice
  let aliceFileList: FileListPage;
  let aliceUploadZone: UploadZonePage;
  let aliceContextMenu: ContextMenuPage;
  let aliceCreateFolderDialog: CreateFolderDialogPage;
  let aliceShareDialog: ShareDialogPage;
  let aliceInviteTab: InviteLinkTabPage;

  // Page objects for Dave and Eve
  let daveSharedBrowser: SharedFileBrowserPage;
  let eveSharedBrowser: SharedFileBrowserPage;

  // Test data -- unique per run
  const runId = Date.now().toString();

  // Shared file
  const sharedFileName = `invite-file-${runId}.txt`;
  const sharedFileContent = 'This file is shared via invite link';

  // Shared folder structure
  const sharedFolderName = `invite-folder-${runId}`;
  const subFolderName = `invite-subfolder-${runId}`;
  const folderFile1Name = `invite-ff1-${runId}.txt`;
  const folderFile2Name = `invite-sf1-${runId}.txt`;

  // Captured invite URLs
  let fileInviteUrl = '';
  let fileInviteToken = '';
  let fileInviteKey = '';
  let folderInviteUrl = '';
  let folderInviteToken = '';
  let folderInviteKey = '';
  let revokedInviteUrl = '';
  let selfClaimInviteUrl = '';

  // ============================================
  // Alice helpers (same patterns as sharing-workflow.spec.ts)
  // ============================================

  async function aliceCreateFolder(name: string): Promise<void> {
    const newFolderButton = alice.page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await aliceCreateFolderDialog.waitForOpen();
    await aliceCreateFolderDialog.createFolder(name);
    await aliceFileList.waitForItemToAppear(name, { timeout: 30000 });
  }

  async function aliceUploadFile(fileName: string, content: string): Promise<void> {
    const testFile = createTestTextFile(fileName, content);
    await aliceUploadZone.uploadFile(testFile.path);

    await Promise.race([
      aliceFileList.waitForItemToAppear(fileName, { timeout: 30000 }),
      alice.page
        .locator('[role="alert"]')
        .waitFor({ state: 'visible', timeout: 30000 })
        .then(async () => {
          const alertText = await alice.page.locator('[role="alert"]').textContent();
          throw new Error(`Upload failed with alert: ${alertText}`);
        }),
    ]);
  }

  async function aliceNavigateIntoFolder(name: string): Promise<void> {
    await aliceFileList.doubleClickFolder(name);
    await alice.page.locator('.breadcrumb-item', { hasText: name.toLowerCase() }).waitFor({
      state: 'visible',
      timeout: 30000,
    });
  }

  async function aliceNavigateBack(): Promise<void> {
    await alice.page.locator('[data-testid="parent-dir-row"]').dblclick();
    await alice.page.waitForTimeout(500);
  }

  async function aliceOpenShareDialog(itemName: string): Promise<void> {
    await aliceFileList.rightClickItem(itemName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
  }

  // ============================================
  // Setup and Teardown
  // ============================================

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (alice || dave || eve) {
      await closeWalletTestAccounts([alice, dave, eve].filter(Boolean));
    }
  });

  // ============================================
  // Phase 1: Account Setup
  // ============================================

  test('1.1 Create test accounts (Alice, Dave, Eve)', async () => {
    test.setTimeout(180_000); // 3 wallet logins with Core Kit init
    alice = await createWalletTestAccount(browser, 'alice');
    dave = await createWalletTestAccount(browser, 'dave');
    eve = await createWalletTestAccount(browser, 'eve');

    // Initialize page objects for Alice
    aliceFileList = new FileListPage(alice.page);
    aliceUploadZone = new UploadZonePage(alice.page);
    aliceContextMenu = new ContextMenuPage(alice.page);
    aliceCreateFolderDialog = new CreateFolderDialogPage(alice.page);
    aliceShareDialog = new ShareDialogPage(alice.page);
    aliceInviteTab = new InviteLinkTabPage(alice.page);

    // Initialize page objects for Dave and Eve
    daveSharedBrowser = new SharedFileBrowserPage(dave.page);
    eveSharedBrowser = new SharedFileBrowserPage(eve.page);

    // Verify all accounts have different public keys
    expect(alice.publicKey).not.toBe(dave.publicKey);
    expect(alice.publicKey).not.toBe(eve.publicKey);
    expect(dave.publicKey).not.toBe(eve.publicKey);
  });

  // ============================================
  // Phase 2: Alice Creates Content
  // ============================================

  test('1.2 Alice creates test content', async () => {
    // Upload a text file at root
    await aliceUploadFile(sharedFileName, sharedFileContent);
    expect(await aliceFileList.isItemVisible(sharedFileName)).toBe(true);

    // Create folder with nested content
    await aliceCreateFolder(sharedFolderName);
    expect(await aliceFileList.isItemVisible(sharedFolderName)).toBe(true);

    // Navigate into folder and add files + subfolder
    await aliceNavigateIntoFolder(sharedFolderName);
    await aliceUploadFile(folderFile1Name, 'File inside invite shared folder');

    // Create subfolder
    await aliceCreateFolder(subFolderName);

    // Navigate into subfolder and add file
    await aliceNavigateIntoFolder(subFolderName);
    await aliceUploadFile(folderFile2Name, 'File inside invite subfolder');

    // Navigate back to root
    await aliceNavigateBack(); // back to folder
    await aliceNavigateBack(); // back to root
  });

  // ============================================
  // Phase 2: ShareDialog Tab UI
  // ============================================

  test('2.1 ShareDialog shows tab bar with two tabs', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Verify tab bar has both tabs
    await expect(aliceInviteTab.directShareTab()).toBeVisible();
    await expect(aliceInviteTab.inviteLinkTab()).toBeVisible();

    // Verify "DIRECT SHARE" is the default active tab
    expect(await aliceInviteTab.isDirectTabActive()).toBe(true);
    expect(await aliceInviteTab.isInviteTabActive()).toBe(false);

    // Verify pubkey input is visible (direct share content)
    await expect(aliceShareDialog.pubKeyInput()).toBeVisible();

    await aliceShareDialog.close();
  });

  test('2.2 Tab switching works', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Switch to Invite Link tab
    await aliceInviteTab.switchToInviteTab();
    expect(await aliceInviteTab.isInviteTabActive()).toBe(true);
    expect(await aliceInviteTab.isDirectTabActive()).toBe(false);

    // Verify invite link content visible, pubkey input hidden
    await expect(aliceInviteTab.createButton()).toBeVisible();
    await expect(aliceShareDialog.pubKeyInput()).not.toBeVisible();

    // Switch back to Direct Share tab
    await aliceInviteTab.switchToDirectTab();
    expect(await aliceInviteTab.isDirectTabActive()).toBe(true);
    expect(await aliceInviteTab.isInviteTabActive()).toBe(false);

    // Verify pubkey input visible again
    await expect(aliceShareDialog.pubKeyInput()).toBeVisible();

    await aliceShareDialog.close();

    // Reopen dialog -- should reset to Direct Share tab
    await aliceOpenShareDialog(sharedFileName);
    expect(await aliceInviteTab.isDirectTabActive()).toBe(true);
    expect(await aliceInviteTab.isInviteTabActive()).toBe(false);

    await aliceShareDialog.close();
  });

  test('2.3 Invite Link tab shows empty state', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Switch to Invite Link tab
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();

    // Verify empty state message
    await expect(aliceInviteTab.emptyState()).toBeVisible();
    const emptyText = await aliceInviteTab.emptyState().textContent();
    expect(emptyText).toContain('no active invite links');

    await aliceShareDialog.close();
  });

  // ============================================
  // Phase 3: Invite Link Creation - File
  // ============================================

  test('3.1 Alice creates an invite link for a file', async () => {
    await aliceOpenShareDialog(sharedFileName);

    // Switch to Invite Link tab
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();

    // Intercept clipboard before clicking create
    await aliceInviteTab.interceptClipboard();

    // Click create invite link button
    await aliceInviteTab.clickCreate();

    // Wait for success message (clipboard may not be available in headless CI)
    const successText = await aliceInviteTab.waitForSuccess({ timeout: 30000 });
    expect(successText).toMatch(/link (copied to clipboard|created)/);

    // Read clipboard content -- capture invite URL
    fileInviteUrl = await aliceInviteTab.getClipboardContent();
    expect(fileInviteUrl).toContain('#/invite/');
    expect(fileInviteUrl).toContain('?key=');

    // Parse token and ephemeral key from URL
    const parsed = parseInviteUrl(fileInviteUrl);
    fileInviteToken = parsed.token;
    fileInviteKey = parsed.ephemeralKey;

    expect(fileInviteToken.length).toBeGreaterThan(0);
    expect(fileInviteKey.length).toBeGreaterThan(0);
  });

  test('3.2 Active invite appears in the list', async () => {
    // Still on the invite tab from 3.1
    expect(await aliceInviteTab.getInviteCount()).toBe(1);

    // Verify invite item shows "ACTIVE" status
    const itemText = await aliceInviteTab.inviteItem(0).textContent();
    expect(itemText).toContain('ACTIVE');
  });

  test('3.3 Alice closes and reopens dialog -- invite persists', async () => {
    await aliceShareDialog.close();

    // Reopen share dialog for same file
    await aliceOpenShareDialog(sharedFileName);

    // Switch to Invite Link tab
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();

    // Verify invite count is still 1
    expect(await aliceInviteTab.getInviteCount()).toBe(1);

    await aliceShareDialog.close();
  });

  // ============================================
  // Phase 4: Invite Claim - File Happy Path
  // ============================================

  test('4.1 Unauthenticated visitor sees invite landing page', async () => {
    // Create a fresh context with no auth to verify the landing page renders
    const bareContext = await browser.newContext();
    const barePage = await bareContext.newPage();
    const bareInvitePage = new InvitePageObject(barePage);

    await bareInvitePage.goto(fileInviteToken, fileInviteKey);

    // Wait for valid state (not loading, not error)
    await bareInvitePage.waitForValidState({ timeout: 30000 });

    // Verify card is visible
    await expect(bareInvitePage.card()).toBeVisible();

    // Verify message text
    const messageText = await bareInvitePage.message().textContent();
    expect(messageText).toContain('someone shared a file with you');

    // Verify auth area (login buttons) is visible
    expect(await bareInvitePage.isAuthAreaVisible()).toBe(true);

    await bareContext.close();
  });

  test('4.2 Dave authenticates and claim auto-triggers', async () => {
    // Dave already has auth from createWalletTestAccount
    // Navigate Dave to the invite URL -- InvitePage should detect isAuthenticated and auto-claim
    const daveInvitePage = new InvitePageObject(dave.page);
    await daveInvitePage.goto(fileInviteToken, fileInviteKey);

    // Wait for claim to complete and redirect to /shared
    await daveInvitePage.waitForClaimedRedirect({ timeout: 60000 });
  });

  test('4.3 Dave sees the shared file in ~/shared', async () => {
    // After claim redirect, Dave should be on /shared
    await navigateToShared(dave);
    await daveSharedBrowser.waitForLoaded({ timeout: 30000 });

    // Dave should see Alice's shared file
    await daveSharedBrowser.waitForSharedItem(sharedFileName, { timeout: 15000 });
    expect(await daveSharedBrowser.getSharedItemCount()).toBeGreaterThanOrEqual(1);

    // Verify [RO] badge
    const roBadge = daveSharedBrowser.getReadOnlyBadge(sharedFileName);
    expect(await roBadge.isVisible()).toBe(true);
  });

  // ============================================
  // Phase 5: Invite Claim - Folder Happy Path
  // ============================================

  test('5.1 Alice creates an invite link for the folder', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFolderName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFolderName);

    // Switch to Invite Link tab
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();

    // Intercept clipboard
    await aliceInviteTab.interceptClipboard();

    // Click create
    await aliceInviteTab.clickCreate();

    // Wait for success (folder invite may take longer due to key re-wrapping)
    const successText = await aliceInviteTab.waitForSuccess({ timeout: 60000 });
    expect(successText).toMatch(/link (copied to clipboard|created)/);

    // Capture URL
    folderInviteUrl = await aliceInviteTab.getClipboardContent();
    const parsed = parseInviteUrl(folderInviteUrl);
    folderInviteToken = parsed.token;
    folderInviteKey = parsed.ephemeralKey;

    expect(folderInviteToken.length).toBeGreaterThan(0);
    expect(folderInviteKey.length).toBeGreaterThan(0);

    await aliceShareDialog.close();
  });

  test('5.2 Eve claims the folder invite', async () => {
    const eveInvitePage = new InvitePageObject(eve.page);
    await eveInvitePage.goto(folderInviteToken, folderInviteKey);

    // Wait for auto-claim and redirect
    await eveInvitePage.waitForClaimedRedirect({ timeout: 60000 });
  });

  test('5.3 Eve navigates the shared folder tree', async () => {
    await navigateToShared(eve);
    await eveSharedBrowser.waitForLoaded({ timeout: 30000 });

    // Find and open the shared folder
    await eveSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
    await eveSharedBrowser.openSharedItem(sharedFolderName);
    await eve.page.waitForTimeout(3000);

    // If IPNS resolution failed on first try, retry
    const parentDirVisible = await eveSharedBrowser.parentDirRow().isVisible();
    if (!parentDirVisible) {
      await navigateToShared(eve);
      await eveSharedBrowser.waitForLoaded({ timeout: 30000 });
      await eveSharedBrowser.waitForSharedItem(sharedFolderName, { timeout: 15000 });
      await eveSharedBrowser.navigateIntoFolder(sharedFolderName);
    }

    // Should see folder contents: the file and subfolder
    const itemNames = await eveSharedBrowser.getFolderItemNames();
    expect(itemNames.some((n) => n.includes(folderFile1Name))).toBe(true);
    expect(itemNames.some((n) => n.includes(subFolderName))).toBe(true);

    // Navigate into subfolder
    await eveSharedBrowser.doubleClickFolderItem(subFolderName);
    await eve.page.waitForTimeout(2000);

    const subItems = await eveSharedBrowser.getFolderItemNames();
    expect(subItems.some((n) => n.includes(folderFile2Name))).toBe(true);

    // Navigate back to shared root
    await eveSharedBrowser.navigateToRoot();
    await eveSharedBrowser.waitForLoaded({ timeout: 15000 });
  });

  // ============================================
  // Phase 6: Link Management
  // ============================================

  test('6.1 Alice revokes an invite link', async () => {
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFileName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFileName);

    // Switch to Invite Link tab
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();

    // Phase 3 invite was claimed by Dave, so the list only shows active invites (0)
    const existingCount = await aliceInviteTab.getInviteCount();

    // Create a NEW invite link so we have an active one to revoke
    await aliceInviteTab.interceptClipboard();
    await aliceInviteTab.clickCreate();
    await aliceInviteTab.waitForSuccess({ timeout: 30000 });
    revokedInviteUrl = await aliceInviteTab.getClipboardContent();

    // Now we should have existingCount + 1 invites
    const newCount = await aliceInviteTab.getInviteCount();
    expect(newCount).toBe(existingCount + 1);

    // Revoke the newest invite (last in list)
    await aliceInviteTab.revokeInvite(newCount - 1);

    // Verify invite count decreased
    expect(await aliceInviteTab.getInviteCount()).toBe(existingCount);

    await aliceShareDialog.close();
  });

  test('6.2 Revoked invite shows error on landing page', async () => {
    // Navigate to the revoked invite URL in a fresh context
    const bareContext = await browser.newContext();
    const barePage = await bareContext.newPage();
    const bareInvitePage = new InvitePageObject(barePage);

    const parsed = parseInviteUrl(revokedInviteUrl);
    await bareInvitePage.goto(parsed.token, parsed.ephemeralKey);

    // Wait for error state
    await bareInvitePage.waitForErrorState({ timeout: 30000 });

    // Verify error card appears
    expect(await bareInvitePage.isError()).toBe(true);

    // Verify error message -- API collapses all non-active statuses to 404
    // to prevent token-existence oracle attacks, so client shows "expired"
    const errorMsg = await bareInvitePage.getErrorMessage();
    expect(errorMsg).toMatch(/expired|revoked/);

    // Verify "[GO HOME]" button is visible
    await expect(bareInvitePage.homeButton()).toBeVisible();

    await bareContext.close();
  });

  // ============================================
  // Phase 7: Error States
  // ============================================

  test('7.1 Invalid URL (missing key) shows error', async () => {
    const bareContext = await browser.newContext();
    const barePage = await bareContext.newPage();
    const bareInvitePage = new InvitePageObject(barePage);

    // Navigate to invite URL without ?key= param
    await bareInvitePage.gotoInvalidUrl('sometoken12345');

    // Wait for error state
    await bareInvitePage.waitForErrorState({ timeout: 15000 });

    // Verify error card with "invalid link" message
    const errorMsg = await bareInvitePage.getErrorMessage();
    expect(errorMsg.toLowerCase()).toContain('invalid');

    // Verify home button works
    await expect(bareInvitePage.homeButton()).toBeVisible();

    await bareContext.close();
  });

  test('7.2 Non-existent token shows error', async () => {
    const bareContext = await browser.newContext();
    const barePage = await bareContext.newPage();
    const bareInvitePage = new InvitePageObject(barePage);

    // Navigate to invite URL with a non-existent token
    await bareInvitePage.goto('nonexistenttoken123456789', 'deadbeef1234567890');

    // Wait for error state (should show expired or error)
    await bareInvitePage.waitForErrorState({ timeout: 30000 });

    expect(await bareInvitePage.isError()).toBe(true);

    await bareContext.close();
  });

  test('7.3 Already-claimed invite shows error', async () => {
    // Use the file invite URL from Phase 3 (already claimed by Dave in Phase 4)
    // Navigate to it in Eve's authenticated context
    const eveInvitePage = new InvitePageObject(eve.page);
    await eveInvitePage.goto(fileInviteToken, fileInviteKey);

    // The invite was already claimed, so we expect an error
    // Either the status check returns "claimed" or the claim attempt returns 409
    await eveInvitePage.waitForErrorState({ timeout: 30000 });

    const errorMsg = await eveInvitePage.getErrorMessage();
    // Could be "already been claimed" or "claimed" depending on which check catches it
    expect(errorMsg.toLowerCase()).toMatch(/claimed|expired|invalid/);
  });

  test('7.4 Self-claim prevention', async () => {
    // Alice creates a new invite link for the file
    await navigateToFiles(alice);
    await aliceFileList.waitForItemToAppear(sharedFileName, { timeout: 15000 });

    await aliceOpenShareDialog(sharedFileName);
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();

    // Intercept clipboard and create new invite
    await aliceInviteTab.interceptClipboard();
    await aliceInviteTab.clickCreate();
    await aliceInviteTab.waitForSuccess({ timeout: 30000 });
    selfClaimInviteUrl = await aliceInviteTab.getClipboardContent();

    await aliceShareDialog.close();

    // Alice opens the invite URL in her own context
    const aliceInvitePage = new InvitePageObject(alice.page);
    const parsed = parseInviteUrl(selfClaimInviteUrl);
    await aliceInvitePage.goto(parsed.token, parsed.ephemeralKey);

    // Self-claim should fail -- either the API returns a 409/conflict or
    // the page shows an error. Wait for error state.
    await aliceInvitePage.waitForErrorState({ timeout: 30000 });

    expect(await aliceInvitePage.isError()).toBe(true);
  });

  // ============================================
  // Phase 8: Cleanup
  // ============================================

  test('8.1 Cleanup', async () => {
    cleanupTestFiles();
    await closeWalletTestAccounts([alice, dave, eve].filter(Boolean));
    // Null out to prevent afterAll from double-closing
    alice = null as unknown as WalletTestAccount;
    dave = null as unknown as WalletTestAccount;
    eve = null as unknown as WalletTestAccount;
  });
});
