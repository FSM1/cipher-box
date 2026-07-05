import { test, expect, Browser, Request } from '@playwright/test';
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
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { InviteLinkTabPage } from '../page-objects/dialogs/invite-link-tab.page';
import { InvitePageObject } from '../page-objects/pages/invite.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * GAP-6 (68.1-24) — encrypted item-name pipeline, end-to-end.
 *
 * Replaces the retired share-itemname-backfill.spec.ts (removed: the plaintext
 * `item_name` column was dropped in the Phase 66 schema cutover, so the lazy
 * plaintext-backfill feature it tested is permanently unreachable dead code —
 * see VERIFICATION.md "Round-2 Addendum ... GAP-6 product decision").
 *
 * The current pipeline never has a plaintext display name at rest: the client
 * ECIES-wraps `itemName` to the recipient's (or invite ephemeral) public key
 * BEFORE it ever leaves the browser, sends only `itemNameEncrypted` (hex
 * ciphertext) to the API, and the recipient decrypts it client-side with their
 * own vault private key for display (`decryptItemName` in
 * apps/web/src/services/share.service.ts). This spec proves that round-trip
 * for both sharing entry points (direct share + invite link claim) and
 * verifies the wire-level create/claim request bodies never carry a plaintext
 * name.
 *
 * Owner-side display note (documented, not re-tested here): ShareDialog's
 * recipient rows show only the recipient's public key + permission — they
 * never render a per-row item name (the item name is already shown once, in
 * the dialog's own title, using the plaintext the owner already holds
 * locally). There is no "empty name" regression to guard against on the
 * owner side; `SentShare.itemName` from the paginated `/shares/sent` fetch
 * (`toSentShare`, correctly `''` since the owner cannot decrypt a
 * ciphertext wrapped for the recipient's key) is never rendered per-row.
 */
test.describe.serial('Share itemName encrypted pipeline (GAP-6 / 68.1-24)', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let bob: WalletTestAccount;

  let aliceFileList: FileListPage;
  let aliceUploadZone: UploadZonePage;
  let aliceContextMenu: ContextMenuPage;
  let aliceShareDialog: ShareDialogPage;
  let aliceInviteTab: InviteLinkTabPage;

  let bobSharedBrowser: SharedFileBrowserPage;

  const runId = Date.now().toString(36).toLowerCase();
  const directShareFileName = `direct-name-${runId}.txt`;
  const inviteFileName = `invite-name-${runId}.txt`;

  let inviteUrl = '';
  let inviteToken = '';
  let inviteKey = '';

  async function aliceUploadFile(fileName: string, content: string): Promise<void> {
    const testFile = createTestTextFile(fileName, content);
    await aliceUploadZone.uploadFile(testFile.path);
    await Promise.race([
      aliceFileList.waitForItemToAppear(fileName, { timeout: 30_000 }),
      alice.page
        .locator('[role="alert"]')
        .waitFor({ state: 'visible', timeout: 30_000 })
        .then(async () => {
          const alertText = await alice.page.locator('[role="alert"]').textContent();
          throw new Error(`Upload failed with alert: ${alertText}`);
        }),
    ]);
  }

  async function aliceOpenShareDialog(itemName: string): Promise<void> {
    await aliceFileList.rightClickItem(itemName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
    await aliceShareDialog.waitForRecipientsLoaded();
  }

  /** Parse an invite URL to extract token and ephemeral key (HashRouter format). */
  function parseInviteUrl(url: string): { token: string; ephemeralKey: string } {
    const hashPart = url.split('#')[1];
    const [path, query] = hashPart.split('?');
    const token = path.split('/invite/')[1];
    const params = new URLSearchParams(query);
    const ephemeralKey = params.get('key')!;
    return { token, ephemeralKey };
  }

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    if (alice || bob) {
      await closeWalletTestAccounts([alice, bob].filter(Boolean));
    }
  });

  test('1. Create owner (Alice) and recipient (Bob)', async () => {
    test.setTimeout(300_000);
    alice = await createWalletTestAccount(browser, 'alice');
    bob = await createWalletTestAccount(browser, 'bob');

    aliceFileList = new FileListPage(alice.page);
    aliceUploadZone = new UploadZonePage(alice.page);
    aliceContextMenu = new ContextMenuPage(alice.page);
    aliceShareDialog = new ShareDialogPage(alice.page);
    aliceInviteTab = new InviteLinkTabPage(alice.page);
    bobSharedBrowser = new SharedFileBrowserPage(bob.page);

    expect(alice.publicKey).not.toBe(bob.publicKey);
  });

  test('2. Alice creates the two test files', async () => {
    await navigateToFiles(alice);
    await aliceUploadFile(directShareFileName, 'direct-share content');
    await aliceUploadFile(inviteFileName, 'invite-link content');
  });

  test('3. Direct share: create-share request carries itemNameEncrypted, no plaintext itemName', async () => {
    await aliceOpenShareDialog(directShareFileName);

    const [shareRequest] = await Promise.all([
      alice.page.waitForRequest(
        (req: Request) => /\/shares$/.test(new URL(req.url()).pathname) && req.method() === 'POST'
      ),
      aliceShareDialog.shareWithKey(bob.publicKey),
    ]);
    await aliceShareDialog.waitForSuccess({ timeout: 30_000 });

    const body = shareRequest.postDataJSON() as Record<string, unknown>;
    expect(body.itemNameEncrypted, 'itemNameEncrypted must be sent').toBeTruthy();
    expect(typeof body.itemNameEncrypted).toBe('string');
    expect(body.itemNameEncrypted as string).toMatch(/^([0-9a-fA-F]{2})+$/);
    // The wrapped ciphertext must never equal (or contain) the plaintext name.
    expect((body.itemNameEncrypted as string).toLowerCase()).not.toContain(
      Buffer.from(directShareFileName, 'utf8').toString('hex').toLowerCase()
    );
    // CreateShareDto has no plaintext display-name field at all (post node/v3
    // schema cutover) -- the key must be entirely absent from the wire body.
    expect(body.itemName).toBeUndefined();

    await aliceShareDialog.close();
  });

  test('4. Bob sees the correct decrypted name in ~/shared', async () => {
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30_000 });
    await bobSharedBrowser.waitForSharedItem(directShareFileName, { timeout: 20_000 });

    const names = await bobSharedBrowser.getSharedItemNames();
    expect(names.some((n) => n.includes(directShareFileName))).toBe(true);
  });

  test('5. Invite create: request carries itemNameEncrypted (wrapped to ephemeral key), no plaintext itemName', async () => {
    await navigateToFiles(alice);
    await aliceOpenShareDialog(inviteFileName);
    await aliceInviteTab.switchToInviteTab();
    await aliceInviteTab.waitForLoaded();
    await aliceInviteTab.interceptClipboard();

    const [inviteCreateRequest] = await Promise.all([
      alice.page.waitForRequest(
        (req: Request) =>
          /\/shares\/invites$/.test(new URL(req.url()).pathname) && req.method() === 'POST'
      ),
      aliceInviteTab.clickCreate(),
    ]);
    await aliceInviteTab.waitForSuccess({ timeout: 30_000 });

    const createBody = inviteCreateRequest.postDataJSON() as Record<string, unknown>;
    expect(createBody.itemNameEncrypted, 'itemNameEncrypted must be sent').toBeTruthy();
    expect(typeof createBody.itemNameEncrypted).toBe('string');
    expect(createBody.itemNameEncrypted as string).toMatch(/^([0-9a-fA-F]{2})+$/);
    expect(createBody.itemName).toBeUndefined();

    inviteUrl = await aliceInviteTab.getClipboardContent();
    expect(inviteUrl).toContain('#/invite/');
    const parsed = parseInviteUrl(inviteUrl);
    inviteToken = parsed.token;
    inviteKey = parsed.ephemeralKey;
    expect(inviteToken.length).toBeGreaterThan(0);

    await aliceShareDialog.close();
  });

  test('6. Invite claim: request re-wraps itemNameEncrypted to the claimant vault key, no plaintext itemName', async () => {
    const bobInvitePage = new InvitePageObject(bob.page);
    await bobInvitePage.goto(inviteToken, inviteKey);

    const [claimRequest] = await Promise.all([
      bob.page.waitForRequest(
        (req: Request) =>
          /\/invites\/[^/]+\/claim$/.test(new URL(req.url()).pathname) && req.method() === 'POST'
      ),
      bobInvitePage.waitForClaimedRedirect({ timeout: 60_000 }),
    ]);

    const claimBody = claimRequest.postDataJSON() as Record<string, unknown>;
    expect(
      claimBody.itemNameEncrypted,
      'itemNameEncrypted must be re-wrapped on claim'
    ).toBeTruthy();
    expect(typeof claimBody.itemNameEncrypted).toBe('string');
    expect(claimBody.itemNameEncrypted as string).toMatch(/^([0-9a-fA-F]{2})+$/);
    expect(claimBody.itemName).toBeUndefined();
  });

  test('7. Bob sees the correct decrypted name for the claimed invite', async () => {
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30_000 });
    await bobSharedBrowser.waitForSharedItem(inviteFileName, { timeout: 20_000 });

    const names = await bobSharedBrowser.getSharedItemNames();
    expect(names.some((n) => n.includes(inviteFileName))).toBe(true);
  });
});
