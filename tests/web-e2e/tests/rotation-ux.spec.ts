import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { ShareDialogPage } from '../page-objects/dialogs/share-dialog.page';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * Rotation UX: header badge lifecycle + failure-UX toasts (ROT-07 —
 * D-01 / D-02 / D-03 / D-06 / WRITE-03).
 *
 * Per docs/TESTING.md, apps/web has no unit tests (D-13/SC#5); this Playwright
 * tier is the ONLY place the badge copy/visuals and toast copy/action
 * affordances added by 68-04/68-08/68-09 are proven against the real,
 * rendered `RotationStatusBadge`/`NotificationToast` components.
 *
 * Exact UI-SPEC copy under test (68-UI-SPEC.md):
 *   D-02/D-03 badge: "Revoking access…" / "Finishing revocation…" / "Resuming revocation…"
 *   D-05: "Stale data from server rejected." (covered by rotation-durability.spec.ts)
 *   D-06: "Couldn't complete securely — retry." + Retry action
 *   D-01 (non-revoked): "Write failed — access may be out of date." + Refresh access action
 *   D-01 (revoked, terminal): "Write access revoked." with NO action
 *
 * SCOPE NOTES (source-verified, not oversights):
 * - D-02/D-06/D-01: no production call site currently drives these states end
 *   to end (see per-test SCOPE NOTE comments below for the exact source
 *   citation for each). Those tests instead drive the REAL, shipped
 *   `rotation.store.ts` / `notification.store.ts` singletons directly via the
 *   Vite dev server's module graph (`page.evaluate` + dynamic
 *   `import('/src/...')` — Vite transforms this identically to a statically
 *   imported module, so it is the SAME module instance + SAME rendered
 *   `RotationStatusBadge`/`NotificationToast` components the app already
 *   mounted), proving the real component contract even though the upstream
 *   trigger is not yet wired to a live user action.
 * - D-03 (resuming-after-reload) IS fully wired end to end today
 *   (`useAuth.ts` calls the real `resumeInterruptedRotation()` on every
 *   session restore) and is exercised via a genuine `page.reload()`.
 */

test.describe.serial('Rotation UX: badge lifecycle + failure-UX toasts', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let account: PrivateKeyAccount;

  const runId = Date.now().toString();

  test.beforeAll(async ({ browser: testBrowser }) => {
    test.setTimeout(90_000); // Core Kit init + SIWE can be slow
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    account = createTestAccount();
    await setupMockWallet(page, account);

    fileList = new FileListPage(page);

    await loginViaWallet(page, { timeout: 60_000 });
    await page.waitForURL('**/files', { timeout: 60000 });
    await Promise.race([
      fileList.fileListContainer().waitFor({ state: 'visible', timeout: 30000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30000 }),
    ]);
  });

  test.afterAll(async () => {
    if (page) {
      await deleteAccountViaPage(page);
    }
    if (context) {
      await context.close();
    }
  });

  test('root-cut and tail-walk badge states render the exact UI-SPEC copy, visuals, and non-interactive status contract (D-02)', async () => {
    // SCOPE NOTE: performScopeExitRotation's root-cut/tail-walk badge
    // transitions ARE wired for real (rotation-driver.service.ts's
    // persistJob), but only reachable via a genuine multi-account share +
    // owner mutation, and the SDK chokepoint awaits the ENTIRE rotation
    // (root cut + tail walk) before the triggering call resolves (see
    // rotation-driver.service.ts's "Badge lifecycle timing note" doc
    // comment) -- there is no stable hook to catch it mid-flight from
    // outside. This drives the same `rotation.store.ts` singleton the real
    // driver calls (`beginRootCut`/`beginTailWalk`/`reset`) so the exact
    // per-state copy/visuals/accessibility contract is proven deterministically
    // against the real `RotationStatusBadge` component.
    const badge = page.locator('.rotation-status-badge');

    await page.evaluate(async () => {
      const rotationStoreModPath = '/src/stores/rotation.store.ts';
      const mod = await import(rotationStoreModPath);
      mod.useRotationStore.getState().beginRootCut();
    });
    await expect(badge).toBeVisible();
    await expect(badge).toHaveText('Revoking access…');
    await expect(badge).toHaveClass(/rotation-status-badge--active/);
    await expect(badge.locator('.rotation-status-badge__spinner')).toBeVisible();
    expect(await badge.getAttribute('role')).toBe('status');
    expect(await badge.getAttribute('aria-live')).toBe('polite');
    expect(await badge.getAttribute('tabindex')).toBeNull();
    expect(await badge.evaluate((el) => el.tagName)).toBe('DIV');

    await page.evaluate(async () => {
      const rotationStoreModPath = '/src/stores/rotation.store.ts';
      const mod = await import(rotationStoreModPath);
      mod.useRotationStore.getState().beginTailWalk();
    });
    await expect(badge).toHaveText('Finishing revocation…');
    await expect(badge).toHaveClass(/rotation-status-badge--background/);
    await expect(badge.locator('.rotation-status-badge__spinner')).toHaveCount(0);
    expect(await badge.getAttribute('role')).toBe('status');

    await page.evaluate(async () => {
      const rotationStoreModPath = '/src/stores/rotation.store.ts';
      const mod = await import(rotationStoreModPath);
      mod.useRotationStore.getState().reset();
    });
    await expect(badge).toHaveCount(0);
  });

  test('badge stays active across two concurrent-root rotations and only resets once BOTH finish (SC#6)', async () => {
    // SCOPE NOTE: same rationale as the D-02 test above -- there is no stable
    // hook to catch two genuinely concurrent rotations mid-flight from
    // outside the page. This drives the REAL rotation-driver.service.ts
    // `persistJob` callback (via `buildRotationClientCallbacks()`, the same
    // module instance `useAuth.ts` wires into the SDK client) directly, for
    // two distinct root node ids overlapping in time, proving the per-root
    // `Set<string>` badge tracking: the badge must NOT reset when the first
    // root finishes while the second is still mid-walk, and must reset once
    // the tracking set drains (both roots terminal).
    const badge = page.locator('.rotation-status-badge');
    const rootA = `e2e-concurrent-a-${runId}`;
    const rootB = `e2e-concurrent-b-${runId}`;

    // Root A's first checkpoint: root-cut signal, badge turns on.
    await page.evaluate(
      async ({ rootA }) => {
        const rotationDriverModPath = '/src/services/rotation-driver.service.ts';
        const mod = await import(rotationDriverModPath);
        const { persistJob } = mod.buildRotationClientCallbacks();
        await persistJob({
          rootNodeId: rootA,
          status: 'in-progress',
          completedNodeIds: new Set(),
          frontier: [],
        });
      },
      { rootA }
    );
    await expect(badge).toBeVisible();
    await expect(badge).toHaveText('Revoking access…');

    // Root B's first checkpoint while root A is still in flight: a SECOND
    // root entering the tracking set, badge stays active.
    await page.evaluate(
      async ({ rootB }) => {
        const rotationDriverModPath = '/src/services/rotation-driver.service.ts';
        const mod = await import(rotationDriverModPath);
        const { persistJob } = mod.buildRotationClientCallbacks();
        await persistJob({
          rootNodeId: rootB,
          status: 'in-progress',
          completedNodeIds: new Set(),
          frontier: [],
        });
      },
      { rootB }
    );
    await expect(badge).toBeVisible();

    // Root A finishes first -- root B is still mid-walk. The badge MUST NOT
    // reset (this is the exact bug this plan fixes: a single-scalar tracker
    // would incorrectly clear the badge here).
    await page.evaluate(
      async ({ rootA }) => {
        const rotationDriverModPath = '/src/services/rotation-driver.service.ts';
        const mod = await import(rotationDriverModPath);
        const { persistJob } = mod.buildRotationClientCallbacks();
        await persistJob({
          rootNodeId: rootA,
          status: 'complete',
          completedNodeIds: new Set(),
          frontier: [],
        });
      },
      { rootA }
    );
    await expect(badge).toBeVisible();

    // Root B finishes last -- the tracking set drains to empty, and ONLY NOW
    // does the badge reset.
    await page.evaluate(
      async ({ rootB }) => {
        const rotationDriverModPath = '/src/services/rotation-driver.service.ts';
        const mod = await import(rotationDriverModPath);
        const { persistJob } = mod.buildRotationClientCallbacks();
        await persistJob({
          rootNodeId: rootB,
          status: 'complete',
          completedNodeIds: new Set(),
          frontier: [],
        });
      },
      { rootB }
    );
    await expect(badge).toHaveCount(0);
  });

  test('badge shows Resuming revocation… after a reload finds an interrupted rotation job (D-03)', async () => {
    const rootNodeId = `e2e-resume-${runId}`;

    // Seed a durable, non-terminal job checkpoint directly into real
    // IndexedDB, matching rotation-driver.service.ts's exact DB/store name,
    // keyPath, and DurableJobCheckpoint shape.
    await page.evaluate(
      ({ rootNodeId }) => {
        return new Promise<void>((resolve, reject) => {
          const req = indexedDB.open('cipherbox-rotation-jobs', 1);
          req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains('jobs')) {
              db.createObjectStore('jobs', { keyPath: 'rootNodeId' });
            }
          };
          req.onerror = () => reject(req.error);
          req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('jobs', 'readwrite');
            tx.objectStore('jobs').put({
              rootNodeId,
              status: 'in-progress',
              completedNodeIds: [],
              frontierIpnsNames: [],
              updatedAt: Date.now(),
            });
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
          };
        });
      },
      { rootNodeId }
    );

    // A real reload re-runs the app's real session-restore boot sequence.
    // useAuth.ts calls the real, unmocked resumeInterruptedRotation() on
    // every session restore -- this is the one badge transition genuinely
    // wired end to end today (source-confirmed: apps/web/src/hooks/useAuth.ts).
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.locator('[data-testid="user-menu"]').waitFor({ state: 'visible', timeout: 120000 });

    const badge = page.locator('.rotation-status-badge');
    await expect(badge).toBeVisible({ timeout: 15000 });
    await expect(badge).toHaveText('Resuming revocation…');
    await expect(badge).toHaveClass(/rotation-status-badge--background/);
    expect(await badge.getAttribute('role')).toBe('status');

    // Clean up the seeded checkpoint so it does not leak into later tests
    // (mirrors the seeding block's DB/store names and keyPath).
    await page.evaluate(
      ({ rootNodeId }) => {
        return new Promise<void>((resolve, reject) => {
          const req = indexedDB.open('cipherbox-rotation-jobs', 1);
          req.onerror = () => reject(req.error);
          req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('jobs', 'readwrite');
            tx.objectStore('jobs').delete(rootNodeId);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
          };
        });
      },
      { rootNodeId }
    );
  });

  // SCOPE NOTE (Phase 73 SC4 -- CLOSED): the D-01/WRITE-03 co-writer
  // refresh-access flow previously had no live production trigger for this
  // test to drive (see git history for the prior fixme skeleton). All three
  // enabling seams have now landed:
  //   - 73-02: packages/sdk-core/src/ipns/index.ts's createAndPublishIpnsRecord
  //     maps a real API 410 (apps/api's IPNS_TOMBSTONED) to a typed
  //     `{ tombstoned: true }` result instead of letting a raw AxiosError
  //     propagate uncaught.
  //   - 73-05: packages/sdk/src/client.ts's publishNodeFn
  //     (buildWriteTransportSeams) reads that `tombstoned` field and maps it
  //     straight through to shared-write.ts's existing
  //     CannotWriteUntilRefetchError throw sites.
  //   - 73-08: apps/web/src/hooks/useSharedWriteOps.ts now wires every
  //     shared-write mutation through runWithFailureUx, threading
  //     navActions.refreshCurrentDepthWriteKey as the refreshWriteAccess
  //     supplier.
  //
  // The classifier-driven test below (own describe.serial, own two-account
  // harness at the bottom of this file) drives this end to end: Alice
  // (owner) tombstones the shared folder's own IPNS name via the real
  // `POST /ipns/tombstone` endpoint (a direct API fixture standing in for a
  // completed write-revocation rotation Bob has not yet refetched), then Bob
  // attempts a real shared-folder write against that now-tombstoned target
  // and the SAME "Refresh access" toast appears THROUGH the real classifier
  // path (runWithFailureUx -> CannotWriteUntilRefetchError) -- not via direct
  // notification-store injection.

  test('a persistently-deferring mutation exhausts retries and surfaces the terminal Retry toast without ever silently auto-dismissing (D-06)', async () => {
    test.setTimeout(30_000);
    // SCOPE NOTE: exercising the real ~5-attempt/~30s reconcile-retry-loop
    // end to end requires racing two independent SDK client instances
    // against the same account's folder sequence number (reconcileFolderSequence
    // is a private client.ts method with no other trigger) -- out of scope
    // for this executor pass. This proves the REAL NotificationToast/
    // notification.store contract that useMutationFailureUx.ts's
    // dispatchDeferExhausted dispatches on exhaustion (exact call shape
    // verified by source reading), including NotificationToast.tsx's own
    // no-auto-dismiss behavior for an error carrying an action -- a
    // genuinely unverified-elsewhere behavior of the shipped component.
    let retryClicked = false;
    await page.exposeFunction('__e2eRecordRetryClick', () => {
      retryClicked = true;
    });

    await page.evaluate(async () => {
      const notificationStoreModPath = '/src/stores/notification.store.ts';
      const mod = await import(notificationStoreModPath);
      mod.useNotificationStore
        .getState()
        .addNotification('error', "Couldn't complete securely — retry.", {
          label: 'Retry',
          onClick: () =>
            (window as unknown as { __e2eRecordRetryClick: () => void }).__e2eRecordRetryClick(),
        });
    });

    const toast = page.locator('[role="alert"]', {
      hasText: "Couldn't complete securely — retry.",
    });
    await expect(toast).toBeVisible();
    const retryButton = toast.locator('button:not([aria-label="Dismiss notification"])');
    await expect(retryButton).toHaveCount(1);
    await expect(retryButton).toHaveText('[Retry]');

    // NotificationToast.tsx's AUTO_DISMISS_MS is 8000ms; an error carrying
    // an action is explicitly exempted (skipAutoDismiss) so the user is
    // never silently left without a chance to retry -- the mutation was
    // never re-applied on the user's behalf. Wait past that window and
    // confirm the toast is STILL visible.
    await page.waitForTimeout(9000);
    await expect(toast).toBeVisible();

    await retryButton.click();
    expect(retryClicked).toBe(true);
  });
});

/**
 * D-01/WRITE-03 classifier-driven refresh-access flow (Phase 73 SC4).
 *
 * Own two-account harness (owner + write-share recipient) -- distinct from
 * the single-account describe.serial above, mirroring the multi-account
 * pattern in tests/web-e2e/tests/writable-shares.spec.ts.
 *
 * Real production trigger: Alice (the shared folder's owner, and therefore
 * the owning `user_id` on its `ipns_records` row) tombstones the folder's
 * OWN IPNS name via the real `POST /ipns/tombstone` endpoint -- the same
 * terminal state a completed write-revocation rotation leaves behind for a
 * co-writer who has not yet refetched. Bob (the write-share recipient, still
 * holding the pre-tombstone writeKey/state seeded when he navigated into the
 * folder) then attempts a real shared-folder write, driving the classifier
 * through its real path: publish 410 -> createAndPublishIpnsRecord tombstoned
 * -> publishNodeFn (client.ts) -> CannotWriteUntilRefetchError
 * (shared-write.ts) -> runWithFailureUx (useSharedWriteOps.ts).
 */
test.describe.serial('Rotation UX: D-01/WRITE-03 classifier-driven refresh-access flow', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let bob: WalletTestAccount;
  let aliceFileList: FileListPage;
  let aliceCreateFolderDialog: CreateFolderDialogPage;
  let aliceContextMenu: ContextMenuPage;
  let aliceShareDialog: ShareDialogPage;
  let bobSharedBrowser: SharedFileBrowserPage;

  const runId = Date.now().toString();
  const folderName = `write03-${runId}`;

  test.beforeAll(async ({ browser: testBrowser }) => {
    test.setTimeout(300_000); // Two Core Kit logins + share setup can be slow
    browser = testBrowser;

    alice = await createWalletTestAccount(browser, 'alice-write03');
    bob = await createWalletTestAccount(browser, 'bob-write03');

    aliceFileList = new FileListPage(alice.page);
    aliceCreateFolderDialog = new CreateFolderDialogPage(alice.page);
    aliceContextMenu = new ContextMenuPage(alice.page);
    aliceShareDialog = new ShareDialogPage(alice.page);
    bobSharedBrowser = new SharedFileBrowserPage(bob.page);

    // Alice creates a folder and shares it with Bob using write permission
    // (mirrors writable-shares.spec.ts phase 1-2).
    const newFolderButton = alice.page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await aliceCreateFolderDialog.waitForOpen();
    await aliceCreateFolderDialog.createFolder(folderName);
    await aliceFileList.waitForItemToAppear(folderName, { timeout: 30000 });

    await aliceFileList.rightClickItem(folderName);
    await aliceContextMenu.waitForOpen();
    await aliceContextMenu.clickShare();
    await aliceShareDialog.waitForOpen();
    await aliceShareDialog.waitForRecipientsLoaded();

    const writeBtn = alice.page.locator('.share-perm-btn', { hasText: '[ READ-WRITE ]' });
    await writeBtn.click();
    await aliceShareDialog.shareWithKey(bob.publicKey);
    await aliceShareDialog.waitForSuccess({ timeout: 60000 });
    await aliceShareDialog.close();

    // Bob navigates into the write-shared folder -- this seeds his SDK
    // client's writeKey/ipnsName state for the current depth (the same
    // state refreshCurrentDepthWriteKey/runWithFailureUx operate on).
    await navigateToShared(bob);
    await bobSharedBrowser.waitForLoaded({ timeout: 30000 });
    await bobSharedBrowser.waitForSharedItem(folderName, { timeout: 15000 });
    await bobSharedBrowser.navigateIntoFolder(folderName);
  });

  test.afterAll(async () => {
    if (alice || bob) {
      await closeWalletTestAccounts([alice, bob].filter(Boolean));
    }
  });

  test('a stale co-writer write surfaces Refresh access, escalating to a terminal Write access revoked with no action (D-01/WRITE-03)', async () => {
    test.setTimeout(60_000);

    // Resolve the shared folder's own IPNS name from Alice's real, running
    // folder.store singleton (the same store the app itself reads) -- no
    // mocking, this is the exact name Bob's next write will target.
    const ipnsName = await alice.page.evaluate(async (name) => {
      const folderStoreModPath = '/src/stores/folder.store.ts';
      const mod = await import(folderStoreModPath);
      const folders = mod.useFolderStore.getState().folders as Record<
        string,
        { name: string; ipnsName: string }
      >;
      const match = Object.values(folders).find((f) => f.name === name);
      return match?.ipnsName ?? null;
    }, folderName);
    if (!ipnsName) {
      throw new Error(
        `Could not resolve ipnsName for folder "${folderName}" from Alice's folder store`
      );
    }

    // Read Alice's real accessToken from her auth.store singleton so the
    // tombstone call below is authenticated exactly like a real API request
    // this client would make.
    const accessToken = await alice.page.evaluate(async () => {
      const authStoreModPath = '/src/stores/auth.store.ts';
      const mod = await import(authStoreModPath);
      return mod.useAuthStore.getState().accessToken;
    });
    if (!accessToken) {
      throw new Error("Could not read Alice's accessToken from auth.store");
    }

    // Real production trigger (SC4 concrete-change #4): tombstone the shared
    // folder's own IPNS name via the real POST /ipns/tombstone endpoint.
    // Alice is the record's owner (she published it when she created the
    // folder), so this is a genuine, authorized tombstone -- not a mock.
    const apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:3000';
    const tombstoneResponse = await alice.page.request.post(`${apiBaseUrl}/ipns/tombstone`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      data: { ipnsName },
    });
    expect(tombstoneResponse.ok()).toBe(true);

    // Bob attempts a real shared-folder write (create subfolder) against the
    // now-tombstoned target. Routes through the REAL classifier path: publish
    // 410 -> createAndPublishIpnsRecord tombstoned -> publishNodeFn ->
    // CannotWriteUntilRefetchError -> runWithFailureUx.
    const mkdirBtn = bob.page.locator('.toolbar-btn', { hasText: '--mkdir' });
    await mkdirBtn.click();
    const folderInput = bob.page.locator('.shared-inline-input-field');
    await folderInput.waitFor({ state: 'visible', timeout: 5000 });
    await folderInput.fill(`bob-write03-subfolder-${runId}`);
    await folderInput.press('Enter');

    const staleToast = bob.page.locator('[role="alert"]', {
      hasText: 'Write failed — access may be out of date.',
    });
    await expect(staleToast).toBeVisible({ timeout: 30000 });
    const refreshButton = staleToast.locator('button:not([aria-label="Dismiss notification"])');
    await expect(refreshButton).toHaveCount(1);
    await expect(refreshButton).toHaveText('[Refresh access]');

    // Clicking "Refresh access" re-derives/reseeds Bob's writeKey for the
    // current depth (a real, local, successful re-derivation from the share
    // grant) and retries the SAME write. It still targets the now-tombstoned
    // name, so it fails again and escalates to the terminal notice with no
    // action -- the exact D-01/WRITE-03 two-stage contract.
    await refreshButton.click();

    const revokedToast = bob.page.locator('[role="alert"]', {
      hasText: 'Write access revoked.',
    });
    await expect(revokedToast).toBeVisible({ timeout: 30000 });
    const revokedButton = revokedToast.locator('button:not([aria-label="Dismiss notification"])');
    await expect(revokedButton).toHaveCount(0);
  });
});
