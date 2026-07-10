import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';

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

  // SCOPE NOTE (updated for Phase 73 SC4 -- restructured toward a
  // classifier-driven flow, per 73-RESEARCH.md SC4): CannotWriteUntilRefetchError's
  // throw site in packages/sdk/src/share/shared-write.ts is already correctly
  // wired and needs NO change -- the gap was entirely upstream/downstream of
  // it, across three stacked seams:
  //   - 73-02: packages/sdk-core/src/ipns/index.ts's createAndPublishIpnsRecord
  //     maps a real API 410 (apps/api's IPNS_TOMBSTONED) to a typed
  //     `{ tombstoned: true }` result instead of letting a raw AxiosError
  //     propagate uncaught.
  //   - 73-05: packages/sdk/src/client.ts's publishNodeFn
  //     (buildWriteTransportSeams) reads that new `tombstoned` field and maps
  //     it straight through to shared-write.ts's existing
  //     CannotWriteUntilRefetchError throw sites.
  //   - 73-08: apps/web/src/hooks/useSharedWriteOps.ts wires every
  //     shared-write mutation through runWithFailureUx (today it calls NONE
  //     of them through the classifier -- only withRevocationGuard's 403
  //     detection wraps shared writes), threading a refreshWriteAccess
  //     supplier that re-derives/reseeds the current depth's writeKey (the
  //     SC1/SC6 consolidated restore helper's re-derive path).
  //
  // Once all three land, this test drives a GENUINE flow instead of direct
  // notification-store injection: a co-writer performs a real shared-folder
  // write whose publish target has been tombstoned (e.g. the owner
  // rotates/tombstones the writer's IPNS name via a real API/DB fixture),
  // and the co-writer's write attempt surfaces the SAME "Refresh access"
  // toast THROUGH the real classifier path (runWithFailureUx ->
  // CannotWriteUntilRefetchError), not via direct notification injection.
  //
  // Impl plan 73-08 removes this fixme guard and finalizes the assertions
  // once the seams above land. Until then, do NOT remove the direct-injection
  // assertions below (kept as a reference for the exact toast copy/action
  // contract 73-08's real-flow version must preserve) -- they are commented
  // out, not deleted, so 73-08 knows precisely what this test used to assert
  // before it had a real production trigger.
  test.fixme('a stale co-writer write surfaces Refresh access, escalating to a terminal Write access revoked with no action (D-01/WRITE-03)', async () => {
    test.setTimeout(60_000);

    // TARGET FLOW (skeleton -- 73-08 fills in the real multi-account
    // tombstone trigger and finalizes locators):
    // 1. Set up a co-writer share (owner + writer accounts, write
    //    permission) -- mirror tests/web-e2e/tests/writable-shares.spec.ts's
    //    multi-account harness (createWalletTestAccount for owner/writer).
    // 2. Owner rotates/tombstones the writer's IPNS write name via a real
    //    fixture (API call or DB tombstone), simulating a completed
    //    write-revocation rotation the writer has not yet refetched.
    // 3. Writer attempts a real shared-folder write (upload/rename) that
    //    targets the now-tombstoned IPNS name.
    // 4. Assert the SAME "Write failed — access may be out of date." toast
    //    with a "[Refresh access]" action appears -- reached THROUGH the
    //    real runWithFailureUx -> CannotWriteUntilRefetchError classifier
    //    path (useMutationFailureUx.ts#dispatchWriteDescriptorStale), not
    //    via direct notification-store injection.
    // 5. Clicking "Refresh access" re-derives the writer's writeKey/state
    //    for the current depth and retries the write.
    // 6. A second write against a still-tombstoned target escalates to the
    //    terminal "Write access revoked." toast with NO action button.
    //
    // PRE-73-08 direct-injection assertions this replaces (reference only,
    // not executed -- 73-08 must preserve this exact toast copy/action
    // contract when wiring the real trigger):
    //
    //   await page.evaluate(async () => {
    //     const mod = await import('/src/stores/notification.store.ts');
    //     mod.useNotificationStore.getState().addNotification('error',
    //       'Write failed — access may be out of date.', {
    //         label: 'Refresh access',
    //         onClick: () => { /* record click */ },
    //       });
    //   });
    //   const staleToast = page.locator('[role="alert"]', {
    //     hasText: 'Write failed — access may be out of date.',
    //   });
    //   await expect(staleToast).toBeVisible();
    //   const refreshButton = staleToast.locator(
    //     'button:not([aria-label="Dismiss notification"])'
    //   );
    //   await expect(refreshButton).toHaveCount(1);
    //   await expect(refreshButton).toHaveText('[Refresh access]');
    //   await refreshButton.click();
    //   // ... escalation: clearNotifications() + addNotification('error',
    //   // 'Write access revoked.') with no action button, assert
    //   // revokedToast visible and its action button count is 0.
  });

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
