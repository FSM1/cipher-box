import { test, expect, Browser } from '@playwright/test';
import { createWalletTestAccount, closeWalletTestAccounts } from '../utils/multi-account-wallet';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';

/**
 * Poll Monotonicity Regression (SC3c / D-08 item 3)
 *
 * Proves the poll-vs-nav data-integrity race is closed: a slow in-flight poll
 * response applied by `useSyncPolling.ts::invalidateOpenFolder` can NEVER
 * overwrite a newer nav-triggered folder state. The write is gated by
 * `sequenceNumber` (the IPNS clock), mirroring folder.store.ts's existing
 * monotonicity guard — a stale poll result (captured at an older sequence)
 * is dropped once a newer sequence has landed on the same open folder.
 *
 * DETERMINISM (no poll-timing reliance): the race is reproduced by CONTROLLED
 * ORDERING, not by waiting out the 30s IPNS poll:
 *   1. Open a folder (real login + real subfolder), record its live
 *      `sequenceNumber` (S1) from the exposed folder store.
 *   2. Arm a `/ipns/resolve` route interceptor that HOLDS only the OPEN
 *      folder's resolve (root `onSync` resolves for other names pass through).
 *   3. Trigger a poll via a deterministic visibility regain — the poll's
 *      open-folder `listFolder`/`ensureFolderLoaded(forceResolve)` resolve is
 *      now in flight and HELD at the network boundary (we await proof it was
 *      intercepted — no timing guess).
 *   4. While the stale poll is held, a NEWER nav-triggered state lands: the
 *      folder store is advanced to S2 = S1 + 100 with a distinctive marker
 *      child, exactly as a nav re-resolve writes (`updateFolderChildren` +
 *      `updateFolderSequence`). The real backend still holds S1, so the held
 *      poll is now STALE.
 *   5. Release the held resolve. The poll completes carrying the real (stale)
 *      S1 record.
 *   6. Assert the open folder still reflects the NEWER state (S2 + marker),
 *      not the stale poll — the stale write was dropped by the sequence guard.
 *
 * EXPECTED-RED before the fix: without the sequence guard in
 * `invalidateOpenFolder`, the stale poll's `updateFolderChildren` /
 * `updateFolderSequence(S1)` clobbers the newer state — the marker child
 * disappears and the sequence regresses to S1. Turns GREEN once the guard
 * drops any poll result whose resolved sequence is older than the store's
 * current sequence.
 *
 * This is a PERMANENT regression test — do NOT `test.skip` or `test.fixme` it,
 * ever. Modeled on the multi-account nav-triggered-re-resolve house style of
 * `shared-folder-desync.spec.ts` (single account suffices here).
 */
/**
 * Minimal structural view of the folder store exposed on `window` in the dev
 * build (`apps/web/src/stores/folder.store.ts`, `import.meta.env.DEV`). Only
 * the members this spec touches are typed — avoids importing app internals
 * into the web-e2e project.
 */
type ExposedFolder = {
  ipnsName: string;
  isLoaded: boolean;
  sequenceNumber: bigint;
  children: Array<{ name: string }>;
};
type ExposedFolderStore = {
  getState: () => {
    currentFolderId: string | null;
    folders: Record<string, ExposedFolder>;
    updateFolderChildren: (id: string, children: Array<Record<string, unknown>>) => void;
    updateFolderSequence: (id: string, sequenceNumber: bigint) => void;
  };
};

declare global {
  interface Window {
    __ZUSTAND_FOLDER_STORE__?: ExposedFolderStore;
  }
}

test.describe.serial('Poll Monotonicity (SC3c / D-08 item 3)', () => {
  let browser: Browser;
  let user: Awaited<ReturnType<typeof createWalletTestAccount>>;

  let fileList: FileListPage;
  let createFolderDialog: CreateFolderDialogPage;

  const runId = Date.now().toString();
  const folderName = `poll-race-${runId}`;

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
  });

  test.afterAll(async () => {
    if (user) {
      await closeWalletTestAccounts([user].filter(Boolean));
    }
  });

  test('1. Create a test account and open a subfolder', async () => {
    test.setTimeout(180_000); // wallet login (up to 90s) + vault init

    user = await createWalletTestAccount(browser, 'user');
    fileList = new FileListPage(user.page);
    createFolderDialog = new CreateFolderDialogPage(user.page);

    // Create a subfolder so the OPEN folder's ipnsName differs from the root
    // ipnsName (root is what `onSync` resolves — we must not hold that).
    const newFolderButton = user.page.locator('.file-browser-new-folder-button');
    await newFolderButton.click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(folderName);
    await fileList.waitForItemToAppear(folderName, { timeout: 30000 });

    // Open it — this loads the folder and makes it the current open folder.
    await fileList.doubleClickFolder(folderName);
    await user.page
      .locator('.breadcrumb-item', { hasText: folderName.toLowerCase() })
      .waitFor({ state: 'visible', timeout: 30000 });
  });

  test('2. A stale in-flight poll cannot clobber a newer nav-triggered state', async () => {
    test.setTimeout(120_000);

    const page = user.page;

    // --- Read the live open-folder identity + sequence (S1) from the store.
    const opened = await page.evaluate(() => {
      const store = window.__ZUSTAND_FOLDER_STORE__;
      if (!store) return null;
      const state = store.getState();
      const id = state.currentFolderId;
      if (!id) return null;
      const folder = state.folders[id];
      if (!folder || !folder.isLoaded) return null;
      return { id, ipnsName: folder.ipnsName, seq: folder.sequenceNumber.toString() };
    });

    // The exposed store is only present in the dev build (import.meta.env.DEV).
    // The web-e2e config boots the vite dev server, so it must be available.
    expect(opened, 'window.__ZUSTAND_FOLDER_STORE__ open folder must be resolvable').not.toBeNull();
    const { id: folderId, ipnsName: folderIpnsName, seq: s1 } = opened!;
    const newerSeq = (BigInt(s1) + 100n).toString();

    // --- Arm the interceptor: HOLD only the open folder's resolve.
    let holding = false;
    const heldResolvers: Array<() => void> = [];
    let markFolderResolveSeen!: () => void;
    const folderResolveSeen = new Promise<void>((resolve) => {
      markFolderResolveSeen = resolve;
    });

    await page.route('**/ipns/resolve**', async (route) => {
      const url = route.request().url();
      if (holding && url.includes(folderIpnsName)) {
        markFolderResolveSeen();
        // Hold this resolve at the network boundary until explicitly released.
        await new Promise<void>((resolve) => heldResolvers.push(resolve));
      }
      await route.continue();
    });

    // --- Trigger a poll deterministically via a visibility regain edge.
    // `useVisibility` reads `document.hidden`; toggle hidden -> visible so the
    // visibility-regain effect fires `doSync` (which runs `invalidateOpenFolder`
    // after the root `onSync`). No reliance on the 30s interval.
    const triggerPoll = async () => {
      await page.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: true, configurable: true });
        document.dispatchEvent(new Event('visibilitychange'));
      });
      await page.evaluate(() => {
        Object.defineProperty(document, 'hidden', { value: false, configurable: true });
        document.dispatchEvent(new Event('visibilitychange'));
      });
    };

    holding = true;
    // Fire the poll; a concurrent in-flight sync can swallow one edge (the
    // `isSyncingRef` guard), so retry the visibility edge until the open
    // folder's resolve is actually intercepted.
    let intercepted = false;
    for (let attempt = 0; attempt < 5 && !intercepted; attempt++) {
      await triggerPoll();
      intercepted = await Promise.race([
        folderResolveSeen.then(() => true),
        page.waitForTimeout(6000).then(() => false),
      ]);
    }
    expect(intercepted, 'the open-folder poll resolve must be intercepted in flight').toBe(true);

    // --- The NEWER nav-triggered state lands while the stale poll is held.
    // This mirrors exactly what a nav re-resolve writes into the store.
    await page.evaluate(
      ({ id, seq }) => {
        const store = window.__ZUSTAND_FOLDER_STORE__!;
        const markerChild = {
          ipnsName: 'k51-newer-nav-marker',
          name: 'NEWER_NAV_MARKER',
          kind: 'file' as const,
          modifiedAt: Date.now(),
          sequence: 0,
        };
        store.getState().updateFolderChildren(id, [markerChild]);
        store.getState().updateFolderSequence(id, BigInt(seq));
      },
      { id: folderId, seq: newerSeq }
    );

    // --- Release the stale poll; it now completes carrying the real S1 record.
    holding = false;
    for (const release of heldResolvers.splice(0)) release();

    // Let the released resolves complete and the poll attempt its (dropped)
    // store write. This is a short network settle, NOT a poll-timing wait.
    await page.waitForTimeout(1500);

    // --- Assert the newer nav-triggered state survived: the stale poll was
    // dropped by the sequence guard.
    const after = await page.evaluate((id) => {
      const folder = window.__ZUSTAND_FOLDER_STORE__!.getState().folders[id];
      return {
        seq: folder.sequenceNumber.toString(),
        names: folder.children.map((child) => child.name),
      };
    }, folderId);

    expect(after.seq, 'sequence must not regress to the stale poll value').toBe(newerSeq);
    expect(after.names, 'newer nav-triggered marker child must survive the stale poll').toContain(
      'NEWER_NAV_MARKER'
    );

    await page.unroute('**/ipns/resolve**');
  });
});
