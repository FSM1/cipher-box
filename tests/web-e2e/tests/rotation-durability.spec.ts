import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';
import { RenameDialogPage } from '../page-objects/dialogs/rename-dialog.page';

/**
 * Rotation Durability: real-reload IndexedDB persistence + fail-closed
 * relay-regression rejection (ROT-07 -- SC#1 / SC#4 / D-05).
 *
 * Per docs/TESTING.md, the web app is covered ONLY at this (Playwright)
 * tier. The SDK's monotonic-max/fail-closed comparison logic is already
 * unit-proven in `@cipherbox/sdk` (68-01); `rotation-state.service.ts`'s own
 * module doc states it has NO unit test and relies on THIS spec to prove its
 * real-browser IndexedDB persistence. This spec is that proof.
 *
 * SCOPE NOTE (updated -- Gap 1 closure, 68-11): the SDK client's own
 * `reconcileFolderSequence` (`packages/sdk/src/client.ts`) now gates its
 * resolve through an injected `RotationHighWater.enforceResolved` whenever
 * the client is constructed with one -- `useAuth.ts` injects the
 * IndexedDB-backed `rotation-state.service.ts` instance for every login
 * (68-11 Task 2). `useFileBrowserActions.ts`'s `handleSync` also now threads
 * a real `ResolveRotationContext`. This spec drives that LIVE path via real
 * UI mutations: renaming a root-level item triggers
 * `CipherBoxClient.renameItem` -> `reconcileFolderSequence(rootIpnsName, ...)`
 * -> `enforceResolved`, gated exactly as any real user's rename action would
 * be -- no direct `page.evaluate` + dynamic-import invocation of
 * `resolveIpnsRecord`/`enforceResolved` is needed to trigger the gate any
 * more. `page.evaluate` is still used below, but ONLY for two narrowly-scoped,
 * non-mechanism-invoking purposes: (a) reading the real IndexedDB high-water
 * floor for assertions, and (b) reading `vaultStore.rootIpnsName` after a
 * real login to identify the account's own root IPNS name for the mock-relay
 * HTTP calls below -- neither reads/writes app rotation state, both are
 * read-only observation of state the UI mutations below already produced.
 */

const MOCK_ROUTING_URL = process.env.DELEGATED_ROUTING_URL?.trim() || 'http://localhost:3001';

/**
 * Reads the durable generation/seq high-water floors for `nodeId` directly
 * from the real IndexedDB store `rotation-state.service.ts` writes to.
 * Read-only observation -- does not invoke any app resolve/enforce logic.
 */
async function readDurableFloors(
  page: Page,
  nodeId: string
): Promise<{ generation: number | undefined; seq: number | undefined }> {
  return page.evaluate(
    ({ nodeId }) => {
      return new Promise<{ generation: number | undefined; seq: number | undefined }>(
        (resolve, reject) => {
          // No version argument: open at whatever version the service created
          // so this read-only probe never races a future DB_VERSION bump.
          const req = indexedDB.open('cipherbox-rotation-state');
          req.onerror = () => reject(req.error);
          req.onsuccess = () => {
            const db = req.result;
            // The DB (or its stores) may not exist yet — e.g. a fresh profile
            // where rotation-state.service.ts has never written. Treat that as
            // "no floors recorded" instead of throwing synchronously.
            if (
              !db.objectStoreNames.contains('generation-high-water') ||
              !db.objectStoreNames.contains('seq-high-water')
            ) {
              resolve({ generation: undefined, seq: undefined });
              return;
            }
            try {
              const tx = db.transaction(['generation-high-water', 'seq-high-water'], 'readonly');
              const genReq = tx.objectStore('generation-high-water').get(nodeId);
              const seqReq = tx.objectStore('seq-high-water').get(nodeId);
              tx.oncomplete = () => {
                resolve({
                  generation: genReq.result as number | undefined,
                  seq: seqReq.result as number | undefined,
                });
              };
              tx.onerror = () => reject(tx.error);
            } catch (err) {
              reject(err);
            }
          };
        }
      );
    },
    { nodeId }
  );
}

test.describe
  .serial('Rotation Durability: real IndexedDB persistence + fail-closed rejection', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let createFolderDialog: CreateFolderDialogPage;
  let contextMenu: ContextMenuPage;
  let renameDialog: RenameDialogPage;
  let account: PrivateKeyAccount;

  const runId = Date.now().toString();

  let rootIpnsName: string;
  let seededSeq: number;
  let bumpedSeq: number;

  test.beforeAll(async ({ browser: testBrowser }) => {
    test.setTimeout(90_000); // Core Kit init + SIWE can be slow
    browser = testBrowser;
    context = await browser.newContext();
    page = await context.newPage();

    account = createTestAccount();
    await setupMockWallet(page, account);

    fileList = new FileListPage(page);
    createFolderDialog = new CreateFolderDialogPage(page);
    contextMenu = new ContextMenuPage(page);
    renameDialog = new RenameDialogPage(page);

    await loginViaWallet(page, { timeout: 60_000 });
    await page.waitForURL('**/files', { timeout: 60000 });
    await Promise.race([
      fileList.fileListContainer().waitFor({ state: 'visible', timeout: 30000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30000 }),
    ]);

    // Read-only: identify the account's own real root IPNS name post-login.
    // Does not invoke resolveIpnsRecord/enforceResolved -- see SCOPE NOTE.
    rootIpnsName = await page.evaluate(async () => {
      const vaultModPath = '/src/stores/vault.store.ts';
      const vaultMod = await import(vaultModPath);
      const name = vaultMod.useVaultStore.getState().rootIpnsName as string | null;
      if (!name) throw new Error('vault store has no rootIpnsName after login');
      return name;
    });
    expect(rootIpnsName).toMatch(/^(k51|bafzaa)/);
  });

  test.afterAll(async () => {
    if (page) {
      await deleteAccountViaPage(page);
    }
    if (context) {
      await context.close();
    }
  });

  test('seeds the durable high-water floor via a real UI mutation (create + rename, SC#4 setup)', async () => {
    // A create alone does not touch reconcileFolderSequence (createFolder has
    // no reconcile-before-publish call). Renaming the created item is the
    // real UI action that calls CipherBoxClient.renameItem ->
    // reconcileFolderSequence(rootIpnsName, ...) -> the live enforceResolved
    // gate (Gap 1 closure) -- this is the FIRST resolve this test run makes
    // through that gate, seeding the durable floor for the account's real
    // rootIpnsName.
    const folderName = `durability-seed-${runId}`;
    await page.locator('.file-browser-new-folder-button').click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(folderName);
    await fileList.waitForItemToAppear(folderName, { timeout: 30000 });

    const renamedName = `${folderName}-renamed`;
    await fileList.rightClickItem(folderName);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();
    await renameDialog.rename(renamedName);
    await fileList.waitForItemToAppear(renamedName, { timeout: 15000 });

    const floors = await readDurableFloors(page, rootIpnsName);
    expect(floors.generation).toBeDefined();
    expect(floors.seq).toBeDefined();
    seededSeq = floors.seq as number;
  });

  test('persists the floor to real IndexedDB across a real reload (SC#1)', async () => {
    // A real browser reload wipes every module-scope JS variable (the
    // rotation-state.service.ts stores, the SDK client, everything) -- only
    // the wallet session and IndexedDB survive. Reading the floor back after
    // this reload is the durability proof; reading it from any in-memory
    // map (module variable, closure, cache) would be rejected at review.
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.locator('[data-testid="user-menu"]').waitFor({ state: 'visible', timeout: 120000 });

    const floors = await readDurableFloors(page, rootIpnsName);

    // Real-IndexedDB-after-real-reload assertion (SC#1) -- not an in-memory claim.
    expect(floors.seq).toBe(seededSeq);
  });

  // 68.1-28 diagnostic note: this test currently FAILS (confirmed via a live
  // repro) not because of a toast-classification gap, but because the replay
  // below never reaches the client at all. `apps/api`'s IPNS resolve prefers
  // its DB-cached record whenever it is at or ahead of the network record
  // (ipns.service.ts::resolveRecord), and the DB row for rootIpnsName is
  // written synchronously by THIS SAME test's own "bump" mutation below --
  // so by the time the replay is PUT to the mock relay, the DB row is
  // already strictly ahead of the replayed bytes and always wins the
  // resolve. The rename mutation below therefore SUCCEEDS silently (renames
  // to "-rejected") instead of throwing anything for useMutationFailureUx to
  // classify. See 68.1-28-SUMMARY.md for the full trace; per that plan's
  // explicit scope boundary this was surfaced, not fixed here -- assertions
  // below are left intact ("never weaken an assertion") pending a dedicated
  // follow-up plan.
  test('rejects a relay-replayed stale record fail-closed via a genuine UI mutation, with the D-05 toast, and does not apply it (SC#4)', async ({
    request,
  }) => {
    test.setTimeout(60_000);
    const encodedName = encodeURIComponent(rootIpnsName);
    const recordUrl = `${MOCK_ROUTING_URL}/routing/v1/ipns/${encodedName}`;

    // 1. Capture the CURRENT record bytes directly from the delegated-routing
    //    mock -- this is the "old" record a colluding/lagging relay (T-68-101)
    //    could later replay once a newer sequence has been published.
    const staleResponse = await request.get(recordUrl, {
      headers: { Accept: 'application/vnd.ipfs.ipns-record' },
    });
    expect(staleResponse.ok()).toBe(true);
    const staleBytes = await staleResponse.body();

    // 2. Perform a REAL bump mutation (create + rename another throwaway
    //    folder) so root republishes with a HIGHER sequence, and the live
    //    reconcileFolderSequence -> enforceResolved gate advances the durable
    //    floor past the bytes captured above -- entirely via real UI actions.
    const folderName = `durability-bump-${runId}`;
    await page.locator('.file-browser-new-folder-button').click();
    await createFolderDialog.waitForOpen();
    await createFolderDialog.createFolder(folderName);
    await fileList.waitForItemToAppear(folderName, { timeout: 30000 });

    const renamedName = `${folderName}-renamed`;
    await fileList.rightClickItem(folderName);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();
    await renameDialog.rename(renamedName);
    await fileList.waitForItemToAppear(renamedName, { timeout: 15000 });

    const floorsAfterBump = await readDurableFloors(page, rootIpnsName);
    bumpedSeq = floorsAfterBump.seq as number;
    expect(bumpedSeq).toBeGreaterThan(seededSeq);

    // 3. Replay the captured stale bytes back into the mock relay -- this is
    //    the T-68-101 colluding/lagging relay scenario: a lower-sequence
    //    record served after a higher sequence has already been observed.
    const putResponse = await request.put(recordUrl, {
      data: staleBytes,
      headers: { 'Content-Type': 'application/vnd.ipfs.ipns-record' },
    });
    expect(putResponse.ok()).toBe(true);

    // 4. Perform a REAL revocation-triggering mutation on a root child --
    //    renaming the same item again. CipherBoxClient.renameItem calls
    //    reconcileFolderSequence(rootIpnsName, ...), which resolves the
    //    NOW-STALE record from the relay above and gates it through
    //    enforceResolved (live, Gap 1 closure) -- the durable floor rejects
    //    it fail-closed. The dialog does NOT close on failure
    //    (handleRenameConfirm only calls closeRenameDialog() on success), so
    //    we drive the form directly rather than using the `.rename()`
    //    convenience helper (which awaits a close that will not happen).
    await fileList.rightClickItem(renamedName);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();
    await renameDialog.clearAndEnterName(`${renamedName}-rejected`);
    await renameDialog.clickSave();

    // 5. D-05: the fail-closed toast is visible with the exact UI-SPEC copy,
    //    surfaced by the SAME runWithFailureUx classifier real folder
    //    mutations use (useFolderMutations.ts).
    await expect(
      page.locator('[role="alert"]', { hasText: 'Stale data from server rejected.' })
    ).toBeVisible({ timeout: 10000 });

    // The rename dialog stays open (mutation threw) -- close it so it does
    // not interfere with subsequent assertions or afterAll cleanup.
    await renameDialog.clickCancel();

    // 6. "Not applied": re-read the durable seq floor directly from real
    //    IndexedDB -- it MUST still be the bumped value, never the replayed
    //    stale sequence (the regression is rejected, not silently accepted).
    const floorAfterRejection = await readDurableFloors(page, rootIpnsName);
    expect(floorAfterRejection.seq).toBe(bumpedSeq);

    // The item's display name must also be unchanged (the rename itself was
    // rejected, not silently applied against the stale record).
    expect(await fileList.isItemVisible(renamedName)).toBe(true);
    expect(await fileList.isItemVisible(`${renamedName}-rejected`)).toBe(false);
  });
});
