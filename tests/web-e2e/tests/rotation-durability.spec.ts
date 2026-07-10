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
 * more. `page.evaluate` is still used below for three narrowly-scoped
 * purposes: (a) reading the real IndexedDB high-water floor for assertions,
 * (b) reading `vaultStore.rootIpnsName` after a real login to identify the
 * account's own root IPNS name, and (c) writing a durable seq high-water floor
 * directly into IndexedDB to STAGE the ROT-07 anti-rollback condition. (a)/(b)
 * are read-only observation; only (c) writes app rotation state -- it seeds the
 * exact durable "this device already saw a higher sequence" memory the SC#4
 * gate consumes, because the relay-replay path cannot reach the client through
 * the real resolve (see the SC#4 test's own comment for the full rationale).
 */

/**
 * Reads the durable generation/seq high-water floors for `nodeId` directly
 * from the real IndexedDB `rotation-floor` store `rotation-state.service.ts`
 * writes to (the single combined store introduced by Phase 70.1 / D-06).
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
            // Phase 70.1 (D-06) collapsed the two `generation-high-water` /
            // `seq-high-water` stores into a single `rotation-floor` store
            // keyed by nodeId, holding a `{ generation?, seq?, ... }` record.
            if (!db.objectStoreNames.contains('rotation-floor')) {
              resolve({ generation: undefined, seq: undefined });
              return;
            }
            try {
              const tx = db.transaction('rotation-floor', 'readonly');
              const getReq = tx.objectStore('rotation-floor').get(nodeId);
              tx.oncomplete = () => {
                const rec = getReq.result as { generation?: number; seq?: number } | undefined;
                resolve({ generation: rec?.generation, seq: rec?.seq });
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

/**
 * Writes a durable seq high-water floor for `nodeId` directly into the real
 * IndexedDB store `rotation-state.service.ts` owns. Used to STAGE the ROT-07
 * anti-rollback condition test-only (a device that durably observed a higher
 * sequence than the server now serves) -- see the SC#4 test comment for why
 * the relay-replay path cannot reproduce this against the live API resolve.
 *
 * The `rotation-floor` store is created WITHOUT a keyPath (out-of-line keys),
 * matching `rotation-state.service.ts` -- so `put(value, key)` passes the value
 * first and the nodeId key second. This stages only the `seq` field via a
 * read-modify-write so any existing `generation`/`wrappedKeyCheckpoint` floors
 * for the node are preserved (matching production's max-preserving write).
 */
async function writeDurableSeqFloor(page: Page, nodeId: string, value: number): Promise<void> {
  await page.evaluate(
    ({ nodeId, value }) => {
      return new Promise<void>((resolve, reject) => {
        // No version argument: open at whatever version the service created so
        // this write never races a future DB_VERSION bump.
        const req = indexedDB.open('cipherbox-rotation-state');
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains('rotation-floor')) {
            reject(new Error('rotation-floor store missing -- durable floor not yet seeded'));
            return;
          }
          try {
            const tx = db.transaction('rotation-floor', 'readwrite');
            const store = tx.objectStore('rotation-floor');
            const readBack = store.get(nodeId);
            readBack.onsuccess = () => {
              const existing =
                (readBack.result as
                  | { generation?: number; seq?: number; wrappedKeyCheckpoint?: string }
                  | undefined) ?? {};
              store.put({ ...existing, seq: value }, nodeId);
            };
            readBack.onerror = () => reject(readBack.error);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
          } catch (err) {
            reject(err);
          }
        };
      });
    },
    { nodeId, value }
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

  // SC#4 mechanism note (supersedes the 68.1-28 relay-replay approach): a
  // colluding/lagging RELAY replaying old bytes CANNOT reach the client through
  // the real resolve path. `apps/api`'s ipns.service.ts::resolveRecord prefers
  // its DB-cached record whenever `dbSeq >= networkSeq` (ipns.service.ts:685),
  // and the DB row for rootIpnsName is written synchronously by every publish
  // -- so any bytes PUT back to the mock relay are shadowed by the fresher DB
  // row and never served. Forging a HIGHER-sequence signed record (to win the
  // network-ahead branch) is impossible without the root IPNS private key
  // (client-held), and there is no HTTP surface to lower or clear the API DB
  // row. Those are product-tier facts, not test-harness gaps, and the API's
  // DB-cache-wins is itself an anti-rollback defense we must NOT weaken.
  //
  // The client-side durable floor (ROT-07) is the defense-in-depth layer this
  // spec proves: even if the WHOLE server (relay + API) regressed to an older
  // sequence, a device that has DURABLY recorded a higher sequence rejects the
  // regressed resolve fail-closed. We reproduce exactly that condition
  // test-only by raising this device's durable seq high-water floor above the
  // server's current sequence (the same persisted memory :152/:180 prove is
  // durable), then driving a real UI rename whose live reconcileFolderSequence
  // resolves the (now below-floor) server record and is rejected by the live
  // enforceResolved gate -- surfacing the D-05 toast and NOT applying the
  // rename. No product code is touched.
  test('rejects a below-durable-floor server record fail-closed via a genuine UI mutation, with the D-05 toast, and does not apply it (SC#4)', async () => {
    test.setTimeout(240_000);

    // 1. Perform a REAL bump mutation (create + rename a throwaway folder) so
    //    root republishes with a HIGHER sequence and the live
    //    reconcileFolderSequence -> enforceResolved gate advances the durable
    //    seq floor -- entirely via real UI actions.
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

    // 2. STAGE the T-68-101 anti-rollback condition test-only: raise this
    //    device's durable seq high-water floor ABOVE the server's current
    //    sequence. This is the persisted "already saw a higher sequence"
    //    memory a real device accumulates over its lifetime; here we set it
    //    directly (see this test's mechanism note above for why a relay replay
    //    cannot). The next real resolve of the server's (lower) record must be
    //    rejected fail-closed by the live enforceResolved gate.
    const injectedFloor = bumpedSeq + 1000;
    await writeDurableSeqFloor(page, rootIpnsName, injectedFloor);
    const floorsAfterInject = await readDurableFloors(page, rootIpnsName);
    expect(floorsAfterInject.seq).toBe(injectedFloor);

    // 3. Perform a REAL rename mutation on a root child. CipherBoxClient.renameItem
    //    calls reconcileFolderSequence(rootIpnsName, ...), which resolves the
    //    server's CURRENT (now below-floor) record and gates it through the live
    //    enforceResolved -- the durable floor rejects it fail-closed with a
    //    SequenceRegressionError. The dialog does NOT close on failure
    //    (handleRenameConfirm only calls closeRenameDialog() on success), so we
    //    drive the form directly rather than using the `.rename()` convenience
    //    helper (which awaits a close that will not happen).
    await fileList.rightClickItem(renamedName);
    await contextMenu.waitForOpen();
    await contextMenu.clickRename();
    await renameDialog.waitForOpen();
    await renameDialog.clearAndEnterName(`${renamedName}-rejected`);
    await renameDialog.clickSave();

    // 4. D-05: the fail-closed toast is visible with the exact UI-SPEC copy,
    //    surfaced by the SAME runWithFailureUx classifier real folder mutations
    //    use (useMutationFailureUx.ts -> dispatchRegressionRejected).
    await expect(
      page.locator('[role="alert"]', { hasText: 'Stale data from server rejected.' })
    ).toBeVisible({ timeout: 10000 });

    // The rename dialog stays open (mutation threw) -- close it so it does not
    // interfere with subsequent assertions or afterAll cleanup.
    await renameDialog.clickCancel();

    // 5. "Not applied": re-read the durable seq floor directly from real
    //    IndexedDB -- a rejected resolve never bumps the floor, so it MUST still
    //    be the injected value (the regression is rejected, not accepted).
    const floorAfterRejection = await readDurableFloors(page, rootIpnsName);
    expect(floorAfterRejection.seq).toBe(injectedFloor);

    // The item's display name must also be unchanged (the rename itself was
    // rejected, not silently applied).
    expect(await fileList.isItemVisible(renamedName)).toBe(true);
    expect(await fileList.isItemVisible(`${renamedName}-rejected`)).toBe(false);
  });
});
