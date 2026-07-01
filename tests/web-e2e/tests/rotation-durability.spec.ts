import { test, expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import type { PrivateKeyAccount } from 'viem/accounts';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { deleteAccountViaPage } from '../utils/cleanup-helpers';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { CreateFolderDialogPage } from '../page-objects/dialogs/create-folder-dialog.page';

/**
 * Rotation Durability: real-reload IndexedDB persistence + fail-closed
 * relay-regression rejection (ROT-07 — SC#1 / SC#4 / D-05).
 *
 * Per docs/TESTING.md, the web app is covered ONLY at this (Playwright)
 * tier. The SDK's monotonic-max/fail-closed comparison logic is already
 * unit-proven in `@cipherbox/sdk` (68-01); `rotation-state.service.ts`'s own
 * module doc states it has NO unit test and relies on THIS spec to prove its
 * real-browser IndexedDB persistence. This spec is that proof.
 *
 * SCOPE NOTE (source-verified gap, not an oversight): as of this phase, NO
 * production call site threads a `rotation` context into
 * `ipns.service.ts#resolveIpnsRecord` (grep confirms zero call sites pass a
 * second argument) — `useFileBrowserActions.ts`'s own comment says "once a
 * rotation context is threaded through here" for its still-unwired sync
 * resolve. `enforceResolved`/`seedFromGrant` are therefore not yet reachable
 * from any UI click. To still prove the REAL, shipped adapter — real
 * IndexedDB, real browser reload, real network resolve, real notification
 * toast — this spec drives `ipns.service.ts#resolveIpnsRecord` and
 * `useMutationFailureUx.ts#runWithFailureUx` directly via the Vite dev
 * server's module graph (`page.evaluate` + dynamic `import('/src/...')`,
 * which Vite transforms identically to a statically-imported module — the
 * SAME module instance the running app already loaded). A synthetic `nodeId`
 * decouples the durable-floor key from any real node so this spec cannot
 * collide with the app's own (currently dormant) rotation state. The
 * underlying resolve target is the test account's own root IPNS name — always
 * resolvable, requiring no sharing setup for this specific proof.
 */

const MOCK_ROUTING_URL = process.env.DELEGATED_ROUTING_URL?.trim() || 'http://localhost:3001';

test.describe
  .serial('Rotation Durability: real IndexedDB persistence + fail-closed rejection', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let createFolderDialog: CreateFolderDialogPage;
  let account: PrivateKeyAccount;

  const runId = Date.now().toString();
  const nodeId = `e2e-durability-${runId}`;

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

  test('seeds the durable high-water floor via a real network resolve', async () => {
    const result = await page.evaluate(
      async ({ nodeId }) => {
        const vaultModPath = '/src/stores/vault.store.ts';
        const ipnsModPath = '/src/services/ipns.service.ts';
        const vaultMod = await import(vaultModPath);
        const ipnsMod = await import(ipnsModPath);

        const rootIpnsName = vaultMod.useVaultStore.getState().rootIpnsName as string | null;
        if (!rootIpnsName) throw new Error('vault store has no rootIpnsName after login');

        const resolved = await ipnsMod.resolveIpnsRecord(rootIpnsName, {
          nodeId,
          generation: 1,
          versionFloor: 0,
        });
        if (!resolved) throw new Error('root IPNS name did not resolve');

        return { rootIpnsName, seq: Number(resolved.sequenceNumber) };
      },
      { nodeId }
    );

    expect(result.rootIpnsName).toMatch(/^(k51|bafzaa)/);
    expect(Number.isInteger(result.seq)).toBe(true);
    expect(result.seq).toBeGreaterThanOrEqual(0);

    rootIpnsName = result.rootIpnsName;
    seededSeq = result.seq;
  });

  test('persists the floor to real IndexedDB across a real reload (SC#1)', async () => {
    // A real browser reload wipes every module-scope JS variable (the
    // rotation-state.service.ts stores, the SDK client, everything) — only
    // the wallet session and IndexedDB survive. Reading the floor back after
    // this reload is the durability proof; reading it from any in-memory
    // map (module variable, closure, cache) would be rejected at review.
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.locator('[data-testid="user-menu"]').waitFor({ state: 'visible', timeout: 120000 });

    const floors = await page.evaluate(
      ({ nodeId }) => {
        return new Promise<{ generation: number | undefined; seq: number | undefined }>(
          (resolve, reject) => {
            const req = indexedDB.open('cipherbox-rotation-state', 1);
            req.onerror = () => reject(req.error);
            req.onsuccess = () => {
              const db = req.result;
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
            };
          }
        );
      },
      { nodeId }
    );

    // Real-IndexedDB-after-real-reload assertion (SC#1) — not an in-memory claim.
    expect(floors.generation).toBe(1);
    expect(floors.seq).toBe(seededSeq);
  });

  test('rejects a relay-replayed stale record fail-closed with the D-05 toast and does not apply it (SC#4)', async ({
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

    // 2. Perform a REAL mutation (throwaway folder create) that republishes
    //    root with a HIGHER sequence, then resolve again through the rotation
    //    gate so the durable floor advances past the bytes captured above.
    await page.locator('.file-browser-new-folder-button').click();
    await createFolderDialog.waitForOpen();
    const throwawayFolderName = `durability-bump-${runId}`;
    await createFolderDialog.createFolder(throwawayFolderName);
    await fileList.waitForItemToAppear(throwawayFolderName, { timeout: 30000 });

    const bumped = await page.evaluate(
      async ({ nodeId, rootIpnsName }) => {
        const ipnsModPath = '/src/services/ipns.service.ts';
        const ipnsMod = await import(ipnsModPath);
        const resolved = await ipnsMod.resolveIpnsRecord(rootIpnsName, {
          nodeId,
          generation: 1,
          versionFloor: 0,
        });
        return resolved ? Number(resolved.sequenceNumber) : null;
      },
      { nodeId, rootIpnsName }
    );

    expect(bumped).not.toBeNull();
    expect(bumped as number).toBeGreaterThan(seededSeq);
    bumpedSeq = bumped as number;

    // 3. Replay the captured stale bytes back into the mock relay -- this is
    //    the T-68-101 colluding/lagging relay scenario: a lower-sequence
    //    record served after a higher sequence has already been observed.
    const putResponse = await request.put(recordUrl, {
      data: staleBytes,
      headers: { 'Content-Type': 'application/vnd.ipfs.ipns-record' },
    });
    expect(putResponse.ok()).toBe(true);

    // 4. Resolve through the SAME classifier the real mutation hooks use
    //    (runWithFailureUx wrapping resolveIpnsRecord, exactly as
    //    useFolderMutations.ts and useFileBrowserActions.ts do) -- the durable
    //    floor now rejects the replayed record fail-closed.
    const outcome = await page.evaluate(
      async ({ nodeId, rootIpnsName }) => {
        const failureUxModPath = '/src/hooks/useMutationFailureUx.ts';
        const ipnsModPath = '/src/services/ipns.service.ts';
        const failureUxMod = await import(failureUxModPath);
        const ipnsMod = await import(ipnsModPath);
        try {
          await failureUxMod.runWithFailureUx(() =>
            ipnsMod.resolveIpnsRecord(rootIpnsName, { nodeId, generation: 1, versionFloor: 0 })
          );
          return { threw: false, name: null as string | null };
        } catch (err) {
          return { threw: true, name: (err as Error).name };
        }
      },
      { nodeId, rootIpnsName }
    );

    expect(outcome.threw).toBe(true);
    expect(outcome.name).toBe('SequenceRegressionError');

    // 5. D-05: the fail-closed toast is visible with the exact UI-SPEC copy.
    await expect(
      page.locator('[role="alert"]', { hasText: 'Stale data from server rejected.' })
    ).toBeVisible({ timeout: 10000 });

    // 6. "Not applied": re-read the durable seq floor directly from real
    //    IndexedDB -- it MUST still be the bumped value, never the replayed
    //    stale sequence (the regression is rejected, not silently accepted).
    const floorAfterRejection = await page.evaluate(
      ({ nodeId }) => {
        return new Promise<number | undefined>((resolve, reject) => {
          const req = indexedDB.open('cipherbox-rotation-state', 1);
          req.onerror = () => reject(req.error);
          req.onsuccess = () => {
            const db = req.result;
            const tx = db.transaction('seq-high-water', 'readonly');
            const getReq = tx.objectStore('seq-high-water').get(nodeId);
            getReq.onsuccess = () => resolve(getReq.result as number | undefined);
            getReq.onerror = () => reject(getReq.error);
          };
        });
      },
      { nodeId }
    );

    expect(floorAfterRejection).toBe(bumpedSeq);
  });
});
