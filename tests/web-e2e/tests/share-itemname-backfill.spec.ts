import { randomUUID } from 'node:crypto';
import { test, expect, type Browser } from '@playwright/test';
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
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';

/**
 * REQ-4 (Phase 48) — lazy backfill of share itemName at rest (decision A2).
 *
 * Exercises the gap closed by PR #505: a LEGACY share (plaintext shares.item_name,
 * NULL item_name_encrypted, created before at-rest encryption existed) gets its
 * display name ECIES-re-wrapped for the recipient and persisted server-side via
 * the new PATCH /shares/:shareId/item-name endpoint, with the server staying
 * zero-knowledge (it never sees plaintext; it only stores client ciphertext).
 *
 * Flow under test (apps/web/src/services/share.service.ts):
 *   owner uploads a file  ->  SDK reWrapNewItems -> getCoveringShares callback
 *   -> findCoveringShares -> ensureFreshSentShares -> fetchAllSentShares
 *   -> backfillSentShareItemNames (fire-and-forget) -> PATCH /shares/:id/item-name
 *
 * Why "upload a file" is the trigger: getCoveringShares is invoked on every add
 * into a folder (packages/sdk/src/client.ts:155, before the covering-length check),
 * and fetchAllSentShares fires the backfill over ALL sent shares regardless of
 * which folder was uploaded into. There is no "sent shares list" UI page that
 * triggers it, so the upload is the deterministic hook.
 *
 * Assertion strategy (see audit): proving "ciphertext at rest" needs two signals,
 * because the recipient row keeps its legacy plaintext itemName during rollout and
 * decryptItemName falls back to plaintext on failure — so the recipient seeing the
 * right name alone could be a false pass. We therefore pair:
 *   (a) owner-side GET /shares/sent: itemNameEncrypted flips null -> valid hex that
 *       is NOT the plaintext and is longer than the plaintext (ECIES overhead), and
 *   (b) recipient-side: the share still displays the correct name AND the recipient
 *       row now carries non-null itemNameEncrypted.
 * web-e2e has no direct Postgres access; GET /shares/sent (which serializes the
 * bytea column to hex) is the in-harness proxy for the raw at-rest bytes.
 */

interface ApiResult {
  ok: boolean;
  status: number;
  step?: string;
  data?: unknown;
}

interface ShareRow {
  shareId: string;
  ipnsName: string;
  itemName: string;
  itemNameEncrypted: string | null;
  recipientPublicKey?: string;
  sharerPublicKey?: string;
}

/**
 * Call the CipherBox API from the page's browser context with the user's auth.
 * Mirrors the /auth/refresh -> Bearer pattern in utils/cleanup-helpers.ts so the
 * call runs as the logged-in user (HTTP-only refresh cookie -> access token).
 */
async function callApi(
  page: WalletTestAccount['page'],
  method: string,
  path: string,
  body?: unknown
): Promise<ApiResult> {
  return page.evaluate(
    async ({ method, path, body }) => {
      const apiUrl =
        (window as unknown as Record<string, string>).__VITE_API_URL ||
        document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
        (window.location.origin.includes('app-staging.')
          ? window.location.origin.replace('app-staging.', 'api-staging.')
          : window.location.origin.includes('app.')
            ? window.location.origin.replace('app.', 'api.')
            : 'http://localhost:3000');

      const refreshRes = await fetch(`${apiUrl}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!refreshRes.ok) return { ok: false, step: 'refresh', status: refreshRes.status };
      const { accessToken } = await refreshRes.json();

      const res = await fetch(`${apiUrl}${path}`, {
        method,
        credentials: 'include',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      let data: unknown = null;
      try {
        data = await res.json();
      } catch {
        data = null;
      }
      return { ok: res.ok, status: res.status, data };
    },
    { method, path, body }
  );
}

async function fetchSentShare(
  page: WalletTestAccount['page'],
  ipnsName: string
): Promise<ShareRow | undefined> {
  const res = await callApi(page, 'GET', '/shares/sent?limit=100&offset=0');
  if (!res.ok) throw new Error(`GET /shares/sent failed: ${res.status} (${res.step ?? 'request'})`);
  const rows = (res.data as { shares?: ShareRow[] })?.shares ?? [];
  return rows.find((s) => s.ipnsName === ipnsName);
}

async function fetchReceivedShare(
  page: WalletTestAccount['page'],
  ipnsName: string
): Promise<ShareRow | undefined> {
  const res = await callApi(page, 'GET', '/shares/received?limit=100&offset=0');
  if (!res.ok)
    throw new Error(`GET /shares/received failed: ${res.status} (${res.step ?? 'request'})`);
  const rows = (res.data as { shares?: ShareRow[] })?.shares ?? [];
  return rows.find((s) => s.ipnsName === ipnsName);
}

test.describe.serial('Share itemName lazy backfill (REQ-4 / decision A2)', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let bob: WalletTestAccount;

  let aliceFileList: FileListPage;
  let aliceUploadZone: UploadZonePage;
  let bobShared: SharedFileBrowserPage;

  // Unique per run.
  const runId = Date.now().toString(36).toLowerCase();
  const legacyItemName = `legacy share ${runId}`;
  // rootIpnsName must be a valid CIDv1 libp2p-key per the current CreateShareDto:
  // /^(k51qzi5uqu5[a-z0-9]{40,60}|bafzaa[a-z2-7]{50,70})$/ — build a unique,
  // well-formed k51 name from runId + random lowercase/digit padding.
  const legacyIpnsName = `k51qzi5uqu5${(
    runId +
    Math.random().toString(36).slice(2) +
    Math.random().toString(36).slice(2)
  )
    .padEnd(44, '0')
    .slice(0, 44)}`;
  // Dummy hex descriptor: even-length hex, >= 64 chars (CreateShareDto
  // MinLength(64)) reused for readDescriptorRef. The recipient never OPENS
  // this share, so the wrapped bytes need not be a real ECIES envelope --
  // only the display-name path is under test.
  const dummyReadDescriptorRef = 'ab'.repeat(64);
  const legacyRootNodeId = randomUUID();
  const legacyItemNameHex = Buffer.from(legacyItemName, 'utf8').toString('hex');

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
    bobShared = new SharedFileBrowserPage(bob.page);

    expect(alice.publicKey).not.toBe(bob.publicKey);
    expect(bob.publicKey).toMatch(/^(0x)?04[0-9a-fA-F]{128}$/);
  });

  test('2. Seed a legacy share (plaintext itemName, NULL itemNameEncrypted)', async () => {
    // Bypass the web ShareDialog (which always sends ciphertext) and POST /shares
    // directly with itemNameEncrypted OMITTED — the shape a pre-encryption client
    // produced. CreateShareDto marks itemNameEncrypted @IsOptional and the service
    // stores NULL when absent (apps/api/src/shares/shares.service.ts).
    //
    // GAP-5 (68.1-21): the current CreateShareDto (post node/v3 schema cutover,
    // apps/api/src/shares/dto/create-share.dto.ts) requires the descriptor-ref
    // shape (readDescriptorRef/rootNodeId/rootIpnsName) and has no plaintext
    // display-name field at all anymore -- the OLD body shape below 400'd
    // outright, both from the stale field names AND because the server's
    // whitelist:true/forbidNonWhitelisted:true ValidationPipe rejects any
    // unrecognized property (including a plaintext `itemName`, which is no
    // longer a DTO field). See 68.1-21-SUMMARY.md "Known Gaps" for the deeper
    // finding this surfaced: the `shares` table's plaintext `item_name`
    // column itself was DROPPED by migration 1750000000000-ApiSchemaCutover,
    // not merely renamed -- the server can never return it again. The
    // assertions below that still reference `itemName` are retained
    // UNMODIFIED (not weakened) as an accurate record of the now-impossible
    // REQ-4 legacy-backfill scenario; they are expected to keep failing until
    // a follow-up plan resolves that gap.
    const res = await callApi(alice.page, 'POST', '/shares', {
      recipientPublicKey: bob.publicKey,
      readDescriptorRef: dummyReadDescriptorRef,
      rootNodeId: legacyRootNodeId,
      rootIpnsName: legacyIpnsName,
      // itemName intentionally omitted -- not a valid DTO field post-cutover
      // itemNameEncrypted intentionally omitted -> legacy (backfill-pending) row
    });
    expect(
      res.ok,
      `POST /shares should succeed (got ${res.status} at ${res.step ?? 'request'})`
    ).toBe(true);

    const seeded = await fetchSentShare(alice.page, legacyIpnsName);
    expect(seeded, 'seeded share should appear in GET /shares/sent').toBeDefined();
    expect(seeded?.itemName).toBe(legacyItemName);
    expect(seeded?.itemNameEncrypted, 'legacy row starts with NULL ciphertext').toBeNull();
  });

  test('3. Recipient sees the legacy share by name (plaintext fallback) pre-backfill', async () => {
    await navigateToShared(bob);
    await bobShared.waitForLoaded({ timeout: 30_000 });
    await bobShared.waitForSharedItem(legacyItemName, { timeout: 20_000 });

    const names = await bobShared.getSharedItemNames();
    expect(names.some((n) => n.includes(legacyItemName))).toBe(true);

    // Confirm it is genuinely a legacy row on the recipient side too.
    const received = await fetchReceivedShare(bob.page, legacyIpnsName);
    expect(received?.itemNameEncrypted, 'recipient row is legacy pre-backfill').toBeNull();
  });

  test('4. Owner upload triggers the backfill; ciphertext is persisted', async () => {
    test.setTimeout(120_000);
    // Any upload fires SDK reWrapNewItems -> getCoveringShares -> fetchAllSentShares
    // -> backfillSentShareItemNames over all sent shares. Alice's session has had no
    // prior sent-share fetch, so the 30s cache is cold and this fetch runs fresh.
    await navigateToFiles(alice);
    const triggerFile = createTestTextFile(`trigger-${runId}.txt`, 'fire the backfill');
    await aliceUploadZone.uploadFile(triggerFile.path);
    await aliceFileList.waitForItemToAppear(`trigger-${runId}.txt`, { timeout: 30_000 });

    // Backfill is fire-and-forget — poll until the ciphertext lands.
    await expect
      .poll(
        async () => (await fetchSentShare(alice.page, legacyIpnsName))?.itemNameEncrypted ?? null,
        {
          timeout: 45_000,
          intervals: [500, 1000, 1000, 2000, 3000],
          message: 'backfill should persist itemNameEncrypted after the owner upload',
        }
      )
      .not.toBeNull();
  });

  test('5. Persisted itemNameEncrypted is ciphertext at rest, not plaintext', async () => {
    const seeded = await fetchSentShare(alice.page, legacyIpnsName);
    expect(seeded?.itemNameEncrypted).toBeTruthy();
    const cipherHex = seeded!.itemNameEncrypted as string;

    // Even-length hex (matches the column / DTO contract).
    expect(cipherHex).toMatch(/^([0-9a-fA-F]{2})+$/);
    // Server never stored the plaintext name's bytes.
    expect(cipherHex.toLowerCase()).not.toBe(legacyItemNameHex.toLowerCase());
    // ECIES envelope (ephemeral pubkey + IV + tag + ct) is strictly larger than the
    // UTF-8 plaintext — a cheap sanity check that this is wrapped, not echoed.
    expect(cipherHex.length / 2).toBeGreaterThan(Buffer.byteLength(legacyItemName, 'utf8'));
    // The legacy plaintext itemName is retained during rollout (decision A2).
    expect(seeded?.itemName).toBe(legacyItemName);
  });

  test('6. Recipient still sees the correct name post-backfill, now from ciphertext', async () => {
    // Recipient row now carries the ciphertext (propagated at rest).
    const received = await fetchReceivedShare(bob.page, legacyIpnsName);
    expect(received?.itemNameEncrypted, 'recipient row now carries ciphertext').toBeTruthy();

    // Re-mount the shared view: fetchReceivedShares decrypts itemNameEncrypted with
    // Bob's vault key (apps/web/src/services/share.service.ts:124). Display name must
    // remain correct (decrypted; falls back to plaintext only on failure).
    await navigateToShared(bob);
    await bobShared.waitForLoaded({ timeout: 30_000 });
    await bobShared.waitForSharedItem(legacyItemName, { timeout: 20_000 });
    const names = await bobShared.getSharedItemNames();
    expect(names.some((n) => n.includes(legacyItemName))).toBe(true);
  });

  test('7. Backfill is idempotent — a second trigger leaves the ciphertext unchanged', async () => {
    const before = (await fetchSentShare(alice.page, legacyIpnsName))?.itemNameEncrypted;
    expect(before).toBeTruthy();

    await navigateToFiles(alice);
    const triggerFile = createTestTextFile(`trigger2-${runId}.txt`, 'second trigger');
    await aliceUploadZone.uploadFile(triggerFile.path);
    await aliceFileList.waitForItemToAppear(`trigger2-${runId}.txt`, { timeout: 30_000 });

    // shouldBackfill() skips rows that already carry ciphertext, so the value must
    // not churn. Give the (no-op) backfill pass a moment, then assert equality.
    await alice.page.waitForTimeout(3000);
    const after = (await fetchSentShare(alice.page, legacyIpnsName))?.itemNameEncrypted;
    expect(after).toBe(before);
  });
});
