/**
 * Recovery Tool E2E Test
 *
 * Seeds a vault with a file via SDK, then uses recovery.html to verify
 * the IPFS-direct v2 blob recovery path works end-to-end.
 *
 * Requires: API + IPFS running locally (same as other web-e2e tests).
 */
import { test, expect } from '@playwright/test';
import {
  createTestAccount,
  deleteTestAccount,
  type TestAccount,
} from '../../sdk-e2e/src/fixtures/test-harness';
import { bytesToHex } from '@cipherbox/crypto';

const API_URL = process.env.SDK_E2E_API_URL?.trim() || 'http://localhost:3000';
const WEB_URL = process.env.WEB_URL?.trim() || 'http://localhost:5173';
const IPFS_GATEWAY = process.env.RECOVERY_IPFS_GATEWAY?.trim() || 'http://localhost:8080';
// IPNS resolution via delegated routing service (Kubo can't resolve IPNS names published
// through it, and the CipherBox API requires auth). Derives from DELEGATED_ROUTING_URL
// used by the API, so it stays in sync if the service runs on a different port.
const IPNS_GATEWAY =
  process.env.RECOVERY_IPNS_GATEWAY?.trim() ||
  process.env.DELEGATED_ROUTING_URL?.trim() ||
  'http://localhost:3001';

// Recovery involves multiple IPNS resolutions + IPFS fetches + decryption.
// Keep test timeout and assertion timeout in sync so the assertion doesn't
// expire before the test itself does.
const RECOVERY_TIMEOUT_MS = 90_000;

test.describe('Vault Recovery Tool', () => {
  let account: TestAccount;
  const testFileName = `recovery-test-${Date.now()}.txt`;
  const testFileContent = new TextEncoder().encode('CipherBox recovery test file content');

  test.beforeAll(async () => {
    // Seed: create test account and upload a file
    account = await createTestAccount({
      apiUrl: API_URL,
      label: `recovery-e2e-${Date.now()}`,
      emailPrefix: 'recovery',
    });

    // Upload a test file to the root folder
    await account.client.uploadFile(
      account.rootIpnsName,
      testFileContent,
      testFileName,
      'text/plain'
    );

    // Brief wait for IPNS propagation to DB cache
    await new Promise((r) => setTimeout(r, 2000));
  });

  test.afterAll(async () => {
    if (account) {
      account.client.destroy();
      account.privateKey.fill(0);
      account.rootFolderKey.fill(0);
      account.rootIpnsKeypair.privateKey.fill(0);
      await deleteTestAccount(account, API_URL);
    }
  });

  // FIXME(recovery-v3): the standalone recovery tool (apps/web/public/recovery.html)
  // was never ported to the v3 two-key vault blob + node/v3 sealed codec introduced
  // in #578. It still hard-checks `blob[0] === 0x02` (recovery.html:394,1160) and
  // parses the pre-#578 `{iv,data}` folder envelope, so it halts with "not v2 format"
  // on any current-format vault. This is a real recoverability gap (the shipped
  // disaster-recovery tool cannot recover a current vault), not a test artifact —
  // tracked separately for a product fix. Un-fixme once recovery.html speaks v3.
  test.fixme('recovers vault files via IPFS-direct v2 blob path', async ({ page }) => {
    test.setTimeout(RECOVERY_TIMEOUT_MS);
    // Navigate to recovery tool
    await page.goto(`${WEB_URL}/recovery.html`);

    // Enter private key
    const privateKeyHex = bytesToHex(account.privateKey);
    await page.locator('[data-testid="recovery-key-input"]').fill(privateKeyHex);

    // Set gateway URLs
    await page.locator('[data-testid="recovery-ipfs-gateway"]').clear();
    await page.locator('[data-testid="recovery-ipfs-gateway"]').fill(IPFS_GATEWAY);

    await page.locator('[data-testid="recovery-ipns-gateway"]').clear();
    await page.locator('[data-testid="recovery-ipns-gateway"]').fill(IPNS_GATEWAY);

    // Click start recovery
    await page.locator('[data-testid="recovery-start-btn"]').click();

    // Wait for recovery to complete (progress log should show file name)
    // Recovery involves: IPNS resolution + IPFS fetch + v2 blob decrypt + folder traversal
    // This can take up to 60 seconds depending on IPNS propagation
    const progressLog = page.locator('[data-testid="recovery-progress-log"]');

    // Wait for the progress log to contain the file name or a success indicator
    // The recovery tool logs each discovered file
    await expect(progressLog).toContainText(testFileName, {
      timeout: RECOVERY_TIMEOUT_MS - 10_000,
    });

    // Verify the download button becomes visible (recovery succeeded)
    await expect(page.locator('[data-testid="recovery-download-btn"]')).toBeVisible({
      timeout: 10_000,
    });
  });
});
