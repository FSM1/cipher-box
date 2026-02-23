import { Browser, BrowserContext, Page } from '@playwright/test';
import { loginViaTestEndpoint, TestAuthState, getPublicKeyHex } from './web3auth-helpers';

/**
 * A fully authenticated test account with its own browser context.
 * Each account has an isolated session (cookies, localStorage, auth state).
 */
export interface TestAccount {
  name: string;
  email: string;
  context: BrowserContext;
  page: Page;
  authState: TestAuthState;
  /** 0x04-prefixed secp256k1 public key (for sharing) */
  publicKey: string;
}

/**
 * Create a test account with a unique email and authenticated browser context.
 *
 * Uses the test-login endpoint to bypass Web3Auth. Each account gets:
 * - A unique timestamped email for test isolation
 * - Its own BrowserContext (isolated cookies/storage)
 * - A deterministic secp256k1 keypair (derived from email)
 * - A fully initialized vault
 *
 * @param browser - Playwright browser instance
 * @param name - Human-readable name for this account (e.g., "alice")
 * @param runId - Unique identifier for this test run (timestamp)
 */
export async function createTestAccount(
  browser: Browser,
  name: string,
  runId: string
): Promise<TestAccount> {
  const email = `${name}-e2e-${runId}@test.local`;
  const context = await browser.newContext();
  const page = await context.newPage();

  const authState = await loginViaTestEndpoint(page, email);
  const publicKey = getPublicKeyHex(authState);

  return { name, email, context, page, authState, publicKey };
}

/**
 * Create multiple test accounts sequentially.
 * All accounts share the same runId for test isolation.
 */
export async function createTestAccounts(
  browser: Browser,
  names: string[],
  runId?: string
): Promise<TestAccount[]> {
  const id = runId ?? Date.now().toString();
  // Create accounts sequentially to avoid overwhelming the API
  const accounts: TestAccount[] = [];
  for (const name of names) {
    accounts.push(await createTestAccount(browser, name, id));
  }
  return accounts;
}

/**
 * Close all test account contexts.
 * Call this in afterAll to clean up browser contexts.
 */
export async function closeTestAccounts(accounts: TestAccount[]): Promise<void> {
  for (const account of accounts) {
    await account.context.close();
  }
}

/**
 * Navigate a test account's page to the shared files view.
 * Always navigates away first to force a component remount and fresh data fetch.
 */
export async function navigateToShared(account: TestAccount): Promise<void> {
  // Navigate away first to ensure the SharedFileBrowser remounts and re-fetches
  const currentUrl = account.page.url();
  if (currentUrl.includes('/shared')) {
    await account.page.evaluate(() => {
      window.location.hash = '#/files';
    });
    await account.page.waitForURL('**/files', { timeout: 30000 });
  }
  await account.page.evaluate(() => {
    window.location.hash = '#/shared';
  });
  await account.page.waitForURL('**/shared', { timeout: 30000 });
}

/**
 * Navigate a test account's page to their own files.
 * Always navigates away first to force a component remount and fresh data fetch.
 */
export async function navigateToFiles(account: TestAccount): Promise<void> {
  const currentUrl = account.page.url();
  if (currentUrl.includes('/files')) {
    await account.page.evaluate(() => {
      window.location.hash = '#/shared';
    });
    await account.page.waitForURL('**/shared', { timeout: 30000 });
  }
  await account.page.evaluate(() => {
    window.location.hash = '#/files';
  });
  await account.page.waitForURL('**/files', { timeout: 30000 });
}
