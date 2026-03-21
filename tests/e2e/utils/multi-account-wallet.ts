import { Browser, BrowserContext, Page } from '@playwright/test';
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { setupMockWallet, loginViaWallet } from './wallet-login-helpers';

/**
 * A fully authenticated test account using wallet-based login.
 * Each account has an isolated browser context, a random EVM identity,
 * and its public key extracted from the Zustand auth store after login.
 */
export interface WalletTestAccount {
  name: string;
  context: BrowserContext;
  page: Page;
  account: PrivateKeyAccount;
  /** 0x04-prefixed secp256k1 public key (for sharing — extracted from auth store) */
  publicKey: string;
  /** JWT access token (extracted from auth store — for direct API calls) */
  accessToken: string;
  /** Root IPNS name (extracted from vault store — for conflict detection API calls) */
  rootIpnsName: string;
}

/**
 * Extract auth state from Zustand stores in the browser.
 *
 * After wallet login, Core Kit manages the secp256k1 identity in-browser.
 * This function extracts the public key, access token, and vault metadata
 * needed by tests that make direct API calls (conflict detection, sharing).
 */
async function extractAuthState(
  page: Page
): Promise<{ publicKey: string; accessToken: string; rootIpnsName: string }> {
  return page.evaluate(() => {
    const stores = (window as unknown as Record<string, unknown>).__ZUSTAND_STORES as {
      auth: { getState: () => { accessToken: string; vaultKeypair?: { publicKey: Uint8Array } } };
      vault: { getState: () => { rootIpnsName: string } };
    };

    const authState = stores.auth.getState();
    const vaultState = stores.vault.getState();

    // Convert Uint8Array public key to 0x-prefixed hex
    const pubKeyBytes = authState.vaultKeypair?.publicKey;
    let publicKey = '';
    if (pubKeyBytes) {
      const hex = Array.from(pubKeyBytes)
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join('');
      publicKey = '0x' + hex;
    }

    return {
      publicKey,
      accessToken: authState.accessToken,
      rootIpnsName: vaultState.rootIpnsName,
    };
  });
}

/**
 * Create a test account with a random wallet identity and authenticated browser context.
 *
 * Uses @johanneskares/wallet-mock to inject an EIP-6963 mock provider,
 * then drives the real wallet -> SIWE -> Core Kit login flow through the UI.
 * Each account gets a unique random private key -> unique wallet address ->
 * unique backend userId -> fresh DKG identity on Sapphire Devnet.
 *
 * @param browser - Playwright browser instance
 * @param name - Human-readable name for this account (e.g., "alice")
 */
export async function createWalletTestAccount(
  browser: Browser,
  name: string
): Promise<WalletTestAccount> {
  const account = privateKeyToAccount(generatePrivateKey());
  const context = await browser.newContext();

  try {
    const page = await context.newPage();

    // Install mock wallet BEFORE navigating (EIP-6963 provider announcement)
    await setupMockWallet(page, account);

    // Drive the real wallet login flow through the UI
    const result = await loginViaWallet(page, { timeout: 90_000 });
    if (result.outcome !== 'success') {
      throw new Error(
        `Wallet login for "${name}" did not reach /files (outcome: ${result.outcome})`
      );
    }

    // Wait for file list or empty state to confirm vault is accessible
    await Promise.race([
      page.locator('.file-list[role="grid"]').waitFor({ state: 'visible', timeout: 30_000 }),
      page.locator('[data-testid="empty-state"]').waitFor({ state: 'visible', timeout: 30_000 }),
    ]);

    // Extract auth state from browser
    const authState = await extractAuthState(page);

    return {
      name,
      context,
      page,
      account,
      publicKey: authState.publicKey,
      accessToken: authState.accessToken,
      rootIpnsName: authState.rootIpnsName,
    };
  } catch (err) {
    await context.close().catch(() => undefined);
    throw err;
  }
}

/**
 * Create multiple wallet-based test accounts sequentially.
 * Sequential creation avoids overwhelming the Web3Auth Sapphire Devnet.
 */
export async function createWalletTestAccounts(
  browser: Browser,
  names: string[]
): Promise<WalletTestAccount[]> {
  const accounts: WalletTestAccount[] = [];
  try {
    for (const name of names) {
      accounts.push(await createWalletTestAccount(browser, name));
    }
    return accounts;
  } catch (err) {
    // Clean up already-created accounts before re-throwing
    await closeWalletTestAccounts(accounts).catch(() => undefined);
    throw err;
  }
}

/**
 * Close all wallet test account contexts.
 */
export async function closeWalletTestAccounts(accounts: WalletTestAccount[]): Promise<void> {
  for (const account of accounts) {
    await account.context.close();
  }
}

/**
 * Navigate a wallet test account's page to the shared files view.
 * Navigates away first to force a component remount and fresh data fetch.
 */
export async function navigateToShared(account: WalletTestAccount): Promise<void> {
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
 * Navigate a wallet test account's page to their own files.
 * Navigates away first to force a component remount and fresh data fetch.
 */
export async function navigateToFiles(account: WalletTestAccount): Promise<void> {
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
