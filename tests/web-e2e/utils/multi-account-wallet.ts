import { Browser, BrowserContext, Page } from '@playwright/test';
import { generatePrivateKey, privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { setupMockWallet, loginViaWallet } from './wallet-login-helpers';
import { deleteAccountViaPage } from './cleanup-helpers';

/**
 * A fully authenticated test account using wallet-based login.
 * Each account has an isolated browser context, a random EVM identity,
 * and its public key extracted from the Settings page UI after login.
 */
export interface WalletTestAccount {
  name: string;
  context: BrowserContext;
  page: Page;
  account: PrivateKeyAccount;
  /** 0x04-prefixed secp256k1 public key (for sharing — extracted from Settings page) */
  publicKey: string;
}

/**
 * Extract the user's public key from the Settings page UI.
 *
 * Navigates to /settings, reads the key from the visible element,
 * then navigates back to /files. This avoids reading Zustand internals.
 */
async function extractPublicKeyFromUI(page: Page): Promise<string> {
  // Navigate to settings
  await page.evaluate(() => {
    window.location.hash = '#/settings';
  });
  await page.waitForURL('**/settings', { timeout: 15_000 });

  // Read public key from the Settings page
  const pubKeyElement = page.locator('.settings-pubkey-value');
  await pubKeyElement.waitFor({ state: 'visible', timeout: 10_000 });
  const publicKey = ((await pubKeyElement.textContent()) ?? '').trim();
  if (!publicKey || !publicKey.startsWith('0x')) {
    throw new Error(
      `Failed to extract public key from Settings page (got: "${publicKey.slice(0, 20)}")`
    );
  }

  // Navigate back to files
  await page.evaluate(() => {
    window.location.hash = '#/files';
  });
  await page.waitForURL('**/files', { timeout: 15_000 });

  return publicKey;
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

    // loginViaWallet already waits for file list / empty state on success.
    // Extract public key from the Settings page UI (no Zustand access needed)
    const publicKey = await extractPublicKeyFromUI(page);

    return {
      name,
      context,
      page,
      account,
      publicKey,
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
 * Delete accounts and close all wallet test account contexts.
 *
 * Calls deleteAccountViaPage for each account BEFORE closing the browser
 * context (the page must still be navigable to send API requests).
 * Each deletion is wrapped individually so one failure doesn't block others.
 */
export async function closeWalletTestAccounts(accounts: WalletTestAccount[]): Promise<void> {
  // Step 1: Delete accounts while pages are still open
  for (const account of accounts) {
    try {
      await deleteAccountViaPage(account.page);
    } catch (err) {
      console.warn(`[cleanup] Failed to delete account "${account.name}":`, err);
    }
  }

  // Step 2: Close browser contexts (individually guarded so one failure doesn't block others)
  for (const account of accounts) {
    try {
      await account.context.close();
    } catch (err) {
      console.warn(`[cleanup] Failed to close context "${account.name}":`, err);
    }
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
