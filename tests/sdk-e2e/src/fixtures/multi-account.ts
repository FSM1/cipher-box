/**
 * Multi-Account Test Fixture
 *
 * Creates N test accounts for tests that require interaction between users
 * (sharing, invite links). Handles the setApiClientConfig singleton caveat
 * by switching the active account before each operation.
 */

import { setApiClientConfig } from '@cipherbox/api-client';
import { createTestContext, deleteTestAccount, type TestContext, API_URL } from './test-harness';

export interface MultiAccountFixture {
  /** All created test contexts, indexed by label */
  accounts: Map<string, TestContext>;
  /**
   * Switch the api-client singleton to the given account.
   * Must be called before any operation that uses the singleton
   * (e.g., sdk-core IPNS functions).
   */
  switchTo: (label: string) => void;
  /** Destroy all clients and delete all accounts */
  cleanupAll: () => Promise<void>;
}

/**
 * Create N test accounts with the given labels.
 *
 * @example
 * const fixture = await createMultiAccountFixture(['alice', 'bob']);
 * const alice = fixture.accounts.get('alice')!;
 * const bob = fixture.accounts.get('bob')!;
 */
export async function createMultiAccountFixture(labels: string[]): Promise<MultiAccountFixture> {
  const accounts = new Map<string, TestContext>();

  // Create accounts sequentially to avoid race conditions on vault init
  for (const label of labels) {
    const ctx = await createTestContext(label);
    accounts.set(label, ctx);
  }

  const switchTo = (label: string): void => {
    const ctx = accounts.get(label);
    if (!ctx) throw new Error(`No account with label "${label}"`);
    setApiClientConfig({
      baseUrl: API_URL,
      getAccessToken: async () => ctx.accessToken,
    });
  };

  const cleanupAll = async (): Promise<void> => {
    for (const [, ctx] of accounts) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
    accounts.clear();
  };

  return { accounts, switchTo, cleanupAll };
}
