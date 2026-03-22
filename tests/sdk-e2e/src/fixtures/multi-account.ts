/**
 * Multi-Account Test Fixture
 *
 * Creates N test accounts for tests that require interaction between users
 * (sharing, invite links). Each CipherBoxClient owns its own axios instance,
 * so no singleton switching is needed.
 */

import { createTestContext, deleteTestAccount, type TestContext } from './test-harness';

export interface MultiAccountFixture {
  /** All created test contexts, indexed by label */
  accounts: Map<string, TestContext>;
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

  const cleanupAll = async (): Promise<void> => {
    for (const [, ctx] of accounts) {
      ctx.cleanup();
      await deleteTestAccount(ctx);
    }
    accounts.clear();
  };

  return { accounts, cleanupAll };
}
