import { describe, expect, it, vi } from 'vitest';
import { createCoreKitSession } from './coreKit';

// The SDK reaches for the Web3Auth network on construction; the seam is what
// lets the persistence options it is handed be read back.
const built = vi.hoisted(() => ({ options: [] as Record<string, unknown>[] }));
vi.mock('@web3auth/mpc-core-kit', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@web3auth/mpc-core-kit')>()),
  Web3AuthMPCCoreKit: class {
    constructor(options: Record<string, unknown>) {
      built.options.push(options);
    }
  },
}));

const ENV = {
  VITE_WEB3AUTH_CLIENT_ID: 'client-id',
  VITE_WEB3AUTH_VERIFIER: 'verifier',
} satisfies Partial<ImportMetaEnv>;

describe('the Core Kit store', () => {
  it('persists origin-wide, so a tab that did not log in can still be promoted to leader', () => {
    createCoreKitSession(ENV);

    expect(built.options.at(-1)?.storage).toBe(window.localStorage);
  });

  it('caps how long a persisted session stays restorable, below the SDK default', () => {
    createCoreKitSession(ENV);

    const sessionTime = built.options.at(-1)?.sessionTime;
    expect(typeof sessionTime).toBe('number');
    expect(sessionTime as number).toBeLessThan(86_400);
    expect(sessionTime as number).toBeGreaterThan(0);
  });
});
