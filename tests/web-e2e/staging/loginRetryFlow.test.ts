import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Locator, Page } from '@playwright/test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { signInWithWallet } from './fixtures';
import {
  DEVNET_BACKOFF_MS,
  RUN_RETRY_BUDGET_KEY,
  RUN_SIGN_IN_RETRY_BUDGET_MS,
  runRetryDeadline,
  SIGN_IN_RETRY_BUDGET_MS,
  type SignInRecord,
} from './loginRetry';

const harness = vi.hoisted(() => {
  const info = {
    project: { outputDir: '', metadata: {} as Record<string, unknown> },
    annotations: [] as Array<{ type: string; description: string }>,
    timeout: 300_000,
    setTimeout: vi.fn(),
  };
  return {
    info,
    enabled: vi.fn(),
    walletClick: vi.fn(),
    refusal: vi.fn(),
  };
});

vi.mock('@playwright/test', () => {
  const test = { extend: () => test, info: () => harness.info };
  return { test, expect: () => ({ toBeEnabled: harness.enabled }) };
});

vi.mock('../page-objects/login.page', () => ({
  LoginPage: class {
    walletButton = { click: harness.walletClick };
    refusal = harness.refusal;
  },
}));

const NODE_FAILURE = 'the request to node-1.dev-node.web3auth.io failed with status 500';
const POLY_FAILURE = 'master poly commits inconsistent with tssPubKey';
const BUSY =
  'undefined unable to assign key, All auth network nodes are currently busy, Please try again.';
const signedIn = {} as Locator;

function page() {
  const calls = {
    reload: vi.fn(),
    on: vi.fn(),
    off: vi.fn(),
    getByRole: () => ({ click: vi.fn() }),
    waitForTimeout: vi.fn(async (ms: number) => {
      await vi.advanceTimersByTimeAsync(ms);
    }),
  };
  return { calls, page: calls as unknown as Page };
}

function records(): SignInRecord[] {
  return harness.info.annotations.map(({ description }) => JSON.parse(description) as SignInRecord);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(1_000_000);
  vi.resetAllMocks();
  harness.info.project.outputDir = mkdtempSync(join(tmpdir(), 'login-flow-'));
  harness.info.project.metadata = {};
  harness.info.annotations = [];
  harness.info.timeout = 300_000;
  harness.info.setTimeout.mockImplementation((timeout: number) => {
    harness.info.timeout = timeout;
  });
});

afterEach(() => {
  rmSync(harness.info.project.outputDir, { recursive: true, force: true });
  vi.useRealTimers();
});

describe('the wallet login retry flow', () => {
  it('gives the login after an exhausted login its own retries on a new page', async () => {
    const first = page();
    harness.refusal.mockResolvedValue(POLY_FAILURE);
    await expect(signInWithWallet(first.page, signedIn)).rejects.toThrow('attempt 5');
    expect(first.calls.waitForTimeout.mock.calls.map(([ms]) => ms)).toEqual(DEVNET_BACKOFF_MS);

    const second = page();
    harness.refusal.mockResolvedValueOnce(NODE_FAILURE).mockResolvedValueOnce(null);
    await expect(signInWithWallet(second.page, signedIn)).resolves.toBe(0);
    expect(second.calls.waitForTimeout).toHaveBeenCalledExactlyOnceWith(15_000);
    expect(records().map(({ result }) => result)).toEqual(['attempts-exhausted', 'recovered']);
    expect(records()[1]?.faults).toEqual([{ fault: 'node-5xx', attempt: 1 }]);
  });

  it('retries the explicit busy-node response and preserves the successful attempt duration', async () => {
    const opened = page();
    harness.refusal.mockResolvedValueOnce(BUSY).mockImplementationOnce(async () => {
      await vi.advanceTimersByTimeAsync(2_000);
      return null;
    });
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(2_000);
    expect(opened.calls.reload).toHaveBeenCalledTimes(1);
    expect(records()).toEqual([
      { faults: [{ fault: 'node-busy', attempt: 1 }], result: 'recovered' },
    ]);
  });

  it('still tries a new login after the run window, but reports a refused retry as suppressed', async () => {
    runRetryDeadline(harness.info.project.outputDir, Date.now());
    await vi.advanceTimersByTimeAsync(RUN_SIGN_IN_RETRY_BUDGET_MS + 1);
    const opened = page();
    harness.refusal.mockResolvedValueOnce(null).mockResolvedValueOnce(NODE_FAILURE);
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(0);
    await expect(signInWithWallet(opened.page, signedIn)).rejects.toThrow('attempt 1 (run-budget)');
    expect(opened.calls.waitForTimeout).not.toHaveBeenCalled();
    expect(records().map(({ result }) => result)).toEqual(['signed-in', 'run-budget']);
  });

  it.each([
    { limit: 'sign-in-budget', elapsedBeforeLogin: 0, firstAttemptMs: 240_000, timeout: 225_000 },
    {
      limit: 'run-budget',
      elapsedBeforeLogin: RUN_SIGN_IN_RETRY_BUDGET_MS - 25_000,
      firstAttemptMs: 0,
      timeout: 10_000,
    },
  ])(
    'bounds an in-flight retry at the $limit deadline and reports it once',
    async ({ limit, elapsedBeforeLogin, firstAttemptMs, timeout }) => {
      runRetryDeadline(harness.info.project.outputDir, Date.now());
      await vi.advanceTimersByTimeAsync(elapsedBeforeLogin);
      const opened = page();
      harness.refusal
        .mockImplementationOnce(async () => {
          await vi.advanceTimersByTimeAsync(firstAttemptMs);
          return NODE_FAILURE;
        })
        .mockImplementationOnce(async (_signedIn: Locator, timeoutMs: number) => {
          expect(timeoutMs).toBe(timeout);
          await vi.advanceTimersByTimeAsync(timeoutMs);
          throw new Error('locator timed out');
        });
      await expect(signInWithWallet(opened.page, signedIn)).rejects.toThrow(`attempt 2: ${limit}`);
      expect(records().map(({ result }) => result)).toEqual([limit]);
      expect(opened.calls.waitForTimeout).toHaveBeenCalledExactlyOnceWith(15_000);
      expect(opened.calls.off).toHaveBeenCalledTimes(2);
    }
  );

  it('takes the run window from the project metadata', async () => {
    harness.info.project.metadata = { [RUN_RETRY_BUDGET_KEY]: DEVNET_BACKOFF_MS[0]! };
    const opened = page();
    harness.refusal.mockResolvedValueOnce(NODE_FAILURE);
    await expect(signInWithWallet(opened.page, signedIn)).rejects.toThrow('attempt 1 (run-budget)');
    expect(opened.calls.waitForTimeout).not.toHaveBeenCalled();
  });

  it('keeps a login that signs in after its deadline has passed', async () => {
    const opened = page();
    harness.refusal.mockImplementationOnce(async () => {
      await vi.advanceTimersByTimeAsync(SIGN_IN_RETRY_BUDGET_MS + 1);
      return null;
    });
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(
      SIGN_IN_RETRY_BUDGET_MS + 1
    );
    expect(records()).toEqual([{ faults: [], result: 'signed-in' }]);
  });

  it('does not retry an unrelated authentication refusal', async () => {
    const opened = page();
    harness.refusal.mockResolvedValue('the wallet signature was rejected');
    await expect(signInWithWallet(opened.page, signedIn)).rejects.toThrow('attempt 1 (refused)');
    expect(opened.calls.waitForTimeout).not.toHaveBeenCalled();
    expect(records()).toEqual([{ faults: [], result: 'refused' }]);
  });
});
