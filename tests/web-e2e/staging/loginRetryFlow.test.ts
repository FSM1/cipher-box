import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Locator, Page } from '@playwright/test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RETURNED_TO_SIGN_IN } from '../page-objects/login.page';
import { signInWithWallet } from './fixtures';
import {
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
    banners: vi.fn(),
    replaced: vi.fn(),
    walletClick: vi.fn(),
    refusal: vi.fn(),
    resumed: vi.fn(),
  };
});

vi.mock('@playwright/test', () => {
  const test = { extend: () => test, info: () => harness.info };
  return { test, expect: () => ({ toBeEnabled: harness.enabled }) };
});

// The mocks answer a refusal text: `null` signs in, and RETURNED_TO_SIGN_IN is signed out.
// The three-way wait after a reload names the wallet button; the wait after a click does not.
vi.mock('../page-objects/login.page', async (importOriginal) => {
  const real = await importOriginal<typeof import('../page-objects/login.page')>();
  return {
    ...real,
    LoginPage: class {
      walletButton = { click: harness.walletClick };
      banners = harness.banners;
      replaced = harness.replaced;
      outcome = async (signedIn: Locator, timeout: number, signedOut?: Locator) => {
        const text: string | null = await (signedOut === undefined
          ? harness.refusal(signedIn, timeout)
          : harness.resumed(signedIn, timeout, signedOut));
        if (text === null) return { kind: 'signed-in' };
        if (text === real.RETURNED_TO_SIGN_IN) return { kind: 'signed-out' };
        return { kind: 'refused', text };
      };
    },
  };
});

const NODE_FAILURE = 'the request to node-1.dev-node.web3auth.io failed with status 500';
const POLY_FAILURE = 'master poly commits inconsistent with tssPubKey';
const BUSY =
  'undefined unable to assign key, All auth network nodes are currently busy, Please try again.';
const signedIn = {} as Locator;

function page() {
  const calls = {
    // `loadInPage` runs a reload as a page `evaluate` behind a `load` wait.
    evaluate: vi.fn(),
    waitForEvent: vi.fn(),
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
  vi.spyOn(Math, 'random').mockReturnValue(0);
  harness.resumed.mockResolvedValue(RETURNED_TO_SIGN_IN);
  harness.banners.mockResolvedValue([]);
  harness.replaced.mockResolvedValue([]);
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
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('the wallet login retry flow', () => {
  it('gives the login after an exhausted login its own retries on a new page', async () => {
    const first = page();
    harness.refusal.mockResolvedValue(POLY_FAILURE);
    const started = Date.now();
    await expect(signInWithWallet(first.page, signedIn)).rejects.toThrow('sign-in-budget');
    expect(Date.now() - started).toBeLessThan(SIGN_IN_RETRY_BUDGET_MS);
    expect(Date.now() - started).toBeGreaterThanOrEqual(SIGN_IN_RETRY_BUDGET_MS - 25_000);
    expect(harness.refusal.mock.calls.length).toBeGreaterThan(5);

    const second = page();
    harness.refusal.mockResolvedValueOnce(NODE_FAILURE).mockResolvedValueOnce(null);
    await expect(signInWithWallet(second.page, signedIn)).resolves.toBe(0);
    expect(second.calls.waitForTimeout).toHaveBeenCalledExactlyOnceWith(15_000);
    expect(records().map(({ result }) => result)).toEqual(['sign-in-budget', 'recovered']);
    expect(records()[1]?.faults).toEqual([{ fault: 'node-5xx', attempt: 1 }]);
  });

  it.each([0, 0.5, 0.9999])(
    'recovers on attempt fourteen on the same page with jitter %s',
    async (jitter) => {
      vi.mocked(Math.random).mockReturnValue(jitter);
      const opened = page();
      harness.refusal.mockImplementation(async () => {
        await vi.advanceTimersByTimeAsync(6_000);
        return harness.refusal.mock.calls.length < 14 ? POLY_FAILURE : null;
      });
      await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(6_000);
      expect(opened.calls.evaluate).toHaveBeenCalledTimes(13);
      expect(harness.refusal.mock.calls.every(([locator]) => locator === signedIn)).toBe(true);
      expect(records()).toEqual([
        {
          faults: Array.from({ length: 13 }, (_, i) => ({ fault: 'poly-commits', attempt: i + 1 })),
          result: 'recovered',
        },
      ]);
    }
  );

  it('retries the explicit busy-node response and preserves the successful attempt duration', async () => {
    const opened = page();
    harness.refusal.mockResolvedValueOnce(BUSY).mockImplementationOnce(async () => {
      await vi.advanceTimersByTimeAsync(2_000);
      return null;
    });
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(2_000);
    expect(opened.calls.evaluate).toHaveBeenCalledExactlyOnceWith(expect.any(Function), null);
    expect(opened.calls.waitForEvent).toHaveBeenCalledExactlyOnceWith('load', {
      timeout: expect.any(Number),
    });
    const [armed] = opened.calls.waitForEvent.mock.invocationCallOrder;
    const [acted] = opened.calls.evaluate.mock.invocationCallOrder;
    expect(armed).toBeLessThan(acted!);
    const [[inPage]] = opened.calls.evaluate.mock.calls as [[(href: string | null) => void]];
    const location = { reload: vi.fn(), assign: vi.fn() };
    vi.stubGlobal('window', { location });
    try {
      inPage(null);
      inPage('https://example.test/next');
      vi.runOnlyPendingTimers();
    } finally {
      vi.unstubAllGlobals();
    }
    expect(location.reload).toHaveBeenCalledOnce();
    expect(location.assign).toHaveBeenCalledExactlyOnceWith('https://example.test/next');
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
    harness.info.project.metadata = { [RUN_RETRY_BUDGET_KEY]: 15_000 };
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

  it('waits for the banner of an earlier refusal to clear before it reads the login', async () => {
    const opened = page();
    harness.banners.mockResolvedValueOnce([POLY_FAILURE]);
    harness.replaced.mockImplementationOnce(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
      return [];
    });
    harness.refusal.mockResolvedValueOnce(null);
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(3_000);
    expect(harness.replaced).toHaveBeenCalledExactlyOnceWith([POLY_FAILURE], 60_000);
    const [cleared] = harness.replaced.mock.invocationCallOrder;
    const [read] = harness.refusal.mock.invocationCallOrder;
    expect(cleared).toBeLessThan(read!);
  });

  it('records a recovery when the reload resumes the saved session', async () => {
    const opened = page();
    harness.refusal.mockResolvedValueOnce(NODE_FAILURE);
    harness.resumed.mockResolvedValueOnce(null);
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(0);
    expect(opened.calls.evaluate).toHaveBeenCalledTimes(1);
    expect(harness.walletClick).toHaveBeenCalledTimes(1);
    expect(harness.resumed).toHaveBeenCalledExactlyOnceWith(
      signedIn,
      180_000,
      expect.objectContaining({ click: harness.walletClick })
    );
    expect(records()).toEqual([
      { faults: [{ fault: 'node-5xx', attempt: 1 }], result: 'recovered' },
    ]);
  });

  it('takes a refusal of the resume after a reload as the refusal of that attempt', async () => {
    const opened = page();
    harness.refusal.mockResolvedValueOnce(NODE_FAILURE).mockResolvedValueOnce(null);
    harness.resumed.mockResolvedValueOnce(POLY_FAILURE);
    await expect(signInWithWallet(opened.page, signedIn)).resolves.toBe(0);
    expect(opened.calls.evaluate).toHaveBeenCalledTimes(2);
    expect(harness.walletClick).toHaveBeenCalledTimes(2);
    expect(harness.refusal).toHaveBeenCalledTimes(2);
    expect(records()).toEqual([
      {
        faults: [
          { fault: 'node-5xx', attempt: 1 },
          { fault: 'poly-commits', attempt: 2 },
        ],
        result: 'recovered',
      },
    ]);
  });

  it('takes a refused resume as the first attempt: the backoff, the reload and the record', async () => {
    const opened = page();
    harness.resumed.mockResolvedValueOnce(null);
    await expect(signInWithWallet(opened.page, signedIn, POLY_FAILURE)).resolves.toBe(0);
    expect(harness.walletClick).not.toHaveBeenCalled();
    expect(opened.calls.waitForTimeout).toHaveBeenCalledExactlyOnceWith(15_000);
    expect(opened.calls.evaluate).toHaveBeenCalledTimes(1);
    expect(records()).toEqual([
      { faults: [{ fault: 'poly-commits', attempt: 1 }], result: 'recovered' },
    ]);
  });

  it('bounds the resume wait after a reload at the sign-in deadline', async () => {
    const opened = page();
    harness.refusal.mockImplementationOnce(async () => {
      await vi.advanceTimersByTimeAsync(300_000);
      return NODE_FAILURE;
    });
    harness.resumed.mockImplementationOnce(async (_signedIn: Locator, timeoutMs: number) => {
      expect(timeoutMs).toBe(SIGN_IN_RETRY_BUDGET_MS - 315_000);
      await vi.advanceTimersByTimeAsync(timeoutMs);
      throw new Error('locator timed out');
    });
    await expect(signInWithWallet(opened.page, signedIn)).rejects.toThrow(
      'attempt 2: sign-in-budget'
    );
    expect(harness.resumed).toHaveBeenCalledTimes(1);
    expect(records().map(({ result }) => result)).toEqual(['sign-in-budget']);
  });

  it('reads a new banner next to a stale one as the refusal, and does not retry it', async () => {
    const opened = page();
    harness.banners.mockResolvedValueOnce([POLY_FAILURE]);
    harness.replaced.mockResolvedValueOnce(['the wallet connector refused the request']);
    await expect(signInWithWallet(opened.page, signedIn)).rejects.toThrow(
      'attempt 1 (refused); the refusal read: the wallet connector refused the request;'
    );
    expect(harness.refusal).not.toHaveBeenCalled();
    expect(opened.calls.waitForTimeout).not.toHaveBeenCalled();
    expect(records()).toEqual([{ faults: [], result: 'refused' }]);
  });
});
