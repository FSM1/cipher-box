import { expect, test, type BrowserContext, type Page } from '@playwright/test';

/**
 * The tab-leadership slice of the merge-blocking browser suite
 * (blueprint/testing.md law 1, blueprint/web-client.md "Engine hosting and tab
 * leadership"). Two real tabs in one browser context share the origin's real
 * `navigator.locks` and `BroadcastChannel`. It asserts the D4 invariant — one
 * engine writer per origin — leader election, kill-the-leader failover with no
 * accepted-op loss, and that both facade transports (leader-local and
 * follower-broadcast) reach the single engine worker.
 */

interface LeadershipHarness {
  cbCreate(options: { lockName: string; channelName: string }): Promise<void>;
  cbRole(): string;
  cbStart(): Promise<string>;
  cbCreateFile(name: string): Promise<string>;
  cbDispose(): Promise<void>;
  cbJournalCount(): Promise<number>;
  cbHeldLocks(lockName: string): Promise<number>;
  cbResetJournal(): Promise<void>;
}

let testSeq = 0;

async function openTab(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  page.on('pageerror', (error) => console.log(`[browser:pageerror] ${error.message}`));
  await page.goto('/');
  await page.waitForFunction(
    () => typeof (window as unknown as { cbCreate?: unknown }).cbCreate === 'function'
  );
  return page;
}

function harness(page: Page): {
  create(lockName: string, channelName: string): Promise<void>;
  role(): Promise<string>;
  start(): Promise<string>;
  createFile(name: string): Promise<string>;
  dispose(): Promise<void>;
  journalCount(): Promise<number>;
  heldLocks(lockName: string): Promise<number>;
  resetJournal(): Promise<void>;
  waitForRole(role: string): Promise<void>;
} {
  return {
    create: (lockName, channelName) =>
      page.evaluate((opts) => (window as unknown as LeadershipHarness).cbCreate(opts), {
        lockName,
        channelName,
      }),
    role: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbRole()),
    start: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbStart()),
    createFile: (name) =>
      page.evaluate((n) => (window as unknown as LeadershipHarness).cbCreateFile(n), name),
    dispose: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbDispose()),
    journalCount: () =>
      page.evaluate(() => (window as unknown as LeadershipHarness).cbJournalCount()),
    heldLocks: (lockName) =>
      page.evaluate((n) => (window as unknown as LeadershipHarness).cbHeldLocks(n), lockName),
    resetJournal: () =>
      page.evaluate(() => (window as unknown as LeadershipHarness).cbResetJournal()),
    waitForRole: (role) =>
      page.waitForFunction(
        (want) => (window as unknown as LeadershipHarness).cbRole() === want,
        role,
        { timeout: 10_000 }
      ) as unknown as Promise<void>,
  };
}

function names(): { lockName: string; channelName: string } {
  testSeq += 1;
  return { lockName: `cb-lock-${testSeq}`, channelName: `cb-chan-${testSeq}` };
}

test.describe('tab leadership over real Web Locks + BroadcastChannel', () => {
  test('elects exactly one leader; the other tab is a follower (single writer per origin)', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));

    await a.create(lockName, channelName);
    await b.create(lockName, channelName);

    const roles = [await a.role(), await b.role()].sort();
    expect(roles).toEqual(['follower', 'leader']);
    // The single exclusive lock is held exactly once — one engine writer.
    expect(await a.heldLocks(lockName)).toBe(1);

    await a.dispose();
    await b.dispose();
  });

  test('a follower command reaches the single leader worker (both transports live)', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));
    await a.resetJournal();

    await a.create(lockName, channelName);
    await b.create(lockName, channelName);
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;

    await leader.start();
    expect(await follower.start()).toBe('ok');

    // Leader-local transport journals one op.
    expect(await leader.createFile('from-leader.txt')).toBe('ok');
    // Follower-broadcast transport routes to the same worker: a second op.
    expect(await follower.createFile('from-follower.txt')).toBe('ok');

    expect(await leader.journalCount()).toBe(2);

    await a.dispose();
    await b.dispose();
  });

  test('kill the leader: a follower is promoted and no accepted op is lost', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));
    await a.resetJournal();

    await a.create(lockName, channelName);
    await b.create(lockName, channelName);
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;

    await leader.start();
    await follower.start();

    // The follower issues a command; it is journaled durably before the ack.
    expect(await follower.createFile('accepted.txt')).toBe('ok');
    const acceptedCount = await follower.journalCount();
    expect(acceptedCount).toBeGreaterThanOrEqual(1);

    // Kill the leader — its Web Lock releases and the follower is elected.
    await leader.dispose();
    await follower.waitForRole('leader');

    // The accepted op survived the handoff in the origin-shared journal.
    expect(await follower.journalCount()).toBe(acceptedCount);

    // The new leader now writes through its own fresh worker.
    expect(await follower.createFile('after-failover.txt')).toBe('ok');
    expect(await follower.journalCount()).toBe(acceptedCount + 1);

    await follower.dispose();
  });
});
