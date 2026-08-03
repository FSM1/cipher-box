import { expect, test, type BrowserContext, type Page } from '@playwright/test';

import type { DownloadResult, ObservedMessage, RangeResult, SnapshotResult } from './leadership.js';
import { hex } from './hexUtil.js';
import { fixtureSlice, LEADER_SEED } from './mediaFixture.js';

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
  cbCreate(options: {
    lockName: string;
    channelName: string;
    worker?: 'journal' | 'engine' | 'media';
  }): Promise<void>;
  cbObserve(channelName: string): void;
  cbObserved(): ObservedMessage[];
  cbReadStream(offset: number, length: number): Promise<RangeResult>;
  cbRole(): string;
  cbStart(): Promise<string>;
  cbCreateFile(name: string): Promise<string>;
  cbCreateNode(name: string, kind: 'file' | 'folder'): Promise<string>;
  cbSnapshot(folderHex: string): Promise<SnapshotResult>;
  cbDownload(nodeHex: string): Promise<DownloadResult>;
  cbDispose(): Promise<void>;
  cbJournalCount(): Promise<number>;
  cbJournalRecords(): Promise<unknown[]>;
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
  create(
    lockName: string,
    channelName: string,
    worker?: 'journal' | 'engine' | 'media'
  ): Promise<void>;
  observe(channelName: string): Promise<void>;
  observed(): Promise<ObservedMessage[]>;
  readStream(offset: number, length: number): Promise<RangeResult>;
  role(): Promise<string>;
  start(): Promise<string>;
  createFile(name: string): Promise<string>;
  createNode(name: string, kind: 'file' | 'folder'): Promise<string>;
  snapshot(folderHex: string): Promise<SnapshotResult>;
  download(nodeHex: string): Promise<DownloadResult>;
  dispose(): Promise<void>;
  journalCount(): Promise<number>;
  journalRecords(): Promise<unknown[]>;
  heldLocks(lockName: string): Promise<number>;
  resetJournal(): Promise<void>;
  waitForRole(role: string): Promise<void>;
} {
  return {
    create: (lockName, channelName, worker) =>
      page.evaluate((opts) => (window as unknown as LeadershipHarness).cbCreate(opts), {
        lockName,
        channelName,
        worker,
      }),
    observe: (channelName) =>
      page.evaluate(
        (name) => (window as unknown as LeadershipHarness).cbObserve(name),
        channelName
      ),
    observed: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbObserved()),
    readStream: (offset, length) =>
      page.evaluate(
        (args) => (window as unknown as LeadershipHarness).cbReadStream(args.offset, args.length),
        { offset, length }
      ),
    role: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbRole()),
    start: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbStart()),
    createFile: (name) =>
      page.evaluate((n) => (window as unknown as LeadershipHarness).cbCreateFile(n), name),
    createNode: (name, kind) =>
      page.evaluate(
        (args) => (window as unknown as LeadershipHarness).cbCreateNode(args.name, args.kind),
        { name, kind }
      ),
    snapshot: (folderHex) =>
      page.evaluate((f) => (window as unknown as LeadershipHarness).cbSnapshot(f), folderHex),
    download: (nodeHex) =>
      page.evaluate((n) => (window as unknown as LeadershipHarness).cbDownload(n), nodeHex),
    dispose: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbDispose()),
    journalCount: () =>
      page.evaluate(() => (window as unknown as LeadershipHarness).cbJournalCount()),
    journalRecords: () =>
      page.evaluate(() => (window as unknown as LeadershipHarness).cbJournalRecords()),
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

    // No plaintext at rest: each upload streams its bytes through a write handle
    // and the durable journal records only {kind, at} for the committed op —
    // never the pushed content or any byte-array field.
    const records = await leader.journalRecords();
    expect(records.map((record) => (record as { kind: string }).kind)).toEqual([
      'commitWrite',
      'commitWrite',
    ]);
    for (const record of records) {
      const row = record as Record<string, unknown>;
      expect(Object.keys(row).sort()).toEqual(['at', 'kind']);
      expect('content' in row).toBe(false);
      expect(
        Object.values(row).some((v) => v instanceof Uint8Array || v instanceof ArrayBuffer)
      ).toBe(false);
    }

    await a.dispose();
    await b.dispose();
  });

  test('a follower reads snapshot and download through the real leader engine', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));

    await a.create(lockName, channelName, 'engine');
    await b.create(lockName, channelName, 'engine');
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;

    expect(await leader.start()).toBe('ok');
    expect(await follower.start()).toBe('ok');

    // Metadata-only creates via the leader's real engine.
    expect(await leader.createNode('docs', 'folder')).toBe('ok');
    expect(await leader.createNode('pending.txt', 'file')).toBe('ok');

    // The follower's snapshot rides the broadcast wire to the leader engine.
    const rootHex = '00'.repeat(16);
    const view = await follower.snapshot(rootHex);
    expect(view.error).toBeUndefined();
    expect(view.rootHex).toBe(rootHex);
    expect(view.folderHex).toBe(rootHex);
    const docs = view.children!.find((child) => child.name === 'docs');
    const file = view.children!.find((child) => child.name === 'pending.txt');
    expect(docs).toMatchObject({ kind: 'folder', pending: 'metadata' });
    expect(file).toMatchObject({
      kind: 'file',
      pending: 'metadata',
      sizeNull: true,
      mtimeNull: false,
    });

    // The nested snapshot's breadcrumb trail ends at the root.
    const nested = await follower.snapshot(docs!.idHex);
    expect(nested.error).toBeUndefined();
    expect(nested.ancestors!.at(-1)!.idHex).toBe(rootHex);

    // A pending-only file's download rejection propagates to the follower with
    // the engine's stable code intact across both wire hops.
    const download = await follower.download(file!.idHex);
    expect(download.bytes).toBeUndefined();
    expect(download.code).toBe('contentUnavailable');

    await a.dispose();
    await b.dispose();
  });

  test('a follower streams plaintext while a second same-origin context sees no payload', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));
    // A third tab that drives no engine and only listens on the origin channel —
    // exactly what every same-origin document used to be handed plaintext.
    const eavesdropper = harness(await openTab(context));
    await eavesdropper.observe(channelName);

    await a.create(lockName, channelName, 'media');
    await b.create(lockName, channelName, 'media');
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;
    expect(await leader.start()).toBe('ok');
    expect(await follower.start()).toBe('ok');

    // Three ranged windows, as a media element playing in the follower would.
    const WINDOW = 1024;
    for (let offset = 0; offset < 3 * WINDOW; offset += WINDOW) {
      const read = await follower.readStream(offset, WINDOW);
      expect(read.error).toBeUndefined();
      // Only the leader's worker holds `LEADER_SEED`, so these bytes prove the
      // read crossed to the leader engine and came back over the private port.
      expect(read.bytesHex).toBe(hex(fixtureSlice(offset, WINDOW, LEADER_SEED)));
    }

    const observed = await eavesdropper.observed();
    // The channel still carries election and the port rendezvous...
    expect([...new Set(observed.map((message) => message.type))].sort()).toEqual([
      'cb:bye',
      'cb:hello',
      'cb:leader',
      'cb:portHost',
      'cb:portWanted',
    ]);
    // ...and not one byte of the plaintext the follower streamed.
    const seen = observed.map((message) => message.bytesHex).join('');
    expect(seen).not.toContain(hex(fixtureSlice(0, 32, LEADER_SEED)));

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
