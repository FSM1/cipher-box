import { expect, test, type BrowserContext, type Page } from '@playwright/test';

import type {
  DownloadResult,
  ObservedEvent,
  ObservedMessage,
  RangeResult,
  SnapshotResult,
} from './leadership.js';
import { presenceLockName } from '../../src/broadcast.js';
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
  cbForge(message: Record<string, unknown>): void;
  cbLockState(name: string): Promise<{ held: number; pending: number }>;
  cbEvents(): ObservedEvent[];
  cbReadStream(offset: number, length: number): Promise<RangeResult>;
  cbRole(): string;
  cbStart(): Promise<string>;
  cbCreateFile(name: string): Promise<string>;
  cbUpload(name: string, bytesHex: string): Promise<string>;
  cbCreateNode(name: string, kind: 'file' | 'folder'): Promise<string>;
  cbSnapshot(folderHex: string): Promise<SnapshotResult>;
  cbDownload(nodeHex: string): Promise<DownloadResult>;
  cbDispose(): Promise<void>;
  cbJournalCount(): Promise<number>;
  cbJournalRecords(): Promise<unknown[]>;
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
  forge(message: Record<string, unknown>): Promise<void>;
  lockState(name: string): Promise<{ held: number; pending: number }>;
  events(): Promise<ObservedEvent[]>;
  readStream(offset: number, length: number): Promise<RangeResult>;
  role(): Promise<string>;
  start(): Promise<string>;
  createFile(name: string): Promise<string>;
  upload(name: string, bytesHex: string): Promise<string>;
  createNode(name: string, kind: 'file' | 'folder'): Promise<string>;
  snapshot(folderHex: string): Promise<SnapshotResult>;
  download(nodeHex: string): Promise<DownloadResult>;
  dispose(): Promise<void>;
  journalCount(): Promise<number>;
  journalRecords(): Promise<unknown[]>;
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
    forge: (message) =>
      page.evaluate((m) => (window as unknown as LeadershipHarness).cbForge(m), message),
    lockState: (name) =>
      page.evaluate((n) => (window as unknown as LeadershipHarness).cbLockState(n), name),
    events: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbEvents()),
    readStream: (offset, length) =>
      page.evaluate(
        (args) => (window as unknown as LeadershipHarness).cbReadStream(args.offset, args.length),
        { offset, length }
      ),
    role: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbRole()),
    start: () => page.evaluate(() => (window as unknown as LeadershipHarness).cbStart()),
    createFile: (name) =>
      page.evaluate((n) => (window as unknown as LeadershipHarness).cbCreateFile(n), name),
    upload: (name, bytesHex) =>
      page.evaluate(
        (args) => (window as unknown as LeadershipHarness).cbUpload(args.name, args.bytesHex),
        { name, bytesHex }
      ),
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

/**
 * How many times a follower has asked where to open a port. It rises only when
 * one re-brokers, so an unchanged count is the proof a port still stands.
 */
async function dialCount(bystander: ReturnType<typeof harness>): Promise<number> {
  const observed = await bystander.observed();
  return observed.filter((message) => message.type === 'cb:portWanted').length;
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
    expect((await a.lockState(lockName)).held).toBe(1);

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

  test('a follower uploads while a second same-origin context sees no plaintext and no arguments', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));
    const eavesdropper = harness(await openTab(context));
    await eavesdropper.observe(channelName);
    await a.resetJournal();

    await a.create(lockName, channelName);
    await b.create(lockName, channelName);
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;
    await leader.start();
    await follower.start();

    // A distinctive filename and a distinctive byte run: both are arguments the
    // follower→leader direction used to broadcast to every same-origin context.
    const plaintext = Uint8Array.from({ length: 64 }, (_, i) => (i * 31 + 17) & 0xff);
    const filename = 'payslip-2026-Q3.pdf';
    expect(await follower.upload(filename, hex(plaintext))).toBe('ok');
    expect(await follower.createNode('rothko-appraisal', 'folder')).toBe('ok');

    // The commit emitted an engine event carrying a node id and a block count;
    // the follower received it over its private port.
    let progress: ObservedEvent | undefined;
    await expect
      .poll(async () => {
        progress = (await follower.events()).find((event) => event.kind === 'opProgress');
        return progress !== undefined;
      })
      .toBe(true);
    expect(progress!.bytesHex.length).toBeGreaterThan(0);

    const observed = await eavesdropper.observed();
    expect(observed.length).toBeGreaterThan(0);
    // The channel carries election and the port rendezvous — no write step, no
    // command and no event, so no argument and no descriptor can ride one.
    for (const type of new Set(observed.map((message) => message.type))) {
      expect(['cb:hello', 'cb:leader', 'cb:leaderGone', 'cb:portHost', 'cb:portWanted']).toContain(
        type
      );
    }
    const seenBytes = observed.map((message) => message.bytesHex).join('|');
    expect(seenBytes).not.toContain(hex(plaintext.slice(0, 16)));
    // Whatever bytes that descriptor carried, the bystander saw none of them —
    // so a field added to `EventDescriptor` later cannot leak here unnoticed.
    expect(seenBytes).not.toContain(progress!.bytesHex);
    const seenText = observed.map((message) => message.text).join(' ');
    expect(seenText).not.toContain(filename);
    expect(seenText).not.toContain('rothko-appraisal');
    // And the strings and counts it carried, so a string-valued descriptor field
    // added later cannot leak here either. A block count or a one-digit op id
    // would match a digit inside a clientId, so only distinctive values count.
    const needles = progress!.text.split(' ').filter((value) => value.length >= 4);
    expect(needles.length).toBeGreaterThan(0);
    for (const needle of needles) expect(seenText).not.toContain(needle);

    await a.dispose();
    await b.dispose();
  });

  test('a forged port rendezvous carrying the observed token moves no adopted follower', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));
    const bystander = harness(await openTab(context));
    await bystander.observe(channelName);
    await a.resetJournal();

    await a.create(lockName, channelName);
    await b.create(lockName, channelName);
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;
    await leader.start();
    await follower.start();
    expect(await follower.createFile('before-forgery.txt')).toBe('ok');

    // The token rides the channel in the clear, so a bystander holds it. It
    // authenticates nothing: the follower adopted a port it dialed itself, and
    // takes no rendezvous while that port stands.
    const token = (await bystander.observed())
      .map((message) => message.token)
      .filter(Boolean)
      .at(-1);
    expect(token).toBeDefined();
    const before = await dialCount(bystander);
    await bystander.forge({ type: 'cb:portHost', token, address: 'attacker-broker' });
    await bystander.forge({ type: 'cb:portHost', token, address: 'attacker-broker' });

    // Still the real leader's engine, over the port it already held.
    expect(await follower.createFile('after-forgery.txt')).toBe('ok');
    expect(await leader.journalCount()).toBe(2);
    expect(await dialCount(bystander)).toBe(before);

    await a.dispose();
    await b.dispose();
  });

  test('no channel message strands a live follower, and a real departure still reclaims', async ({
    context,
  }) => {
    const { lockName, channelName } = names();
    const a = harness(await openTab(context));
    const b = harness(await openTab(context));
    const bystander = harness(await openTab(context));
    await bystander.observe(channelName);
    await a.resetJournal();

    await a.create(lockName, channelName);
    await b.create(lockName, channelName);
    const leader = (await a.role()) === 'leader' ? a : b;
    const follower = leader === a ? b : a;
    await leader.start();
    await follower.start();
    expect(await follower.createFile('before-farewell.txt')).toBe('ok');

    const clientId = (await bystander.observed())
      .filter((message) => message.type === 'cb:portWanted')
      .map((message) => message.clientId)
      .filter(Boolean)
      .at(-1);
    expect(clientId).toBeDefined();
    const presence = presenceLockName(clientId!);
    // The follower holds its presence name, and the leader's watch waits on it.
    await expect
      .poll(() => bystander.lockState(presence), { timeout: 10_000 })
      .toEqual({ held: 1, pending: 1 });

    const before = await dialCount(bystander);
    // Nothing on the channel reports a departure, so neither the retired
    // farewell shape nor anything else costs the follower its port or its
    // handles: it never re-dials, and its writes keep landing.
    await bystander.forge({ type: 'cb:bye', clientId });
    expect(await follower.createFile('after-farewell.txt')).toBe('ok');
    expect(await leader.journalCount()).toBe(2);
    expect(await dialCount(bystander)).toBe(before);

    // The tab genuinely departs: the browser releases the name, the leader's
    // watch is granted, and the reclaim retires it.
    await follower.dispose();
    await expect
      .poll(() => bystander.lockState(presence), { timeout: 10_000 })
      .toEqual({ held: 0, pending: 0 });

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
