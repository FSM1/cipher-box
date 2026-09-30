/**
 * The remote-stack mode: one desktop soak leg against a deployed stack. It
 * starts no API and no Kubo. The `e2e-hook` host carries the endpoints its build
 * read, and signs in as the soak grantee on standard input (ADR 0053 D3).
 *
 * The leg reads the other legs' markers through the mount, writes the marker
 * of today and its ledger line, and proves the publish from a second instance
 * on an empty home. Each step runs against its own budget and names its own
 * reason code, in the web soak's record shape.
 */

import { appendFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  formatLedger,
  parseLedger,
  utcDay,
  type Ledger,
} from '../../../web-e2e/staging/soak/ledger';
import { markerBytes } from '../../../web-e2e/staging/soak/markers';
import { SoakFailure, type FailureReason } from '../../../web-e2e/staging/soak/reasons';
import { renderSummary } from '../../../web-e2e/staging/soak/summary';
import {
  MARKER_LEGS,
  ledgerLine,
  granteeLedgerPath,
  legMarkers,
  markerPath,
  markersToRead,
  readLine,
  recordMarker,
  type DesktopLeg,
  type LegMarker,
  type MarkerLeg,
} from '../../../web-e2e/staging/soak/grantee';
import { DESKTOP_FOLDER } from '../../../web-e2e/staging/soak/paths';
import { describe, withDeadline } from '../cli';
import { startInstance, type Instance } from '../instance';
import { PollTimeout, poll } from '../poll';
import { PRODUCTION_PROFILE, type Deadlines } from '../profile';
import { isMounted } from '../scenario';
import { requireFile, serves } from '../stack';
import {
  legDeadlines,
  legOf,
  loginSecret,
  readBudget,
  remoteStack,
  soakBudgets,
  withoutSoakVars,
  type SoakBudgets,
} from './plan';
import { Recorder } from './recorder';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

/**
 * What a step bound adds past the waits inside it, so a wait that ran out
 * reports its own last value, and releases a stalled read, before the bound
 * takes every mount away.
 */
const STEP_GRACE_MS = 60_000;

const USAGE = `Usage: tsx src/soak/runSoak.ts [--help]

One desktop soak leg in the remote-stack mode. It starts no API and no Kubo.
It signs an "e2e-hook" build of cipherbox-desktop in as the soak grantee,
reads the other legs' markers through the mount, writes the marker of today,
and proves the publish from a second instance on an empty home.

Environment:
  CIPHERBOX_DESKTOP_BINARY    The e2e-hook build. Required.
  VITE_API_URL                The API the build was made against. Required.
  VITE_ROUTING_ENDPOINTS      The routing endpoints of that build. Required.
  SOAK_GRANTEE_LOGIN_SECRET   The grantee login secret. Required. The leg
                              hands it to the host on standard input only.
  SOAK_RESULTS_FILE           Where the result lines go.
                              Default: soak-results.jsonl in the workdir.
  CIPHERBOX_E2E_WORKDIR       Home roots and logs, kept after a pass.
                              Default: a temporary directory the leg removes.
  GITHUB_STEP_SUMMARY         When set, the summary is appended there.
                              Otherwise it goes to standard output.
`;

interface LegContext {
  leg: DesktopLeg;
  binary: string;
  workdir: string;
  recorder: Recorder;
  budgets: SoakBudgets;
  deadlines: Deadlines;
  /** Every instance this leg started, so any bound can take the mounts away. */
  started: Instance[];
  /** The starts in flight. A bound waits for them, so no child outlives the leg. */
  opening: Set<Promise<unknown>>;
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }

  const workdir =
    process.env.CIPHERBOX_E2E_WORKDIR ?? (await mkdtemp(join(tmpdir(), 'cipherbox-desktop-soak-')));
  await mkdir(workdir, { recursive: true });
  const resultsFile = process.env.SOAK_RESULTS_FILE ?? join(workdir, 'soak-results.jsonl');
  await mkdir(dirname(resultsFile), { recursive: true });
  const recorder = new Recorder((line) => appendFile(resultsFile, `${line}\n`));

  let leg: DesktopLeg | undefined;
  let binary: string;
  try {
    if (argv.length > 0)
      throw new Error(`unknown argument ${argv[0]}. Run --help for the options.`);
    leg = legOf(process.platform);
    const named = process.env.CIPHERBOX_DESKTOP_BINARY;
    if (!named)
      throw new Error('CIPHERBOX_DESKTOP_BINARY is unset. Point it at an e2e-hook build.');
    binary = resolve(REPO_ROOT, named);
    await requireFile(binary, `CIPHERBOX_DESKTOP_BINARY names ${binary}, and no file is there.`);
  } catch (error) {
    await recorder.unrecorded(`${leg ?? process.platform} desktop leg`, error);
    await writeSummary(recorder);
    throw error;
  }

  const budgets = soakBudgets(PRODUCTION_PROFILE);
  const context: LegContext = {
    leg,
    binary,
    workdir,
    recorder,
    budgets,
    deadlines: legDeadlines(budgets, PRODUCTION_PROFILE),
    started: [],
    opening: new Set(),
  };

  const test = `${leg} desktop leg`;
  await recorder.phase(test, 'started');
  try {
    await runLeg(context);
  } catch (error) {
    if (!recorder.recorded(error)) await recorder.unrecorded(test, error);
    process.stdout.write(`  ${describe(error)}\n  the instance logs are under ${workdir}\n`);
  } finally {
    for (const instance of [...context.started].reverse()) await instance.stop();
  }
  await recorder.phase(test, 'ended');
  await writeSummary(recorder);

  if (recorder.failures > 0) return 1;
  if (!process.env.CIPHERBOX_E2E_WORKDIR) await rm(workdir, { recursive: true, force: true });
  return 0;
}

async function writeSummary(recorder: Recorder): Promise<void> {
  const summary = renderSummary(recorder.records);
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) await appendFile(summaryFile, summary);
  else process.stdout.write(`\n${summary}`);
}

async function runLeg(context: LegContext): Promise<void> {
  const { leg, recorder, budgets } = context;

  const writer = await step(context, 'sign-in', 'sign-in-failed', budgets.signInMs, async () => {
    const stack = remoteStack(process.env);
    const devKey = loginSecret(process.env);
    // The host inherits this environment. The secret reaches it on standard
    // input alone, so no soak secret stays behind for the child to read.
    const kept = withoutSoakVars(process.env);
    for (const name of Object.keys(process.env)) {
      if (!(name in kept)) delete process.env[name];
    }
    await poll(
      () => serves(stack.apiUrl),
      (up) => up,
      {
        what: 'the API to serve a login',
        timeoutMs: context.deadlines.apiReadyMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
    const instance = await open(context, 'writer', devKey);
    await instance.refresh();
    return { instance, devKey };
  });

  const ledger = await step(context, 'ledger', 'ledger-unreadable', budgets.ledgerMs, () =>
    readGranteeLedger(context, writer.instance)
  );

  const read = await markerReads(context, writer.instance, ledger).catch((error: unknown) => {
    if (!recorder.recorded(error)) throw error;
    return null;
  });
  if (read !== null) await recorder.fact(`${leg} markers read`, readLine(read));

  // A missing marker fails the night, and the leg still writes its own, so
  // the next night has one to read. A stalled read or a step bound takes the
  // writer away, so a new writer writes it then.
  const markerWriter = writer.instance.abandoned
    ? await step(context, 'writer reopen', 'sign-in-failed', budgets.signInMs, async () => {
        const instance = await open(context, 'writer-reopened', writer.devKey);
        await instance.refresh();
        return instance;
      })
    : writer.instance;

  const today: LegMarker = { leg, date: utcDay(new Date()) };
  await step(context, 'marker write', 'desktop-marker-unpublished', budgets.writeMs, async () => {
    await requireLiveMount(markerWriter);
    await writeMarker(markerWriter, today);
  });

  const reader = await step(
    context,
    'cold sign-in',
    'sign-in-failed',
    budgets.signInMs,
    async () => {
      const instance = await open(context, 'reader', writer.devKey);
      await instance.refresh();
      return instance;
    }
  );

  await step(
    context,
    'marker published',
    'desktop-marker-unpublished',
    budgets.publishMs,
    async () => {
      await servesMarker(context, reader, today);
      const settled = await markerWriter.status();
      if (settled.deadLetters > 0) {
        throw new SoakFailure(
          'desktop-marker-unpublished',
          `the writer dead-lettered ${settled.deadLetters} ops`
        );
      }
    }
  );
}

/** One recorded step, bounded by its budget; the bound releases as `withDeadline` does. */
function step<T>(
  context: LegContext,
  name: string,
  reason: FailureReason,
  budgetMs: number,
  body: () => Promise<T>
): Promise<T> {
  const check = `${context.leg} ${name}`;
  const started = Date.now();
  return context.recorder
    .check(check, reason, () =>
      withDeadline(body(), budgetMs + STEP_GRACE_MS, `the ${check} step`, () => release(context))
    )
    .then(
      (value) => {
        process.stdout.write(`- ${check}: passed in ${Date.now() - started}ms\n`);
        return value;
      },
      (error: unknown) => {
        process.stdout.write(`- ${check}: FAILED after ${Date.now() - started}ms\n`);
        throw error;
      }
    );
}

/** Lets each start in flight end on its own deadline, then takes every mount away. */
async function release(context: LegContext): Promise<void> {
  await Promise.allSettled([...context.opening]);
  await Promise.allSettled(context.started.map((instance) => instance.abandon()));
}

/**
 * Fails unless the mount is a live filesystem and its shell still answers. A
 * mount that a bound or a stalled read took away leaves a plain local folder,
 * and a write there proves nothing.
 */
async function requireLiveMount(instance: Instance): Promise<void> {
  if (!(await isMounted(instance.mountRoot))) {
    throw new SoakFailure(
      'desktop-marker-unpublished',
      `${instance.name} has no mount to write to`
    );
  }
  await instance.status();
}

/** Starts an instance on an empty home, so it holds nothing an earlier run cached. */
async function open(context: LegContext, name: string, devKey: string): Promise<Instance> {
  const home = join(context.workdir, name);
  await rm(home, { recursive: true, force: true });
  const starting = startInstance({
    name: `${context.leg}-${name}`,
    home,
    devKey,
    binary: context.binary,
    logDir: join(context.workdir, 'logs'),
    deadlines: context.deadlines,
  });
  context.opening.add(starting);
  let instance: Instance;
  try {
    instance = await starting;
  } finally {
    context.opening.delete(starting);
  }
  context.started.push(instance);
  await poll(
    () => isMounted(instance.mountRoot),
    (mounted) => mounted,
    {
      what: `${instance.name}: the mount root to carry a filesystem of its own`,
      timeoutMs: context.deadlines.mountMs,
      intervalMs: context.deadlines.intervalMs,
      release: () => instance.abandon(),
    }
  );
  return instance;
}

async function readGranteeLedger(context: LegContext, instance: Instance): Promise<Ledger> {
  const path = join(instance.mountRoot, ...granteeLedgerPath());
  try {
    return ledgerFrom(
      await poll(
        refreshingAfterFirst(instance, () => readOrErrno(path)),
        (seen): seen is Buffer => Buffer.isBuffer(seen),
        {
          what: `${instance.name}: the grantee ledger to open`,
          timeoutMs: context.budgets.ledgerMs,
          intervalMs: context.deadlines.readIntervalMs,
          release: () => instance.abandon(),
        }
      )
    );
  } catch (error) {
    if (error instanceof PollTimeout && typeof error.last === 'string') {
      return ledgerFrom(error.last as Errno);
    }
    throw error;
  }
}

/** The grantee ledger one read gave, with every leg marker line checked. */
function ledgerFrom(read: Buffer | Errno): Ledger {
  if (!Buffer.isBuffer(read)) {
    throw read === 'ENOENT'
      ? new SoakFailure(
          'unbootstrapped-or-wiped',
          `the grantee vault has no ${granteeLedgerPath().join('/')}`
        )
      : new SoakFailure('ledger-unreadable', `the grantee ledger did not open: ${read}`);
  }
  const ledger = parseLedger(read.toString('utf8'));
  legMarkers(ledger);
  return ledger;
}

/** Reads every marker of the other legs, byte for byte, and returns what it read. */
async function markerReads(
  context: LegContext,
  instance: Instance,
  ledger: Ledger
): Promise<LegMarker[]> {
  const { leg, budgets } = context;
  const listed = await step(
    context,
    'marker listing',
    'desktop-marker-missing',
    budgets.readBaseMs,
    () => listLegFolders(instance)
  );
  const toRead = markersToRead(ledger, listed, leg);
  const budget = readBudget(budgets, toRead.length);
  return step(context, 'markers', 'desktop-marker-missing', budget, async () => {
    const unread = new Map(toRead.map((marker) => [ledgerLine(marker), marker]));
    try {
      await poll(
        refreshingAfterFirst(instance, async () => {
          const seen: Record<string, MarkerState> = {};
          for (const [line, marker] of unread) {
            const state = await markerState(
              join(instance.mountRoot, ...markerPath(marker)),
              marker.date
            );
            if (state === 'served') unread.delete(line);
            else seen[line] = state;
          }
          return seen;
        }),
        () => unread.size === 0,
        {
          what: `${instance.name}: every marker of the other legs to open`,
          timeoutMs: budget,
          intervalMs: context.deadlines.readIntervalMs,
          release: () => instance.abandon(),
        }
      );
    } catch (error) {
      if (!(error instanceof PollTimeout)) throw error;
      const missing = [...unread.values()].map((marker) => `${marker.leg} ${marker.date}`);
      throw new SoakFailure(
        'desktop-marker-missing',
        `${missing.length} of ${toRead.length} markers did not open: ${missing.join(', ')}`
      );
    }
    return toRead;
  });
}

async function listLegFolders(instance: Instance): Promise<Partial<Record<MarkerLeg, string[]>>> {
  const listed: Partial<Record<MarkerLeg, string[]>> = {};
  for (const leg of MARKER_LEGS) {
    listed[leg] = await listOrEmpty(join(instance.mountRoot, ...DESKTOP_FOLDER, leg));
  }
  return listed;
}

/** The marker of today and its ledger line, each written once on a rerun of the day. */
async function writeMarker(instance: Instance, today: LegMarker): Promise<void> {
  await mkdir(join(instance.mountRoot, ...DESKTOP_FOLDER, today.leg), { recursive: true });
  const path = join(instance.mountRoot, ...markerPath(today));
  if ((await markerState(path, today.date)) !== 'served') {
    await writeFile(path, markerBytes(today.date));
  }

  // The ledger as it is now, not as the leg read it before the marker reads.
  const ledgerAt = join(instance.mountRoot, ...granteeLedgerPath());
  await instance.refresh();
  const ledger = ledgerFrom(await readOrErrno(ledgerAt));
  const next = recordMarker(ledger, today);
  if (next === ledger) return;
  try {
    await writeFile(ledgerAt, formatLedger(next));
  } catch (error) {
    throw new SoakFailure(
      'ledger-unreadable',
      `the grantee ledger did not save: ${(error as NodeJS.ErrnoException).code ?? String(error)}`
    );
  }
}

/** Waits until a mount that holds nothing of the writer's serves the marker and its line. */
async function servesMarker(
  context: LegContext,
  reader: Instance,
  today: LegMarker
): Promise<void> {
  const markerAt = join(reader.mountRoot, ...markerPath(today));
  const ledgerAt = join(reader.mountRoot, ...granteeLedgerPath());
  const line = ledgerLine(today);
  await poll(
    refreshingAfterFirst(reader, async () => {
      const marker = await markerState(markerAt, today.date);
      const ledger = await readOrErrno(ledgerAt);
      return {
        marker,
        line: Buffer.isBuffer(ledger)
          ? ledger.toString('utf8').split(/\r?\n/).includes(line)
            ? 'served'
            : 'absent'
          : ledger,
      };
    }),
    (seen) => seen.marker === 'served' && seen.line === 'served',
    {
      what: `${reader.name}: the marker of today and its ledger line to reach a cold mount`,
      timeoutMs: context.budgets.publishMs,
      intervalMs: context.deadlines.readIntervalMs,
      release: () => reader.abandon(),
    }
  );
}

/** The code a refused read carries, such as `ENOENT`. */
type Errno = `E${string}`;

type MarkerState = 'served' | 'other bytes' | Errno;

/** `served` when the marker holds the bytes of its date, else what the read saw. */
async function markerState(path: string, date: string): Promise<MarkerState> {
  const read = await readOrErrno(path);
  if (!Buffer.isBuffer(read)) return read;
  return read.equals(markerBytes(date)) ? 'served' : 'other bytes';
}

/** The file's bytes, or the errno the mount refused the read with. */
async function readOrErrno(path: string): Promise<Buffer | Errno> {
  try {
    return await readFile(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code?.startsWith('E') ? (code as Errno) : 'EUNKNOWN';
  }
}

/** `probe`, with a nocache refresh before every call after the first. */
function refreshingAfterFirst<T>(instance: Instance, probe: () => Promise<T>): () => Promise<T> {
  let calls = 0;
  return async () => {
    if (calls++ > 0) await instance.refresh();
    return probe();
  };
}

async function listOrEmpty(path: string): Promise<string[]> {
  try {
    return await readdir(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

// An explicit exit, because a killed shell can leave a handle open and Node
// would then wait on it rather than end the run.
main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
);
