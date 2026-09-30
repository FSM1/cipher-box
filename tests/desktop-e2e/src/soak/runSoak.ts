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
import { describe, withDeadline } from '../cli';
import { startInstance, type Instance } from '../instance';
import { PollTimeout, poll } from '../poll';
import { PRODUCTION_PROFILE, type Deadlines } from '../profile';
import { isMounted } from '../scenario';
import { requireFile, serves } from '../stack';
import {
  DESKTOP_FOLDER,
  MARKER_LEGS,
  ledgerLine,
  ledgerPath,
  legDeadlines,
  legMarkers,
  legOf,
  loginSecret,
  markerPath,
  markersToRead,
  readBudget,
  readLine,
  recordMarker,
  remoteStack,
  soakBudgets,
  type DesktopLeg,
  type LegMarker,
  type MarkerLeg,
  type SoakBudgets,
} from './plan';
import { Recorder } from './recorder';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

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
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (argv.length > 0) throw new Error(`unknown argument ${argv[0]}. Run --help for the options.`);

  const leg = legOf(process.platform);
  const named = process.env.CIPHERBOX_DESKTOP_BINARY;
  if (!named) throw new Error('CIPHERBOX_DESKTOP_BINARY is unset. Point it at an e2e-hook build.');
  const binary = resolve(REPO_ROOT, named);
  await requireFile(binary, `CIPHERBOX_DESKTOP_BINARY names ${binary}, and no file is there.`);

  const workdir =
    process.env.CIPHERBOX_E2E_WORKDIR ?? (await mkdtemp(join(tmpdir(), 'cipherbox-desktop-soak-')));
  await mkdir(workdir, { recursive: true });
  const resultsFile = process.env.SOAK_RESULTS_FILE ?? join(workdir, 'soak-results.jsonl');
  await mkdir(dirname(resultsFile), { recursive: true });
  const recorder = new Recorder((line) => appendFile(resultsFile, `${line}\n`));

  const budgets = soakBudgets(PRODUCTION_PROFILE);
  const context: LegContext = {
    leg,
    binary,
    workdir,
    recorder,
    budgets,
    deadlines: legDeadlines(budgets, PRODUCTION_PROFILE),
    started: [],
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

  const summary = renderSummary(recorder.records);
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) await appendFile(summaryFile, summary);
  else process.stdout.write(`\n${summary}`);

  if (recorder.failures > 0) return 1;
  if (!process.env.CIPHERBOX_E2E_WORKDIR) await rm(workdir, { recursive: true, force: true });
  return 0;
}

async function runLeg(context: LegContext): Promise<void> {
  const { leg, recorder, budgets } = context;

  const writer = await step(context, 'sign-in', 'sign-in-failed', async () => {
    const stack = remoteStack(process.env);
    const devKey = loginSecret(process.env);
    // The host inherits this environment. The secret reaches it on standard
    // input alone, so no soak secret stays behind for the child to read.
    for (const name of Object.keys(process.env)) {
      if (name.startsWith('SOAK_')) delete process.env[name];
    }
    await poll(
      () => serves(stack.apiUrl),
      (up) => up,
      {
        what: 'the API to serve a login',
        timeoutMs: budgets.signInMs,
        intervalMs: context.deadlines.intervalMs,
      }
    );
    const instance = await open(context, 'writer', devKey);
    await instance.refresh();
    return { instance, devKey };
  });

  const ledger = await step(context, 'ledger', 'ledger-unreadable', () =>
    readGranteeLedger(context, writer.instance)
  );

  // A missing marker fails the night, and the leg still writes its own, so
  // the next night has one to read.
  const read = await markerReads(context, writer.instance, ledger).catch((error: unknown) => {
    if (!recorder.recorded(error)) throw error;
    return null;
  });
  if (read !== null) await recorder.fact(`${leg} markers read`, readLine(read));

  const today: LegMarker = { leg, date: utcDay(new Date()) };
  await step(context, 'marker write', 'desktop-marker-unpublished', () =>
    bounded(
      context,
      writeMarker(writer.instance, ledger, today),
      budgets.writeMs,
      'the marker write'
    )
  );

  const reader = await step(context, 'cold sign-in', 'sign-in-failed', async () => {
    const instance = await open(context, 'reader', writer.devKey);
    await instance.refresh();
    return instance;
  });

  await step(context, 'marker published', 'desktop-marker-unpublished', async () => {
    await servesMarker(context, reader, today);
    const settled = await writer.instance.status();
    if (settled.deadLetters > 0) {
      throw new SoakFailure(
        'desktop-marker-unpublished',
        `the writer dead-lettered ${settled.deadLetters} ops`
      );
    }
  });
}

/**
 * One recorded step. Every wait inside it is a poll with its own deadline, and
 * a bare filesystem call goes through {@link bounded}.
 */
function step<T>(
  context: LegContext,
  name: string,
  reason: FailureReason,
  body: () => Promise<T>
): Promise<T> {
  const check = `${context.leg} ${name}`;
  const started = Date.now();
  return context.recorder.check(check, reason, body).then(
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

/**
 * Bounds filesystem calls on a mount. A kernel call on a mount carries no
 * timeout, so the bound takes every mount away before it reports.
 */
function bounded<T>(
  context: LegContext,
  work: Promise<T>,
  budgetMs: number,
  what: string
): Promise<T> {
  return withDeadline(work, budgetMs, what, () =>
    Promise.allSettled(context.started.map((instance) => instance.abandon()))
  );
}

async function open(context: LegContext, name: string, devKey: string): Promise<Instance> {
  const home = join(context.workdir, name);
  const instance = await startInstance({
    name: `${context.leg}-${name}`,
    home,
    devKey,
    binary: context.binary,
    logDir: join(context.workdir, 'logs'),
    deadlines: context.deadlines,
  });
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
  const path = join(instance.mountRoot, ...ledgerPath());
  let reads = 0;
  let text: Buffer;
  try {
    text = await poll(
      async () => {
        if (reads++ > 0) await instance.refresh();
        return readOrErrno(path);
      },
      (seen): seen is Buffer => Buffer.isBuffer(seen),
      {
        what: `${instance.name}: the grantee ledger to open`,
        timeoutMs: context.budgets.ledgerMs,
        intervalMs: context.deadlines.readIntervalMs,
        release: () => instance.abandon(),
      }
    );
  } catch (error) {
    if (error instanceof PollTimeout && error.last === 'ENOENT') {
      throw new SoakFailure(
        'unbootstrapped-or-wiped',
        `the grantee vault has no ${ledgerPath().join('/')}`
      );
    }
    throw error;
  }
  const ledger = parseLedger(text.toString('utf8'));
  legMarkers(ledger);
  return ledger;
}

/** Reads every marker of the other legs, byte for byte, and returns what it read. */
function markerReads(
  context: LegContext,
  instance: Instance,
  ledger: Ledger
): Promise<LegMarker[]> {
  const { leg, budgets } = context;
  return step(context, 'markers', 'desktop-marker-missing', async () => {
    const listed = await bounded(
      context,
      listLegFolders(instance),
      budgets.readBaseMs,
      'the listing of the leg folders'
    );
    const toRead = markersToRead(ledger, listed, leg);
    const budget = readBudget(budgets, toRead.length);
    const unread = new Map(toRead.map((marker) => [ledgerLine(marker), marker]));
    let rounds = 0;
    try {
      await poll(
        async () => {
          if (rounds++ > 0) await instance.refresh();
          const seen: Record<string, string> = {};
          for (const [line, marker] of unread) {
            const read = await readOrErrno(join(instance.mountRoot, ...markerPath(marker)));
            if (Buffer.isBuffer(read) && read.equals(markerBytes(marker.date))) unread.delete(line);
            else seen[line] = Buffer.isBuffer(read) ? 'other bytes' : read;
          }
          return seen;
        },
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
async function writeMarker(instance: Instance, ledger: Ledger, today: LegMarker): Promise<void> {
  await mkdir(join(instance.mountRoot, ...DESKTOP_FOLDER, today.leg), { recursive: true });
  const path = join(instance.mountRoot, ...markerPath(today));
  const bytes = markerBytes(today.date);
  const present = await readOrErrno(path);
  if (!Buffer.isBuffer(present) || !present.equals(bytes)) await writeFile(path, bytes);

  const next = recordMarker(ledger, today);
  if (next === ledger) return;
  try {
    await writeFile(join(instance.mountRoot, ...ledgerPath()), formatLedger(next));
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
  const ledgerAt = join(reader.mountRoot, ...ledgerPath());
  const line = ledgerLine(today);
  await poll(
    async () => {
      await reader.refresh();
      const marker = await readOrErrno(markerAt);
      const ledger = await readOrErrno(ledgerAt);
      return {
        marker: Buffer.isBuffer(marker)
          ? marker.equals(markerBytes(today.date))
            ? 'served'
            : 'other bytes'
          : marker,
        line: Buffer.isBuffer(ledger)
          ? ledger.toString('utf8').split(/\r?\n/).includes(line)
            ? 'served'
            : 'absent'
          : ledger,
      };
    },
    (seen) => seen.marker === 'served' && seen.line === 'served',
    {
      what: `${reader.name}: the marker of today and its ledger line to reach a cold mount`,
      timeoutMs: context.budgets.publishMs,
      intervalMs: context.deadlines.readIntervalMs,
      release: () => reader.abandon(),
    }
  );
}

/** The file's bytes, or the errno the mount refused the read with. */
async function readOrErrno(path: string): Promise<Buffer | string> {
  try {
    return await readFile(path);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code ?? String(error);
  }
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
