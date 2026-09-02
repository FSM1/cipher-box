/**
 * The orchestrator: it owns the stack, runs the scenarios in order, and
 * reports what failed.
 *
 * Every scenario gets a fresh login secret and fresh home roots, so one secret
 * is one vault and no scenario inherits another's state.
 */

import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startInstance } from './instance';
import { deadlines } from './profile';
import type { Scenario, ScenarioContext } from './scenario';
import { Stack, requireFile } from './stack';
import { conflictOutcomes } from './scenarios/conflictOutcomes';
import { mountLifecycle } from './scenarios/mountLifecycle';
import { writeRoundTrip } from './scenarios/writeRoundTrip';

// The lifecycle first: every scenario after it stands on a mount that opens.
const SCENARIOS: Scenario[] = [mountLifecycle, writeRoundTrip, conflictOutcomes];

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

const USAGE = `Usage: tsx src/runAll.ts [options]

The desktop mounted e2e suite. It needs Postgres, Kubo and the record
store up, a built API, and an "e2e-hook" build of cipherbox-desktop. It starts and
stops the API itself, because a scenario needs a real outage.

Options:
  --scenario <name>   Run only this scenario. Repeat for several.
  --list              List the scenario names and exit.
  --help              Show this text and exit.

Environment:
  CIPHERBOX_DESKTOP_BINARY   The e2e-hook build. Required.
  CIPHERBOX_API_ENTRY        The built API entry point.
                             Default: apps/api/dist/main.js
  CIPHERBOX_API_URL          Where the API answers.
                             Default: http://localhost:3000
  CIPHERBOX_E2E_WORKDIR      Home roots and logs, kept after a pass.
                             Default: a temporary directory the suite removes.
`;

interface Options {
  help: boolean;
  list: boolean;
  only: string[];
}

export function parseArguments(argv: string[]): Options {
  const options: Options = { help: false, list: false, only: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const argument = argv[i];
    if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--list') options.list = true;
    else if (argument === '--scenario') {
      const value = argv[i + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('--scenario needs a scenario name. Run --list for the names.');
      }
      options.only.push(value);
      i += 1;
    } else {
      throw new Error(`unknown argument ${argument}. Run --help for the options.`);
    }
  }
  return options;
}

function select(options: Options): Scenario[] {
  if (options.only.length === 0) return SCENARIOS;
  return options.only.map((name) => {
    const found = SCENARIOS.find((scenario) => scenario.name === name);
    if (!found) {
      throw new Error(`no scenario is named ${name}. The names are: ${names().join(', ')}`);
    }
    return found;
  });
}

function names(): string[] {
  return SCENARIOS.map((scenario) => scenario.name);
}

async function main(): Promise<number> {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (options.list) {
    process.stdout.write(`${names().join('\n')}\n`);
    return 0;
  }

  const chosen = select(options);

  const named = process.env.CIPHERBOX_DESKTOP_BINARY;
  if (!named) {
    throw new Error(
      'CIPHERBOX_DESKTOP_BINARY is unset. Point it at an e2e-hook build, for example ' +
        'target/debug/cipherbox-desktop after ' +
        '"cargo build -p cipherbox-desktop --features e2e-hook".'
    );
  }
  // A relative path names the repository root, not this package: pnpm runs the
  // script from the package directory.
  const binary = resolve(REPO_ROOT, named);
  await requireFile(
    binary,
    `CIPHERBOX_DESKTOP_BINARY names ${binary}, and no file is there. Build the binary first.`
  );

  const apiEntry = process.env.CIPHERBOX_API_ENTRY ?? join(REPO_ROOT, 'apps/api/dist/main.js');
  const apiUrl = process.env.CIPHERBOX_API_URL ?? 'http://localhost:3000';
  const workdir =
    process.env.CIPHERBOX_E2E_WORKDIR ?? (await mkdtemp(join(tmpdir(), 'cipherbox-desktop-e2e-')));
  await mkdir(workdir, { recursive: true });

  const budget = deadlines();
  const stack = await Stack.start({
    apiEntry,
    apiUrl,
    logDir: join(workdir, 'logs'),
    deadlines: budget,
  });

  const failures: { name: string; error: unknown }[] = [];
  try {
    for (const scenario of chosen) {
      const home = join(workdir, scenario.name);
      const logDir = join(home, 'logs');
      const devKey = randomBytes(32).toString('hex');
      const context: ScenarioContext = {
        deadlines: budget,
        stack,
        start: (name) =>
          startInstance({
            name: `${scenario.name}-${name}`,
            home: join(home, name),
            devKey,
            binary,
            logDir,
            deadlines: budget,
          }),
        log: (message) => process.stdout.write(`  ${scenario.name}: ${message}\n`),
      };

      process.stdout.write(`- ${scenario.name}\n`);
      const started = Date.now();
      try {
        await scenario.run(context);
        process.stdout.write(`  passed in ${Date.now() - started}ms\n`);
      } catch (error) {
        failures.push({ name: scenario.name, error });
        process.stdout.write(`  FAILED after ${Date.now() - started}ms\n`);
        process.stdout.write(`  ${describe(error)}\n`);
        process.stdout.write(`  the instance logs are under ${logDir}\n`);
      }
      // A scenario may leave the API down. Restore it for the next one.
      await stack.startApi();
    }
  } finally {
    await stack.stopApi();
  }

  if (failures.length > 0) {
    process.stdout.write(
      `\n${failures.length} of ${chosen.length} scenarios failed: ` +
        `${failures.map((failure) => failure.name).join(', ')}\n` +
        `the artifacts are under ${workdir}\n`
    );
    return 1;
  }

  process.stdout.write(`\nall ${chosen.length} scenarios passed\n`);
  if (!process.env.CIPHERBOX_E2E_WORKDIR) {
    await rm(workdir, { recursive: true, force: true });
  }
  return 0;
}

function describe(error: unknown): string {
  return error instanceof Error ? (error.stack ?? error.message) : String(error);
}

// An explicit exit, because a killed shell can leave a handle open and Node
// would then wait on it rather than end the run.
main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    // A setup failure names a thing to fix. Its stack names only this file.
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
);
