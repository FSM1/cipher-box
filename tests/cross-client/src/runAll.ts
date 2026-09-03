/**
 * The cross-client orchestrator: one stack, one served web bundle, one browser,
 * and the scenarios that put two hosts on one vault.
 *
 * It owns the API process, because a scenario needs a real outage, and it owns
 * the preview server, because the bundle under test is a built artifact.
 */

import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, type Browser } from '@playwright/test';
import { describe, names, parseArguments, select, withDeadline } from '../../desktop-e2e/src/cli';
import { startInstance, type Instance } from '../../desktop-e2e/src/instance';
import { deadlines, type Deadlines } from '../../desktop-e2e/src/profile';
import { Stack, requireFile } from '../../desktop-e2e/src/stack';
import { Preview } from './preview';
import { USAGE, webPort } from './options';
import { isLoginSecret, type Scenario, type ScenarioContext } from './scenario';
import { leaderFailover } from './scenarios/leaderFailover';
import { mountWriteInPromotedScope } from './scenarios/mountWriteInPromotedScope';
import { nestedScopeUnderMount } from './scenarios/nestedScopeUnderMount';
import { offlineConvergence } from './scenarios/offlineConvergence';
import { shareGrantCut } from './scenarios/shareGrantCut';
import { WebHost } from './web';

const SCENARIOS: Scenario[] = [
  shareGrantCut,
  nestedScopeUnderMount,
  mountWriteInPromotedScope,
  offlineConvergence,
  leaderFailover,
];

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** Everything one scenario started, so a failure strands no mount and no tab. */
class Started {
  private readonly instances: Instance[] = [];
  private readonly hosts: WebHost[] = [];

  hold(started: Instance | WebHost): void {
    if (started instanceof WebHost) this.hosts.push(started);
    else this.instances.push(started);
  }

  /** Takes every mount away without waiting for a graceful stop. */
  abandon(): Promise<unknown> {
    return Promise.allSettled(this.instances.map((instance) => instance.abandon()));
  }

  /** Tabs first: a context that outlives its vault holds the mount's session. */
  async release(): Promise<string[]> {
    const tails = this.hosts.map((host) => `${host.name}: ${host.tail()}`);
    for (const host of this.hosts.reverse()) await host.close().catch(() => undefined);
    for (const instance of this.instances.reverse()) {
      await instance.stop().catch(() => undefined);
    }
    return tails;
  }
}

async function main(): Promise<number> {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (options.list) {
    process.stdout.write(`${names(SCENARIOS).join('\n')}\n`);
    return 0;
  }

  const chosen = select(SCENARIOS, options);

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

  const outDir = process.env.CIPHERBOX_WEB_DIST || 'dist';
  await requireFile(
    join(REPO_ROOT, 'apps/web', outDir, 'index.html'),
    `no built web bundle is at apps/web/${outDir}. Run ` +
      '"pnpm --filter @cipherbox/web run build:wasm" and then "build:bundle" with ' +
      'VITE_E2E_HOOK=true first.'
  );

  const apiEntry = process.env.CIPHERBOX_API_ENTRY ?? join(REPO_ROOT, 'apps/api/dist/main.js');
  const apiUrl = process.env.CIPHERBOX_API_URL ?? 'http://localhost:3000';
  const port = webPort(process.env.CIPHERBOX_WEB_PORT);
  const workdir =
    process.env.CIPHERBOX_E2E_WORKDIR ?? (await mkdtemp(join(tmpdir(), 'cipherbox-cross-client-')));
  await mkdir(workdir, { recursive: true });

  const budget = deadlines();
  const logDir = join(workdir, 'logs');
  const stack = await Stack.start({ apiEntry, apiUrl, logDir, deadlines: budget });
  let preview: Preview | null = null;
  let browser: Browser | null = null;
  const failures: { name: string; error: unknown }[] = [];

  try {
    preview = await Preview.start({ repoRoot: REPO_ROOT, outDir, port, logDir, deadlines: budget });
    browser = await chromium.launch({ channel: 'chromium' });

    for (const scenario of chosen) {
      const home = join(workdir, scenario.name);
      const scenarioLogs = join(home, 'logs');
      const started = new Started();
      const context = scenarioContext({
        scenario,
        budget,
        stack,
        started,
        binary,
        home,
        logDir: scenarioLogs,
        browser,
        baseUrl: preview.url,
      });

      process.stdout.write(`- ${scenario.name}\n`);
      const began = Date.now();
      try {
        await withDeadline(scenario.run(context), budget.scenarioMs, scenario.name, () =>
          started.abandon()
        );
        process.stdout.write(`  passed in ${Date.now() - began}ms\n`);
      } catch (error) {
        failures.push({ name: scenario.name, error });
        process.stdout.write(`  FAILED after ${Date.now() - began}ms\n`);
        process.stdout.write(`  ${describe(error)}\n`);
        process.stdout.write(`  the host logs are under ${scenarioLogs}\n`);
      } finally {
        for (const tail of await started.release()) process.stdout.write(`  ${tail}\n`);
        // A scenario may leave the API down. Restore it for the next one.
        await stack.startApi();
      }
    }
  } finally {
    await browser?.close();
    await preview?.stop();
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

interface ContextOptions {
  scenario: Scenario;
  budget: Deadlines;
  stack: Stack;
  started: Started;
  binary: string;
  home: string;
  logDir: string;
  browser: Browser;
  baseUrl: string;
}

function scenarioContext(options: ContextOptions): ScenarioContext {
  const { scenario, budget, stack, started, binary, home, logDir, browser, baseUrl } = options;
  const hold = <T extends Instance | WebHost>(value: T): T => {
    started.hold(value);
    return value;
  };
  const secret = () => {
    const hex = randomBytes(32).toString('hex');
    // The desktop entry and the web tap take the same shape, and a mismatch
    // would surface as a login refusal rather than as the defect it is.
    if (!isLoginSecret(hex)) throw new Error('the minted login secret is not 64 hex characters');
    return hex;
  };

  return {
    deadlines: budget,
    stack,
    secret,
    desktop: async (name, secretHex) =>
      hold(
        await startInstance({
          name: `${scenario.name}-${name}`,
          home: join(home, name),
          devKey: secretHex,
          binary,
          logDir,
          deadlines: budget,
        })
      ),
    web: async (name, secretHex) =>
      hold(
        await WebHost.open({
          browser,
          baseUrl,
          name: `${scenario.name}-${name}`,
          secretHex,
          accountId: crypto.randomUUID(),
          deadlines: budget,
        })
      ),
    claimant: async (name, secretHex, link) =>
      hold(
        await WebHost.claim({
          browser,
          baseUrl,
          name: `${scenario.name}-${name}`,
          secretHex,
          accountId: crypto.randomUUID(),
          deadlines: budget,
          link,
        })
      ),
    log: (message) => process.stdout.write(`  ${scenario.name}: ${message}\n`),
  };
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
