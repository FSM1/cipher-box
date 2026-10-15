/**
 * The mount-cadence probe: one account mounts, quits, and mounts again every
 * few seconds across the span after its first mount, on one machine. It fails
 * on any mount that does not go live. Dispatch only (blueprint/testing.md).
 *
 * `CIPHERBOX_E2E_SHARED_MOUNT_NAME=1` mounts under FUSE-T's shared default
 * name, the comparison leg.
 */

import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe } from '../cli';
import { startInstance } from '../instance';
import { deadlines } from '../profile';
import { Stack, requireFile } from '../stack';
import { cadenceOf, line, nextStart, verdict, type MountResult } from './plan';

const run = promisify(execFile);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

/** The mount table's line for `mountRoot`, which names the server it resolved. */
async function listing(mountRoot: string): Promise<string> {
  const { stdout } = await run('mount', [], { timeout: 10_000 });
  return stdout.split('\n').find((entry) => entry.includes(` on ${mountRoot} (`)) ?? 'not listed';
}

function wait(ms: number): Promise<void> {
  return new Promise((done) => setTimeout(done, ms));
}

async function main(): Promise<number> {
  const named = process.env.CIPHERBOX_DESKTOP_BINARY;
  if (!named) throw new Error('CIPHERBOX_DESKTOP_BINARY is unset. Point it at an e2e-hook build.');
  const binary = resolve(REPO_ROOT, named);
  await requireFile(binary, `CIPHERBOX_DESKTOP_BINARY names ${binary}, and no file is there.`);

  const cadence = cadenceOf(process.env);
  const workdir =
    process.env.CIPHERBOX_E2E_WORKDIR ?? (await mkdtemp(join(tmpdir(), 'cipherbox-cadence-')));
  const home = join(workdir, 'cadence');
  const logDir = join(home, 'logs');
  await mkdir(logDir, { recursive: true });

  const budget = deadlines();
  const stack = await Stack.start({
    apiEntry: process.env.CIPHERBOX_API_ENTRY ?? join(REPO_ROOT, 'apps/api/dist/main.js'),
    apiUrl: process.env.CIPHERBOX_API_URL ?? 'http://localhost:3000',
    logDir: join(workdir, 'logs'),
    deadlines: budget,
  });

  const shared = process.env.CIPHERBOX_E2E_SHARED_MOUNT_NAME === '1';
  process.stdout.write(
    `mounting every ${cadence.everyMs}ms for ${cadence.spanMs}ms under ` +
      `${shared ? "FUSE-T's shared name" : 'a name per mount'}\n`
  );

  const devKey = randomBytes(32).toString('hex');
  const results: MountResult[] = [];
  let first: number | null = null;
  try {
    for (let index = 0; ; index += 1) {
      const elapsed = first === null ? 0 : Date.now() - first;
      const offset = nextStart(cadence, elapsed);
      if (offset === null) break;
      await wait(offset - elapsed);
      const started = Date.now();
      first ??= started;
      let result: MountResult;
      try {
        const instance = await startInstance({
          name: `cadence-${index}`,
          home,
          devKey,
          binary,
          logDir,
          deadlines: budget,
        });
        const tookMs = Date.now() - started;
        const detail = await listing(instance.mountRoot);
        await instance.stop();
        result = { offsetMs: started - first, outcome: 'live', tookMs, detail };
      } catch (error) {
        const tookMs = Date.now() - started;
        result = { offsetMs: started - first, outcome: 'failed', tookMs, detail: describe(error) };
      }
      results.push(result);
      process.stdout.write(`${line(result)}\n`);
    }
  } finally {
    await stack.stopApi();
  }

  const failed = verdict(cadence, results);
  process.stdout.write(
    `\n${results.length} mounts, ${failed.length} failed` +
      `${failed.length > 0 ? `: ${failed.map(line).join('; ')}` : ''}\n` +
      `the instance logs are under ${logDir}\n`
  );
  return failed.length > 0 ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
);
