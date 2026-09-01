import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { poll } from './poll';
import type { Deadlines } from './profile';
import { Stack } from './stack';

/** Small budgets: these tests prove the refusal path, not a real API start. */
const BUDGET: Deadlines = {
  intervalMs: 25,
  apiReadyMs: 1_500,
  controlFileMs: 1_500,
  mountMs: 1_500,
  refreshMs: 1_500,
  readIntervalMs: 100,
  readMs: 1_500,
  convergeMs: 3_000,
  shutdownMs: 5_000,
  scenarioMs: 10_000,
};

/** The discard port. Nothing listens there, so the health probe never answers. */
const SILENT_URL = 'http://127.0.0.1:9';

const LOG_DIR = join(tmpdir(), 'cipherbox-stack-logs');

let leftover: number | null = null;

afterEach(() => {
  if (leftover === null) return;
  try {
    process.kill(leftover, 'SIGKILL');
  } catch {
    // Already gone.
  }
  leftover = null;
});

/** An API stand-in that starts, records its process id, and never answers. */
async function silentApi(): Promise<{ entry: string; pidFile: string }> {
  const root = await mkdtemp(join(tmpdir(), 'cipherbox-stack-'));
  const dist = join(root, 'dist');
  await mkdir(dist, { recursive: true });
  const pidFile = join(root, 'pid');
  const entry = join(dist, 'main.js');
  await writeFile(
    entry,
    `require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));\n` +
      'setInterval(() => {}, 1000);\n'
  );
  return { entry, pidFile };
}

function startSilent(entry: string): Promise<unknown> {
  return Stack.start({
    apiEntry: entry,
    apiUrl: SILENT_URL,
    logDir: LOG_DIR,
    deadlines: BUDGET,
  }).catch((error: unknown) => error);
}

describe('Stack.start', () => {
  it('names the build a caller must make before it starts anything', async () => {
    const refusal = await Stack.start({
      apiEntry: join(tmpdir(), 'cipherbox-stack-absent', 'dist', 'main.js'),
      apiUrl: SILENT_URL,
      logDir: LOG_DIR,
      deadlines: BUDGET,
    }).catch((error: unknown) => error);

    expect((refusal as Error).message).toContain('the built API is absent');
  });

  it('refuses a start whose API never answers its health probe', async () => {
    const { entry } = await silentApi();

    const refusal = await startSilent(entry);

    expect(refusal).toBeInstanceOf(Error);
    expect((refusal as Error).message).toContain('the API to answer');
  });

  it('leaves no API process behind when that start is refused', async () => {
    const { entry, pidFile } = await silentApi();

    await startSilent(entry);

    const pid = Number(await readFile(pidFile, 'utf8'));
    leftover = pid;
    expect(Number.isInteger(pid)).toBe(true);
    await poll(
      () => {
        try {
          process.kill(pid, 0);
          return true;
        } catch {
          return false;
        }
      },
      (alive) => !alive,
      { what: 'the refused API process to be gone', timeoutMs: 2_000, intervalMs: 25 }
    );
    leftover = null;
  });
});
