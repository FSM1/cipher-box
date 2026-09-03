import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { poll } from './poll';
import type { Deadlines } from './profile';
import { Stack, serves } from './stack';

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

  it('refuses a start whose API never serves', async () => {
    const { entry } = await silentApi();

    const refusal = await startSilent(entry);

    expect(refusal).toBeInstanceOf(Error);
    expect((refusal as Error).message).toContain('the API to serve a login');
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

describe('the readiness gate', () => {
  let running: Server | null = null;

  afterEach(async () => {
    const server = running;
    running = null;
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  // Per path, because the gate reads `/health` and the login route separately.
  async function serving(routes: Record<string, number>): Promise<string> {
    const server = createServer((request, response) => {
      const path = (request.url ?? '/').split('?')[0];
      response.writeHead(routes[path] ?? 404).end();
    });
    running = server;
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it('refuses a port nothing holds', async () => {
    expect(await serves(SILENT_URL)).toBe(false);
  });

  it('refuses an API that answers its health probe and maps no login route', async () => {
    const url = await serving({ '/health': 200 });

    expect(await serves(url)).toBe(false);
  });

  it('accepts an API whose login route refuses the probe body', async () => {
    const url = await serving({ '/health': 200, '/auth/challenge': 400 });

    expect(await serves(url)).toBe(true);
  });

  it('refuses an API whose login route is mapped and still failing', async () => {
    const url = await serving({ '/health': 200, '/auth/challenge': 503 });

    expect(await serves(url)).toBe(false);
  });

  it('refuses an API whose health probe fails, however it maps the login route', async () => {
    const url = await serving({ '/health': 503, '/auth/challenge': 400 });

    expect(await serves(url)).toBe(false);
  });
});
