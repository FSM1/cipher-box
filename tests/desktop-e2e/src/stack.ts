/**
 * The API process, owned by the orchestrator.
 *
 * The offline scenario needs a real outage rather than a mocked one, and only
 * the process owner can take the API down and bring it back.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { access, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { poll } from './poll';
import type { Deadlines } from './profile';

export interface StackOptions {
  /** The built API entry point, for example `apps/api/dist/main.js`. */
  apiEntry: string;
  /** Where the API answers, for example `http://localhost:3000`. */
  apiUrl: string;
  logDir: string;
  deadlines: Deadlines;
}

export class Stack {
  private child: ChildProcess | null = null;
  private generation = 0;

  private constructor(private readonly options: StackOptions) {}

  /**
   * Checks the API build and the port, then starts the API.
   *
   * A port that already answers is a refusal: an API this orchestrator does not
   * own cannot go offline on command.
   */
  static async start(options: StackOptions): Promise<Stack> {
    await requireFile(
      options.apiEntry,
      `the built API is absent at ${options.apiEntry}. Run "pnpm --filter @cipherbox/api build" first.`
    );
    if (await answers(options.apiUrl)) {
      throw new Error(
        `another process already answers ${options.apiUrl}. This suite owns the API, because ` +
          `the offline scenario stops it. Stop that process and run again.`
      );
    }
    const stack = new Stack(options);
    await stack.startApi();
    return stack;
  }

  /** Starts the API and returns once it serves a login, which every host needs. */
  async startApi(): Promise<void> {
    if (this.child) return;
    this.generation += 1;
    await mkdir(this.options.logDir, { recursive: true });
    const logPath = join(this.options.logDir, `api-${this.generation}.log`);
    const log = createWriteStream(logPath);
    const child = spawn(process.execPath, [this.options.apiEntry], {
      cwd: dirname(dirname(this.options.apiEntry)),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout?.pipe(log);
    child.stderr?.pipe(log);
    child.on('exit', () => {
      if (this.child === child) this.child = null;
    });
    this.child = child;

    try {
      await poll(
        () => serves(this.options.apiUrl),
        (up) => up,
        {
          what: `the API to serve a login at ${this.options.apiUrl}; its log is ${logPath}`,
          timeoutMs: this.options.deadlines.apiReadyMs,
          intervalMs: this.options.deadlines.intervalMs,
        }
      );
    } catch (error) {
      // A start that never answers still owns a live process. It holds the
      // port, so the next run of this suite would refuse to start at all.
      await this.stopApi();
      throw error;
    }
  }

  /** Stops the API and returns once the port goes silent. */
  async stopApi(): Promise<void> {
    const child = this.child;
    if (!child) return;
    this.child = null;
    child.kill('SIGKILL');
    await poll(
      () => child.exitCode !== null || child.signalCode !== null,
      (gone) => gone,
      {
        what: 'the API process to exit',
        timeoutMs: this.options.deadlines.shutdownMs,
        intervalMs: this.options.deadlines.intervalMs,
      }
    );
    await poll(
      () => answers(this.options.apiUrl),
      (up) => !up,
      {
        what: `the API to go silent at ${this.options.apiUrl}`,
        timeoutMs: this.options.deadlines.apiReadyMs,
        intervalMs: this.options.deadlines.intervalMs,
      }
    );
  }
}

const PROBE_TIMEOUT_MS = 2_000;

/** Liveness: a process holds the port. `/health` is static and answers nothing else. */
async function answers(apiUrl: string): Promise<boolean> {
  try {
    const response = await fetch(new URL('/health', apiUrl), {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Readiness: the login surface is mapped.
 *
 * A host logs in as its first act, and `/health` carries no route of the auth
 * controller, so a scenario that starts on liveness alone can meet a 404 on the
 * route it needs. The empty body draws a validation refusal, which leaves no
 * state behind.
 */
export async function serves(apiUrl: string): Promise<boolean> {
  if (!(await answers(apiUrl))) return false;
  try {
    const response = await fetch(new URL('/auth/challenge', apiUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    return response.status !== 404 && response.status < 500;
  } catch {
    return false;
  }
}

export async function requireFile(path: string, complaint: string): Promise<void> {
  try {
    await access(path);
  } catch {
    throw new Error(complaint);
  }
}
