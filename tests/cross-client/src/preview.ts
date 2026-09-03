/**
 * The built web bundle, served the way the web suite serves it.
 *
 * The artifact that ships is the artifact tested (blueprint/testing.md "E2E"),
 * so this serves a built directory. `vite preview` rather than a static server
 * of this suite's own: the bundle needs the SPA fallback its routes take and
 * the security headers `apps/web/vite.config.ts` sets on the preview server,
 * and the Service Worker the engine streams through refuses to install without
 * them.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { poll } from '../../desktop-e2e/src/poll';
import type { Deadlines } from '../../desktop-e2e/src/profile';

export interface PreviewOptions {
  /** The repository root, so the child runs where the workspace filter works. */
  repoRoot: string;
  /** The built directory, relative to `apps/web`. */
  outDir: string;
  port: number;
  logDir: string;
  deadlines: Deadlines;
}

/** The package manager binary, which carries an extension on Windows. */
export function packageManager(platform: string): string {
  return platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
}

/** The argv that serves one built directory on one port. */
export function previewArguments(outDir: string, port: number): string[] {
  return [
    '--filter',
    '@cipherbox/web',
    'exec',
    'vite',
    'preview',
    '--outDir',
    outDir,
    '--port',
    String(port),
    '--strictPort',
  ];
}

/** One `vite preview` child, owned by the orchestrator. */
export class Preview {
  private constructor(
    readonly url: string,
    private readonly child: ChildProcess,
    private readonly budget: Deadlines
  ) {}

  /**
   * Checks the port, then starts the server and returns once it answers.
   *
   * A port that already answers is a refusal, not something to serve beside:
   * `--strictPort` would take this run's `vite` down and leave the poll below
   * satisfied by the stranger, so every scenario would run against a bundle
   * that is not the one under test.
   */
  static async start(options: PreviewOptions): Promise<Preview> {
    const url = `http://localhost:${options.port}`;
    if (await answers(url)) {
      throw new Error(
        `another process already answers ${url}. This suite serves the bundle under ` +
          'test there. Stop that process and run again.'
      );
    }
    await mkdir(options.logDir, { recursive: true });
    const logPath = join(options.logDir, `preview-${options.port}.log`);
    const log = createWriteStream(logPath);
    // Its own process group, and a shell on Windows, where `pnpm` is a `.cmd`:
    // the package manager runs `vite` as a child rather than becoming it, and
    // a signal to the wrapper alone would leave the server holding the port.
    const child = spawn(
      packageManager(process.platform),
      previewArguments(options.outDir, options.port),
      {
        cwd: options.repoRoot,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
        shell: process.platform === 'win32',
      }
    );
    // Both pipes keep the log open: the first stream to end would otherwise
    // close it under the other, and the diagnostics that matter are the last.
    child.stdout?.pipe(log, { end: false });
    child.stderr?.pipe(log, { end: false });
    child.once('close', () => log.end());

    // The port check above narrows the window; only the child answers whether
    // this run's `vite` still holds the port. Without it a stranger that took
    // the port could satisfy the poll and serve a bundle nobody built here.
    let died: Error | undefined;
    child.once('error', (error) => {
      died ??= new Error(`the preview server could not start: ${error.message}`);
    });
    child.once('exit', (code, signal) => {
      died ??= new Error(
        `the preview server exited with ${signal ?? code} before it served ${url}`
      );
    });

    const preview = new Preview(url, child, options.deadlines);
    try {
      await poll(
        async () => {
          const up = await answers(url);
          if (died) throw died;
          return up;
        },
        (up) => up,
        {
          what: `the web bundle to be served at ${url}; its log is ${logPath}`,
          timeoutMs: options.deadlines.apiReadyMs,
          intervalMs: options.deadlines.intervalMs,
        }
      );
    } catch (error) {
      await preview.stop();
      throw error;
    }
    return preview;
  }

  /** Ends the server and returns once the port goes silent. */
  async stop(): Promise<void> {
    const { pid } = this.child;
    if (pid !== undefined && this.child.exitCode === null && this.child.signalCode === null) {
      try {
        if (process.platform === 'win32') this.child.kill('SIGKILL');
        else process.kill(-pid, 'SIGKILL');
      } catch {
        // The group was already gone, which is the state this wanted.
      }
    }
    await poll(
      () => answers(this.url),
      (up) => !up,
      {
        what: `the web bundle to stop answering ${this.url}`,
        timeoutMs: this.budget.shutdownMs,
        intervalMs: this.budget.intervalMs,
      }
    );
  }
}

async function answers(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
    return response.ok;
  } catch {
    return false;
  }
}
